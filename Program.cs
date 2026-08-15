using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace ShazrinSonar
{
    public class AppSettings
    {
        public string SourceIp { get; set; } = "127.0.0.1";
        public int SourcePort { get; set; } = 7000;

        public string TargetProtocol { get; set; } = "TCP"; // "TCP" or "UDP"
        public int TargetPort { get; set; } = 7001;
    }

    internal class Program
    {
        private static readonly string ConfigPath = "ShazrinSonar_Config.json";
        private static AppSettings Config = new AppSettings();
        private static readonly object ConsoleLock = new object();

        // High-performance channel passing decoupled S7K binary frames to the Qinsy outbound engine
        private static readonly Channel<byte[]> FrameQueue = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true
        });

        // Telemetry Counters
        private static long _totalBytesRead = 0;
        private static long _s7kFramesExtracted = 0;
        private static long _bathymetryFrames = 0;
        private static long _positionFrames = 0;
        private static long _otherRecordFrames = 0;

        static async Task Main(string[] args)
        {
            LoadConfiguration();

            Console.Clear();
            Console.CursorVisible = false;
            Console.Title = "ShazrinSonar Engine - Reson S7K Stream Parser";

            lock (ConsoleLock)
            {
                Console.WriteLine("==================================================");
                Console.WriteLine("        SHAZRIN SONAR - S7K STREAM ENGINE         ");
                Console.WriteLine("==================================================");
                Console.WriteLine($"[+] Source (Norbit TCP Client) : {Config.SourceIp}:{Config.SourcePort}");
                Console.WriteLine($"[+] Target (Qinsy {Config.TargetProtocol} Server): Port {Config.TargetPort}");
                Console.WriteLine("--------------------------------------------------");
                Console.WriteLine("\n\n\n\n\n\n");
                Console.WriteLine("Press [ENTER] to stop ShazrinSonar gracefully...\n");
            }

            using var cts = new CancellationTokenSource();

            // Launch Async Background Tasks
            Task ingestTask = Task.Run(() => StartNorbitTcpIngestAsync(cts.Token));
            Task forwardTask = Task.Run(() => StartQinsyForwarderAsync(cts.Token));
            Task statsTask = Task.Run(() => DisplayStatsAsync(cts.Token));

            Console.ReadLine();

            // Initiate Graceful Shutdown
            cts.Cancel();

            try
            {
                await Task.WhenAll(ingestTask, forwardTask, statsTask);
            }
            catch (Exception ex) when (ex is OperationCanceledException || ex is TaskCanceledException)
            {
                // Expected cancellation on shutdown
            }

            lock (ConsoleLock)
            {
                SafeSetCursorPosition(0, 16);
                Console.WriteLine("[+] ShazrinSonar stopped cleanly. Have a great day!          ");
                Console.CursorVisible = true;
            }
        }

        private static void LoadConfiguration()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    string json = File.ReadAllText(ConfigPath);
                    Config = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
                else
                {
                    string json = JsonSerializer.Serialize(Config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(ConfigPath, json);
                }
            }
            catch
            {
                Config = new AppSettings();
            }
        }

        /// <summary>
        /// Task 1: Connects to Norbit TCP Server and reads incoming byte stream.
        /// </summary>
        private static async Task StartNorbitTcpIngestAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(Config.SourceIp, Config.SourcePort, ct);

                    using NetworkStream stream = client.GetStream();
                    using var memoryBuffer = new MemoryStream();
                    byte[] readBuffer = new byte[32768]; // 32KB buffer

                    while (!ct.IsCancellationRequested && client.Connected)
                    {
                        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, ct);
                        if (bytesRead == 0) break; // Reconnect if server closes connection

                        Interlocked.Add(ref _totalBytesRead, bytesRead);
                        memoryBuffer.Write(readBuffer, 0, bytesRead);

                        // Decouple full S7K binary frames out of continuous TCP memory stream
                        ExtractS7KFrames(memoryBuffer);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception)
                {
                    try { await Task.Delay(2000, ct); } catch (OperationCanceledException) { break; }
                }
            }
        }

        /// <summary>
        /// Carves continuous TCP stream into individual Reson S7K records using Big-Endian frame headers
        /// and Little-Endian record IDs.
        /// </summary>
        private static void ExtractS7KFrames(MemoryStream stream)
        {
            stream.Position = 0;

            // Minimum full header requirement: 32 bytes Data Frame Header + 4 bytes Data Record Header ID
            while (stream.Length - stream.Position >= 64)
            {
                long frameStartPos = stream.Position;
                byte[] headerBuffer = new byte[64];
                stream.Read(headerBuffer, 0, 64);

                // Read Total Frame Size (Bytes 8-11, Big-Endian / Network Byte Order)
                uint frameSize = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.AsSpan(8, 4));

                // Sanity check frame size boundaries (S7K records: 64 bytes to 2MB)
                if (frameSize < 64 || frameSize > 2097152)
                {
                    // Unaligned byte stream: advance cursor by 1 byte to seek next valid header
                    stream.Position = frameStartPos + 1;
                    continue;
                }

                // Wait if the full frame record payload has not completely arrived in the buffer yet
                if (stream.Length - frameStartPos < frameSize)
                {
                    stream.Position = frameStartPos; // Rewind and await next TCP read
                    break;
                }

                // Slice the complete S7K record
                stream.Position = frameStartPos;
                byte[] completeFrame = new byte[frameSize];
                stream.Read(completeFrame, 0, (int)frameSize);

                // Read Record Type ID (Bytes 32-35) strictly in Little-Endian format
                uint recordType = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(32, 4));

                // Classify S7K Record Types
                switch (recordType)
                {
                    case 7027: // Raw Detection Data / Bathymetric Depths
                    case 7006: // Compressed Bathymetry
                    case 7004: // Beam Geometry / Bathymetry Setup
                    case 7000: // Sonar Settings
                        Interlocked.Increment(ref _bathymetryFrames);
                        break;

                    case 1012: // Roll, Pitch, Heave & Position
                    case 1013: // Position / GPS Data
                    case 1015: // Navigation / Position Record
                    case 1016: // Motion / Attitude Record
                        Interlocked.Increment(ref _positionFrames);
                        break;

                    default:
                        Interlocked.Increment(ref _otherRecordFrames);
                        break;
                }

                // Forward full frame to Qinsy dispatch queue
                FrameQueue.Writer.TryWrite(completeFrame);
                Interlocked.Increment(ref _s7kFramesExtracted);
            }

            // Compact unprocessed partial trailing bytes back to the start of the stream
            byte[] remainingData = stream.ToArray();
            int remainingBytes = (int)(stream.Length - stream.Position);

            stream.SetLength(0);
            if (remainingBytes > 0)
            {
                stream.Write(remainingData, remainingData.Length - remainingBytes, remainingBytes);
            }
        }

        /// <summary>
        /// Task 2: Forwards raw or modified S7K records to Qinsy over TCP or UDP.
        /// </summary>
        private static async Task StartQinsyForwarderAsync(CancellationToken ct)
        {
            if (Config.TargetProtocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                var listener = new TcpListener(IPAddress.Any, Config.TargetPort);
                listener.Start();

                while (!ct.IsCancellationRequested)
                {
                    try
                    {
                        using TcpClient qinsyClient = await listener.AcceptTcpClientAsync(ct);
                        using NetworkStream qinsyStream = qinsyClient.GetStream();

                        await foreach (byte[] frame in FrameQueue.Reader.ReadAllAsync(ct))
                        {
                            byte[] processedFrame = ProcessAndModifyS7KRecord(frame);
                            await qinsyStream.WriteAsync(processedFrame, 0, processedFrame.Length, ct);
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception) { /* Handle client disconnect/reconnect */ }
                }
                listener.Stop();
            }
            else
            {
                using var udpClient = new UdpClient();
                var targetEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), Config.TargetPort);

                await foreach (byte[] frame in FrameQueue.Reader.ReadAllAsync(ct))
                {
                    byte[] processedFrame = ProcessAndModifyS7KRecord(frame);
                    await udpClient.SendAsync(processedFrame, processedFrame.Length, targetEndpoint);
                }
            }
        }

        /// <summary>
        /// Day 3 Pipeline Hook: Inspects and modifies binary payload records (e.g., Record 7027 depth adjustments).
        /// </summary>
        private static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame.Length < 36) return frame;

            // Extract Record Type ID at offset 32 (Little-Endian)
            uint recordType = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(32, 4));

            if (recordType == 7027)
            {
                // Day 3 Logic: Intercept Record 7027 bathymetry detection data arrays here
            }

            return frame;
        }

        /// <summary>
        /// Safe terminal cursor positioning compatible with Windows CMD, PowerShell, and MINGW64/Git Bash.
        /// </summary>
        private static void SafeSetCursorPosition(int left, int top)
        {
            try
            {
                int maxLeft = Math.Max(0, Console.WindowWidth - 1);
                int maxTop = Math.Max(0, Console.WindowHeight - 1);

                Console.SetCursorPosition(Math.Clamp(left, 0, maxLeft), Math.Clamp(top, 0, maxTop));
            }
            catch
            {
                // Fallback for MINGW64 / Git Bash PTY environments using VT100 ANSI sequences
                Console.Write($"\x1b[{top + 1};{left + 1}H");
            }
        }

        /// <summary>
        /// Thread-safe console rendering loop.
        /// </summary>
        private static async Task DisplayStatsAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    lock (ConsoleLock)
                    {
                        SafeSetCursorPosition(0, 7);
                        Console.WriteLine($"[+] Stream Status         : ACTIVE                               ");
                        Console.WriteLine($"[+] Raw Ingested Data     : {Interlocked.Read(ref _totalBytesRead) / 1024.0 / 1024.0:F2} MB                  ");
                        Console.WriteLine($"[+] S7K Records Extracted : {Interlocked.Read(ref _s7kFramesExtracted):N0}                      ");
                        Console.WriteLine($"    ├── Bathymetry (7027) : {Interlocked.Read(ref _bathymetryFrames):N0}                      ");
                        Console.WriteLine($"    ├── Navigation (1012) : {Interlocked.Read(ref _positionFrames):N0}                      ");
                        Console.WriteLine($"    └── System / Misc     : {Interlocked.Read(ref _otherRecordFrames):N0}                      ");
                        Console.WriteLine("--------------------------------------------------");
                    }

                    await Task.Delay(250, ct);
                }
            }
            catch (OperationCanceledException)
            {
                // Graceful exit
            }
        }
    }
}