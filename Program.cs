using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
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

        #region Win32 VT100 / MINGW64 ANSI Interop
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        private const int STD_OUTPUT_HANDLE = -11;
        private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

        private static void EnableAnsiTerminal()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
                    if (GetConsoleMode(handle, out uint mode))
                    {
                        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                    }
                }
            }
            catch
            {
                // Silently fallback if PTY handle is a stream/pipe
            }
        }
        #endregion

        static async Task Main(string[] args)
        {
            LoadConfiguration();
            EnableAnsiTerminal();

            Console.Clear();
            Console.CursorVisible = false;
            Console.Title = "ShazrinSonar Engine - Reson S7K Stream Parser";

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
                Console.Write("\x1b[H\x1b[J"); // Clear screen cleanly on exit
                Console.WriteLine("[+] ShazrinSonar stopped cleanly. Have a great day!");
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
                    byte[] readBuffer = new byte[32768];

                    while (!ct.IsCancellationRequested && client.Connected)
                    {
                        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, ct);
                        if (bytesRead == 0) break;

                        Interlocked.Add(ref _totalBytesRead, bytesRead);
                        memoryBuffer.Write(readBuffer, 0, bytesRead);

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

        private static void ExtractS7KFrames(MemoryStream stream)
        {
            stream.Position = 0;

            while (stream.Length - stream.Position >= 64)
            {
                long frameStartPos = stream.Position;
                byte[] headerBuffer = new byte[64];
                stream.Read(headerBuffer, 0, 64);

                uint frameSize = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.AsSpan(8, 4));

                if (frameSize < 64 || frameSize > 2097152)
                {
                    stream.Position = frameStartPos + 1;
                    continue;
                }

                if (stream.Length - frameStartPos < frameSize)
                {
                    stream.Position = frameStartPos;
                    break;
                }

                stream.Position = frameStartPos;
                byte[] completeFrame = new byte[frameSize];
                stream.Read(completeFrame, 0, (int)frameSize);

                uint recordType = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(32, 4));

                switch (recordType)
                {
                    case 7027:
                    case 7006:
                    case 7004:
                    case 7000:
                        Interlocked.Increment(ref _bathymetryFrames);
                        break;

                    case 1012:
                    case 1013:
                    case 1015:
                    case 1016:
                        Interlocked.Increment(ref _positionFrames);
                        break;

                    default:
                        Interlocked.Increment(ref _otherRecordFrames);
                        break;
                }

                FrameQueue.Writer.TryWrite(completeFrame);
                Interlocked.Increment(ref _s7kFramesExtracted);
            }

            byte[] remainingData = stream.ToArray();
            int remainingBytes = (int)(stream.Length - stream.Position);

            stream.SetLength(0);
            if (remainingBytes > 0)
            {
                stream.Write(remainingData, remainingData.Length - remainingBytes, remainingBytes);
            }
        }

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
                    catch (Exception) { }
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

        private static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame.Length < 36) return frame;
            uint recordType = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(32, 4));

            if (recordType == 7027)
            {
                // Day 3 bathymetry record processing
            }

            return frame;
        }

        /// <summary>
        /// Fixed render loop: Uses \x1b[H\x1b[J (Home + Clear to End) and omits the trailing newline.
        /// </summary>
        private static async Task DisplayStatsAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    double mbIngested = Interlocked.Read(ref _totalBytesRead) / 1024.0 / 1024.0;
                    long totalFrames = Interlocked.Read(ref _s7kFramesExtracted);
                    long bathyFrames = Interlocked.Read(ref _bathymetryFrames);
                    long navFrames = Interlocked.Read(ref _positionFrames);
                    long miscFrames = Interlocked.Read(ref _otherRecordFrames);

                    var sb = new StringBuilder();

                    // \x1b[H = Move cursor to row 1, col 1
                    // \x1b[J = Erase from cursor to bottom of screen
                    sb.Append("\x1b[H\x1b[J");

                    sb.AppendLine("==================================================");
                    sb.AppendLine("        SHAZRIN SONAR - S7K STREAM ENGINE         ");
                    sb.AppendLine("==================================================");
                    sb.AppendLine($"[+] Source (Norbit TCP Client) : {Config.SourceIp}:{Config.SourcePort}");
                    sb.AppendLine($"[+] Target (Qinsy {Config.TargetProtocol} Server): Port {Config.TargetPort}");
                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine($"[+] Stream Status         : ACTIVE");
                    sb.AppendLine($"[+] Raw Ingested Data     : {mbIngested:F2} MB");
                    sb.AppendLine($"[+] S7K Records Extracted : {totalFrames:N0}");
                    sb.AppendLine($"    ├── Bathymetry (7027) : {bathyFrames:N0}");
                    sb.AppendLine($"    ├── Navigation (1012) : {navFrames:N0}");
                    sb.AppendLine($"    └── System / Misc     : {miscFrames:N0}");
                    sb.AppendLine("--------------------------------------------------");
                    
                    // Notice Append instead of AppendLine to prevent trailing newline scrolling
                    sb.Append("Press [ENTER] to stop ShazrinSonar gracefully...");

                    lock (ConsoleLock)
                    {
                        try { Console.SetCursorPosition(0, 0); } catch { }
                        Console.Write(sb.ToString());
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