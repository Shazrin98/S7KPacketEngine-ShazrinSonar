using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
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
        public string TargetProtocol { get; set; } = "TCP";
        public int TargetPort { get; set; } = 7001;
    }

    internal class Program
    {
        private static readonly string ConfigPath = "ShazrinSonar_Config.json";
        private static readonly string DebugLogPath = "s7k_debug.log";
        private static AppSettings Config = new AppSettings();
        private static readonly object ConsoleLock = new object();
        private static readonly object FileLock = new object();

        private static readonly Channel<byte[]> FrameQueue = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true
        });

        private static readonly ConcurrentQueue<string> DiagnosticLogs = new ConcurrentQueue<string>();

        // Telemetry Counters
        private static long _totalBytesRead = 0;
        private static long _s7kFramesExtracted = 0;
        private static long _bathymetryFrames = 0;
        private static long _positionFrames = 0;
        private static long _otherRecordFrames = 0;

        #region Win32 ANSI Interop
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
            catch { }
        }
        #endregion

        static async Task Main(string[] args)
        {
            LoadConfiguration();
            EnableAnsiTerminal();

            // Clear debug log on startup
            try { File.WriteAllText(DebugLogPath, $"--- ShazrinSonar Debug Session Started {DateTime.Now} ---\n"); } catch { }

            Console.Clear();
            Console.CursorVisible = false;
            Console.Title = "ShazrinSonar Engine - Reson S7K Stream Parser";

            using var cts = new CancellationTokenSource();

            Task ingestTask = Task.Run(() => StartNorbitTcpIngestAsync(cts.Token));
            Task forwardTask = Task.Run(() => StartQinsyForwarderAsync(cts.Token));
            Task statsTask = Task.Run(() => DisplayStatsAsync(cts.Token));

            Console.ReadLine();

            cts.Cancel();
            try { await Task.WhenAll(ingestTask, forwardTask, statsTask); }
            catch (OperationCanceledException) { }

            lock (ConsoleLock)
            {
                Console.Write("\x1b[H\x1b[J");
                Console.WriteLine("[+] ShazrinSonar stopped cleanly.");
                Console.CursorVisible = true;
            }
        }

        private static void LogDiagnostic(string message)
        {
            string entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            DiagnosticLogs.Enqueue(entry);
            while (DiagnosticLogs.Count > 6)
            {
                DiagnosticLogs.TryDequeue(out _);
            }

            // Write to debug file
            Task.Run(() =>
            {
                lock (FileLock)
                {
                    try { File.AppendAllText(DebugLogPath, entry + Environment.NewLine); } catch { }
                }
            });
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
            catch { Config = new AppSettings(); }
        }

        private static async Task StartNorbitTcpIngestAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var client = new TcpClient();
                    LogDiagnostic($"Connecting to {Config.SourceIp}:{Config.SourcePort}...");
                    await client.ConnectAsync(Config.SourceIp, Config.SourcePort, ct);
                    LogDiagnostic("Connected to Norbit stream source.");

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
                catch (Exception ex)
                {
                    LogDiagnostic($"Ingest Error: {ex.Message}");
                    try { await Task.Delay(2000, ct); } catch (OperationCanceledException) { break; }
                }
            }
        }

        private static void ExtractS7KFrames(MemoryStream stream)
        {
            stream.Position = 0;
            Span<byte> headerBuffer = stackalloc byte[64];

            while (stream.Length - stream.Position >= 64)
            {
                long frameStartPos = stream.Position;
                headerBuffer.Clear();

                int bytesRead = stream.Read(headerBuffer);
                if (bytesRead < 64)
                {
                    stream.Position = frameStartPos;
                    break;
                }

                // S7K Sync Pattern Check: Byte 0-1 must be Version 1 (0x0001)
                ushort syncVerLE = BinaryPrimitives.ReadUInt16LittleEndian(headerBuffer.Slice(0, 2));
                ushort syncVerBE = BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.Slice(0, 2));

                if (syncVerLE != 1 && syncVerBE != 1)
                {
                    stream.Position = frameStartPos + 1;
                    continue;
                }

                // Read Frame Size at bytes 8-11
                uint frameSizeBE = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.Slice(8, 4));
                uint frameSizeLE = BinaryPrimitives.ReadUInt32LittleEndian(headerBuffer.Slice(8, 4));
                uint frameSize = (frameSizeBE >= 64 && frameSizeBE <= 2097152) ? frameSizeBE : frameSizeLE;

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

                // Scan frame header (bytes 32-63) AND inner record header (bytes 64-96) for explicit Record IDs
                ushort foundRecType = 0;
                int maxScan = (int)Math.Min(frameSize - 2, 96);

                for (int offset = 32; offset <= maxScan; offset += 2)
                {
                    ushort valLE = BinaryPrimitives.ReadUInt16LittleEndian(completeFrame.AsSpan(offset, 2));
                    ushort valBE = BinaryPrimitives.ReadUInt16BigEndian(completeFrame.AsSpan(offset, 2));

                    if (valLE == 7027 || valLE == 7006 || valLE == 7004 || valLE == 7000 ||
                        valLE == 1012 || valLE == 1013 || valLE == 1015 || valLE == 1016)
                    {
                        foundRecType = valLE;
                        break;
                    }
                    if (valBE == 7027 || valBE == 7006 || valBE == 7004 || valBE == 7000 ||
                        valBE == 1012 || valBE == 1013 || valBE == 1015 || valBE == 1016)
                    {
                        foundRecType = valBE;
                        break;
                    }
                }

                // Categorize by detected Record ID or by Norbit Frame-Size signature
                if (foundRecType == 7027 || foundRecType == 7006 || foundRecType == 7004 || frameSize == 13515)
                {
                    Interlocked.Increment(ref _bathymetryFrames);
                    foundRecType = (foundRecType == 0) ? (ushort)7027 : foundRecType;
                }
                else if (foundRecType == 1012 || foundRecType == 1013 || foundRecType == 1015 || foundRecType == 1016 || frameSize == 260)
                {
                    Interlocked.Increment(ref _positionFrames);
                    foundRecType = (foundRecType == 0) ? (ushort)1012 : foundRecType;
                }
                else
                {
                    Interlocked.Increment(ref _otherRecordFrames);
                    foundRecType = (foundRecType == 0) ? (ushort)7000 : foundRecType;
                }

                long count = Interlocked.Increment(ref _s7kFramesExtracted);
                LogDiagnostic($"Synced Frame #{count}: Identified RecID={foundRecType} | Size={frameSize}B");

                FrameQueue.Writer.TryWrite(completeFrame);
            }

            int remainingBytes = (int)(stream.Length - stream.Position);
            if (remainingBytes > 0)
            {
                byte[] internalBuffer = stream.GetBuffer();
                Buffer.BlockCopy(internalBuffer, (int)stream.Position, internalBuffer, 0, remainingBytes);
                stream.SetLength(remainingBytes);
                stream.Position = remainingBytes;
            }
            else
            {
                stream.SetLength(0);
                stream.Position = 0;
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
                        LogDiagnostic("Qinsy client connected.");
                        using NetworkStream qinsyStream = qinsyClient.GetStream();

                        await foreach (byte[] frame in FrameQueue.Reader.ReadAllAsync(ct))
                        {
                            byte[] processedFrame = ProcessAndModifyS7KRecord(frame);
                            await qinsyStream.WriteAsync(processedFrame, 0, processedFrame.Length, ct);
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        LogDiagnostic($"Forwarder Exception: {ex.Message}");
                    }
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
            return frame;
        }

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
                    sb.Append("\x1b[H\x1b[J");

                    sb.AppendLine("==================================================");
                    sb.AppendLine("         SHAZRIN SONAR - S7K STREAM ENGINE        ");
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
                    sb.AppendLine("[DIAGNOSTIC LOGS]");

                    var logs = DiagnosticLogs.ToArray();
                    if (logs.Length == 0)
                    {
                        sb.AppendLine(" > Waiting for frames...");
                    }
                    else
                    {
                        foreach (var log in logs)
                        {
                            sb.AppendLine($" > {log}");
                        }
                    }

                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine($"[Log File] Output saved to: s7k_debug.log");
                    sb.Append("Press [ENTER] to stop ShazrinSonar gracefully...");

                    lock (ConsoleLock)
                    {
                        Console.Write(sb.ToString());
                    }

                    await Task.Delay(250, ct);
                }
            }
            catch (OperationCanceledException) { }
        }
    }
}