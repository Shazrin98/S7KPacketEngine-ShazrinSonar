using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using ShazrinSonar.Config;
using ShazrinSonar.Networking;
using ShazrinSonar.Processing;

namespace ShazrinSonar
{
    internal class Program
    {
        private static readonly string ConfigPath = "ShazrinSonar_Config.json";
        private static readonly string DebugLogPath = "s7k_debug.log";

        // HIGH PRIORITY FIX: Use ConfigManager for thread-safe config access and live reloads
        private static readonly ConfigManager _configManager = new ConfigManager(ConfigPath);
        private static AppSettings Config => _configManager.Current;

        private static readonly object ConsoleLock = new object();
        private static readonly object FileLock = new object();

        private static readonly Channel<byte[]> FrameQueue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(500)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.DropOldest
        });

        private static readonly ConcurrentQueue<string> DiagnosticLogs = new ConcurrentQueue<string>();

        // Telemetry Counters
        private static long _totalBytesRead = 0;
        private static long _s7kFramesExtracted = 0;
        private static long _bathymetryFrames = 0;
        private static long _positionFrames = 0;
        private static long _otherRecordFrames = 0;

        // Active Record 7027 Telemetry
        private static uint _lastPingNumber = 0;
        private static uint _lastBeamCount = 0;

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

            if (!SecurityManager.ValidateAuthorization(Config.AuthorizedLicenseKey))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] ACCESS DENIED: Unauthorized hardware device or missing ShazrinSonar.lic key.");
                Console.WriteLine($"[!] Hardware Fingerprint: {SecurityManager.GenerateHardwareId()}");
                Console.ResetColor();
                return;
            }

            Console.Clear();
            Console.CursorVisible = false;
            Console.Title = "ShazrinSonar Engine - Reson S7K Stream Parser";

            using var cts = new CancellationTokenSource();

            var ingestor = new NorbitIngestor(Config, FrameQueue, LogDiagnostic, HandleFrameTelemetry);
            var forwarder = new QinsyForwarder(Config, FrameQueue, LogDiagnostic);

            Task ingestTask = Task.Run(() => ingestor.StartAsync(cts.Token));
            Task forwardTask = Task.Run(() => forwarder.StartAsync(cts.Token));
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
            var cfg = Config;

            S7KFrameProcessor.Settings = new HydrographicConfig
            {
                SoundVelocity = cfg.SoundVelocity,
                TransducerDraft = cfg.TransducerDraft,
                WaterLevelOffset = cfg.WaterLevelOffset,
                FilterLowQualityBeams = cfg.FilterLowQualityBeams,
                MinQualityFlag = cfg.MinQualityFlag
            };
        }

        private static void HandleFrameTelemetry(int bytesRead, ushort recType, byte[] frame)
        {
            Interlocked.Add(ref _totalBytesRead, bytesRead);
            Interlocked.Increment(ref _s7kFramesExtracted);

            if (recType == 7027 || recType == 7006 || recType == 7004 || frame.Length == 13515)
            {
                Interlocked.Increment(ref _bathymetryFrames);
                UnpackRecord7027Data(frame);
            }
            else if (recType == 1012 || recType == 1013 || recType == 1015 || recType == 1016 || frame.Length == 260)
            {
                Interlocked.Increment(ref _positionFrames);
            }
            else
            {
                Interlocked.Increment(ref _otherRecordFrames);
            }
        }

        private static void UnpackRecord7027Data(byte[] frame)
        {
            if (frame.Length < 96) return;

            try
            {
                uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(64, 4));
                uint beamCount = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(72, 4));

                if (beamCount == 0 || beamCount > 2048)
                {
                    beamCount = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(72, 2));
                }

                if (pingNumber > 0) _lastPingNumber = pingNumber;
                if (beamCount > 0 && beamCount <= 2048) _lastBeamCount = beamCount;
            }
            catch { }
        }

        private static async Task DisplayStatsAsync(CancellationToken ct)
        {
            try
            {
                string hwid = SecurityManager.GenerateHardwareId();

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
                    sb.AppendLine($"[+] License Status        : AUTHORIZED (HWID: {hwid})");
                    sb.AppendLine($"[+] Source (Norbit Client): {Config.SourceIp}:{Config.SourcePort}");
                    sb.AppendLine($"[+] Target (Qinsy Server) : Port {Config.TargetPort} ({Config.TargetProtocol})");
                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine("[+] HYDROGRAPHIC CONFIGURATION");
                    sb.AppendLine($"    ├── Sound Velocity    : {S7KFrameProcessor.Settings.SoundVelocity:F1} m/s");
                    sb.AppendLine($"    ├── Transducer Draft  : +{S7KFrameProcessor.Settings.TransducerDraft:F2} m");
                    sb.AppendLine($"    ├── Water Level/Tide  : {S7KFrameProcessor.Settings.WaterLevelOffset:+0.00;-0.00;0.00} m");
                    sb.AppendLine($"    └── Quality Filter    : {(S7KFrameProcessor.Settings.FilterLowQualityBeams ? "ENABLED" : "DISABLED")}");
                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine($"[+] STREAM METRICS");
                    sb.AppendLine($"    ├── Raw Ingested Data : {mbIngested:F2} MB");
                    sb.AppendLine($"    ├── S7K Records Total : {totalFrames:N0}");
                    sb.AppendLine($"    │   ├── Bathymetry(7027) : {bathyFrames:N0}");
                    sb.AppendLine($"    │   ├── Navigation(1012) : {navFrames:N0}");
                    sb.AppendLine($"    │   └── System / Misc    : {miscFrames:N0}");
                    sb.AppendLine($"    ├── Active Ping #     : {_lastPingNumber:N0}");
                    sb.AppendLine($"    └── Beams Per Ping    : {(_lastBeamCount > 0 ? _lastBeamCount.ToString() : "64")}");
                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine("[DIAGNOSTIC LOGS]");

                    var logs = DiagnosticLogs.ToArray();
                    if (logs.Length == 0)
                    {
                        sb.AppendLine(" > Waiting for data stream...");
                    }
                    else
                    {
                        foreach (var log in logs)
                        {
                            sb.AppendLine($" > {log}");
                        }
                    }

                    sb.AppendLine("--------------------------------------------------");
                    sb.AppendLine($"[Log File] Output saved to: {DebugLogPath}");
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