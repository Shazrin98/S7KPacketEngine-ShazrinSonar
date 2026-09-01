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
        // Network Settings
        public string SourceIp { get; set; } = "127.0.0.1";
        public int SourcePort { get; set; } = 7000;
        public string TargetProtocol { get; set; } = "TCP";
        public int TargetPort { get; set; } = 7001;

        // Hydrographic Offsets & Filtering
        public double SoundVelocity { get; set; } = 1500.0;
        public double TransducerDraft { get; set; } = 0.85;
        public double WaterLevelOffset { get; set; } = -0.15;
        public bool FilterLowQualityBeams { get; set; } = true;
        public ushort MinQualityFlag { get; set; } = 0x01;

        // Security Settings
        public string AuthorizedLicenseKey { get; set; } = "SHAZRIN-HWID-DEMO-KEY";
    }

    public class HydrographicConfig
    {
        public double SoundVelocity { get; set; } = 1500.0;    // m/s
        public double TransducerDraft { get; set; } = 0.85;     // Meters below surface
        public double WaterLevelOffset { get; set; } = -0.15;   // Tide / Datum correction (m)
        public double GpsOffsetX { get; set; } = 0.20;         // GPS to Transducer Starboard/Port offset (m)
        public double GpsOffsetY { get; set; } = 1.50;         // GPS to Transducer Bow/Stern offset (m)
        public bool FilterLowQualityBeams { get; set; } = true;
        public ushort MinQualityFlag { get; set; } = 0x01;     // Bit 0 = Valid Detection
    }

    public struct ExtractedBeamPoint
    {
        public ushort BeamIndex;
        public float Twtt;
        public float BeamAngleRad;
        public uint Quality;
        public double SlantRange;
        public double CorrectedDepthZ;
        public double AcrossTrackY;
        public double AlongTrackX;
        public double RelativeEasting;
        public double RelativeNorthing;
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

        // Active Record 7027 Telemetry
        private static uint _lastPingNumber = 0;
        private static uint _lastBeamCount = 0;
        private static ushort _lastSonarSerialNumber = 0;

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

            // Debugging data received in a file
            // try { File.WriteAllText(DebugLogPath, $"--- ShazrinSonar Debug Session Started {DateTime.Now} ---\n"); } catch { }

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

                // Sync loaded settings to processor engine
                S7KRecord7027Processor.Settings = new HydrographicConfig
                {
                    SoundVelocity = Config.SoundVelocity,
                    TransducerDraft = Config.TransducerDraft,
                    WaterLevelOffset = Config.WaterLevelOffset,
                    FilterLowQualityBeams = Config.FilterLowQualityBeams,
                    MinQualityFlag = Config.MinQualityFlag
                };
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

                ushort syncVerLE = BinaryPrimitives.ReadUInt16LittleEndian(headerBuffer.Slice(0, 2));
                ushort syncVerBE = BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.Slice(0, 2));

                if (syncVerLE != 1 && syncVerBE != 1)
                {
                    stream.Position = frameStartPos + 1;
                    continue;
                }

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

                if (foundRecType == 7027 || foundRecType == 7006 || foundRecType == 7004 || frameSize == 13515)
                {
                    Interlocked.Increment(ref _bathymetryFrames);
                    foundRecType = (foundRecType == 0) ? (ushort)7027 : foundRecType;
                    UnpackRecord7027Data(completeFrame);
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
                // To show in terminal the Diagnostic Logs
                // LogDiagnostic($"Synced Frame #{count}: Identified RecID={foundRecType} | Size={frameSize}B");

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

        private static void UnpackRecord7027Data(byte[] frame)
        {
            if (frame.Length < 96) return;

            try
            {
                // Unpack Record 7027 Payload (Header starts at byte offset 64)
                uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(64, 4));
                uint beamCount = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(72, 4));

                // Fallback byte check if beam count yields unexpected scale
                if (beamCount == 0 || beamCount > 2048)
                {
                    beamCount = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(72, 2));
                }

                if (pingNumber > 0) _lastPingNumber = pingNumber;
                if (beamCount > 0 && beamCount <= 2048) _lastBeamCount = beamCount;
            }
            catch { }
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

        ///Process to adjust data from S7K Records
        private static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame.Length >= 96)
            {
                // Read Frame Type at offset 32 / 64
                ushort recType = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(32, 2));

                if (recType == 7027 || frame.Length == 13515)
                {
                    // Apply depth offsets, quality filtering, and coordinate transformations
                    // Pass live vessel attitude (Roll, Pitch, Heading) if available from Record 1012/1016
                    S7KRecord7027Processor.ProcessRecord7027(
                        frame,
                        vesselRollRad: 0.0,
                        vesselPitchRad: 0.0,
                        vesselHeadingRad: 0.0
                    );
                }
            }

            return frame; // Return frame with modified byte payload
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
                    sb.AppendLine($"[+] SONAR LIVE TELEMETRY (Record 7027)");
                    sb.AppendLine($"    ├── Active Ping #     : {_lastPingNumber:N0}");
                    sb.AppendLine($"    └── Beams Per Ping    : {(_lastBeamCount > 0 ? _lastBeamCount.ToString() : "256 (Default)")}");
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
                    // sb.AppendLine($"[Log File] Output saved to: s7k_debug.log");
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
        ///////////////////////////////////////
        public static class S7KRecord7027Processor
        {
            public static HydrographicConfig Settings { get; set; } = new HydrographicConfig();

            /// <summary>
            /// Parses, filters, and transforms a 7027 frame buffer in-place or returns calculated points.
            /// </summary>
            public static ExtractedBeamPoint[] ProcessRecord7027(
                byte[] frame,
                double vesselRollRad = 0.0,
                double vesselPitchRad = 0.0,
                double vesselHeadingRad = 0.0)
            {
                if (frame.Length < 96) return Array.Empty<ExtractedBeamPoint>();

                // Frame Header: Byte 64 is the start of Record 7027 Data Header
                Span<byte> recordData = frame.AsSpan(64);

                uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(0, 4));
                uint beamCount = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(8, 4));

                if (beamCount == 0 || beamCount > 2048)
                {
                    beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(8, 2));
                }

                if (beamCount == 0 || beamCount > 2048) return Array.Empty<ExtractedBeamPoint>();

                // Payload Byte Offsets relative to Record 7027 Data Header (Byte 64)
                int twttArrayOffset = 32;
                int qualityArrayOffset = twttArrayOffset + (int)(beamCount * 4); // 4 bytes per float TWTT
                int angleArrayOffset = qualityArrayOffset + (int)(beamCount * 4); // 4 bytes per uint Quality

                if (recordData.Length < angleArrayOffset + (beamCount * 4))
                {
                    return Array.Empty<ExtractedBeamPoint>();
                }

                var validPoints = new ExtractedBeamPoint[beamCount];
                int validBeamCount = 0;

                for (ushort i = 0; i < beamCount; i++)
                {
                    // Unpack TWTT (Float32, seconds)
                    float twtt = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(twttArrayOffset + (i * 4), 4));

                    // Unpack Quality Flag (UInt32 bitmask)
                    uint quality = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(qualityArrayOffset + (i * 4), 4));

                    // Unpack Beam Angle (Float32, radians relative to array nadir)
                    float beamAngle = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(angleArrayOffset + (i * 4), 4));

                    // Quality Filtering: Discard zero TWTT or invalid phase/amplitude flags
                    if (twtt <= 0.0001f) continue;
                    if (Settings.FilterLowQualityBeams && (quality & Settings.MinQualityFlag) == 0) continue;

                    // 1. Slant Range Calculation
                    double slantRange = (Settings.SoundVelocity * twtt) / 2.0;

                    // 2. Roll & Pitch Compensation
                    double totalAngleRad = beamAngle + vesselRollRad;
                    double depthZRaw = slantRange * Math.Cos(totalAngleRad) * Math.Cos(vesselPitchRad);
                    double acrossTrackY = slantRange * Math.Sin(totalAngleRad);
                    double alongTrackX = slantRange * Math.Sin(vesselPitchRad);

                    // 3. Depth Offsets (Transducer Draft + Tidal/Datum adjustment)
                    double correctedDepthZ = depthZRaw + Settings.TransducerDraft + Settings.WaterLevelOffset;

                    // 4. GPS & Vessel Heading Projection
                    double sinHeading = Math.Sin(vesselHeadingRad);
                    double cosHeading = Math.Cos(vesselHeadingRad);

                    double relEasting = (alongTrackX * sinHeading) + (acrossTrackY * cosHeading) + Settings.GpsOffsetX;
                    double relNorthing = (alongTrackX * cosHeading) - (acrossTrackY * sinHeading) + Settings.GpsOffsetY;

                    // 5. In-Place Binary Repacking: Write corrected TWTT back to stream buffer
                    // Re-calculate modified TWTT corresponding to adjusted depth if required by Qinsy
                    float depthTwttModified = (float)((correctedDepthZ * 2.0) / Settings.SoundVelocity);
                    BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(twttArrayOffset + (i * 4), 4), depthTwttModified);

                    validPoints[validBeamCount++] = new ExtractedBeamPoint
                    {
                        BeamIndex = i,
                        Twtt = twtt,
                        BeamAngleRad = beamAngle,
                        Quality = quality,
                        SlantRange = slantRange,
                        CorrectedDepthZ = correctedDepthZ,
                        AcrossTrackY = acrossTrackY,
                        AlongTrackX = alongTrackX,
                        RelativeEasting = relEasting,
                        RelativeNorthing = relNorthing
                    };
                }

                Array.Resize(ref validPoints, validBeamCount);
                return validPoints;
            }
        }
        /////////////////////////////////////////////////
    }
}