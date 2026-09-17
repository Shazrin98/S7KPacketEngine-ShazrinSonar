using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using ShazrinSonar.Config;
using ShazrinSonar.Processing;

namespace ShazrinSonar.Networking
{
    public class NorbitIngestor
    {
        private readonly AppSettings _config;
        private readonly Channel<byte[]> _frameQueue;
        private readonly S7KStreamAccumulator _accumulator = new S7KStreamAccumulator();
        private readonly Action<string> _logger;
        private readonly Action<int, ushort, byte[]> _telemetryCallback;
        private static readonly object _fileLock = new object();

        public NorbitIngestor(
            AppSettings config,
            Channel<byte[]> frameQueue,
            Action<string> logger,
            Action<int, ushort, byte[]> telemetryCallback)
        {
            _config = config;
            _frameQueue = frameQueue;
            _logger = logger;
            _telemetryCallback = telemetryCallback;
        }

        private static void ConfigureKeepAlive(Socket socket)
        {
            try
            {
                // Standard cross-platform socket configuration
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                socket.NoDelay = true; // Disable Nagle's algorithm for low-latency streaming
            }
            catch (Exception ex)
            {
                // Prevent socket option driver failures from aborting connection
                SafeLog("pipeline_debug.log", $"[WARN] Socket option warning: {ex.Message}");
            }
        }

        public async Task StartAsync(CancellationToken ct)
        {
            int reconnectDelayMs = 1000;
            const int maxReconnectDelayMs = 10000;
            string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pipeline_debug.log");
            int bytesRead = 0;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var client = new TcpClient();
                    _logger($"Connecting to {_config.SourceIp}:{_config.SourcePort}...");
                    await client.ConnectAsync(_config.SourceIp, _config.SourcePort, ct);

                    ConfigureKeepAlive(client.Client);
                    _logger("Connected to Norbit stream source.");

                    reconnectDelayMs = 1000;
                    _accumulator.Clear();

                    using NetworkStream stream = client.GetStream();
                    byte[] readBuffer = new byte[32768];

                    while (!ct.IsCancellationRequested && client.Connected)
                    {
                        try
                        {
                            bytesRead = await stream.ReadAsync(readBuffer.AsMemory(), ct);
                            SafeLog(logPath, $"[INGESTOR] Read {bytesRead} raw bytes from port {_config.SourcePort}.");
                        }
                        catch (Exception ex)
                        {
                            SafeLog(logPath, $"[INGESTOR ERROR] ReadAsync failed: {ex.Message}");
                            throw;
                        }

                        if (bytesRead == 0) break;

                        // --- DIRECT RAW PIPING TEST (Bypassing Accumulator) ---
                        // byte[] rawChunk = new byte[bytesRead];
                        // Array.Copy(readBuffer, 0, rawChunk, 0, bytesRead);
                        // _frameQueue.Writer.TryWrite(rawChunk);

                        foreach (var (rawFrame, recType) in _accumulator.PushBytesAndExtractFrames(readBuffer, bytesRead).Frames)
                        {
                            // SafeLog(logPath, $"[ROUTER] Processing Frame Type: {recType}, Length: {rawFrame.Length}");

                            if (recType == 7027)
                            {
                                // SafeLog(logPath, "[ROUTER] Record 7027 matched! Handing off to modifier...");
                            }

                            // Transform TWTT & hydrographic depth in-place (Passthrough for non-7027 records)
                            byte[] modifiedFrame = S7KFrameProcessor.ProcessAndModifyS7KRecord(rawFrame);

                            // Expected code: To forward modified data
                            // _telemetryCallback(modifiedFrame.Length, recType, modifiedFrame);
                            // _frameQueue.Writer.TryWrite(modifiedFrame);

                            // Temporary test: Forward unmodified rawFrame directly to see if process is smooth to Qinsy
                            _telemetryCallback(rawFrame.Length, recType, rawFrame);
                            _frameQueue.Writer.TryWrite(rawFrame);
                        }
                         // //////////////////////////////////////////////////////
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeLog(logPath, $"[FATAL INGEST ERROR] {ex.Message}\n{ex.StackTrace}");

                    _accumulator.Clear();
                    _logger($"Ingest Error: {ex.Message}. Retrying in {reconnectDelayMs / 1000}s...");

                    try
                    {
                        await Task.Delay(reconnectDelayMs, ct);
                        reconnectDelayMs = Math.Min(reconnectDelayMs * 2, maxReconnectDelayMs);
                    }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        /// <summary>
        /// Thread-safe file logger to prevent file-locking exceptions during high-frequency I/O.
        /// </summary>
        private static void SafeLog(string path, string message)
        {
            try
            {
                lock (_fileLock)
                {
                    using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(stream);
                    writer.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
                }
            }
            catch
            {
                // Non-blocking catch to ensure logging never interrupts telemetry ingestion
            }
        }
    }
}