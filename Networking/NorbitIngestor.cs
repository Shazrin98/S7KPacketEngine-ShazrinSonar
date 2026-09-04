using System;
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

        private static void ConfigureKeepAlive(Socket socket)
        {
            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 5);      // 5 seconds idle before probing
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 1);  // 1 second interval between probes
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3); // 3 failed probes before dropping
            }
            catch (SocketException)
            {
                // Graceful fallback for non-supported platform socket drivers
            }
        }

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

        public async Task StartAsync(CancellationToken ct)
        {
            int reconnectDelayMs = 1000;
            const int maxReconnectDelayMs = 10000;

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
                        int bytesRead = await stream.ReadAsync(readBuffer.AsMemory(), ct);
                        if (bytesRead == 0) break;

                        foreach (var (rawFrame, recType) in _accumulator.PushBytesAndExtractFrames(readBuffer, bytesRead))
                        {
                            // Transform TWTT & hydrographic depth in-place
                            byte[] modifiedFrame = S7KFrameProcessor.ProcessAndModifyS7KRecord(rawFrame);

                            _telemetryCallback(modifiedFrame.Length, recType, modifiedFrame);
                            _frameQueue.Writer.TryWrite(modifiedFrame);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
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
    }
}