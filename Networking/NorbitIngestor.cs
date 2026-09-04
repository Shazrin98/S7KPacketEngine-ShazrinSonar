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
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 5);      // 5 seconds idle before probing
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 1);  // 1 second interval between probes
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3); // 3 failed probes before dropping connection
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
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var client = new TcpClient();
                    _logger($"Connecting to {_config.SourceIp}:{_config.SourcePort}...");
                    await client.ConnectAsync(_config.SourceIp, _config.SourcePort, ct);
                    // Enable aggressive Keep-Alive
                    ConfigureKeepAlive(client.Client);
                    _logger("Connected to Norbit stream source.");

                    // Clear stream accumulator state prior to reading new socket bytes
                    _accumulator.Clear();

                    using NetworkStream stream = client.GetStream();
                    byte[] readBuffer = new byte[32768];

                    while (!ct.IsCancellationRequested && client.Connected)
                    {
                        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length, ct);
                        if (bytesRead == 0) break;

                        foreach (var (frame, recType) in _accumulator.PushBytesAndExtractFrames(readBuffer, bytesRead))
                        {
                            _telemetryCallback(bytesRead, recType, frame);
                            _frameQueue.Writer.TryWrite(frame);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _accumulator.Clear(); // Clear corrupt stream fragments on network error
                    _logger($"Ingest Error: {ex.Message}");
                    try { await Task.Delay(2000, ct); } catch (OperationCanceledException) { break; }
                }
            }
        }
    }
}