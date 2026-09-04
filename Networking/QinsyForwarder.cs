using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using ShazrinSonar.Config;
using ShazrinSonar.Processing;

namespace ShazrinSonar.Networking
{
    public class QinsyForwarder
    {
        private readonly AppSettings _config;
        private readonly Channel<byte[]> _frameQueue;
        private readonly Action<string> _logger;

        public QinsyForwarder(AppSettings config, Channel<byte[]> frameQueue, Action<string> logger)
        {
            _config = config;
            _frameQueue = frameQueue;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken ct)
        {
            if (_config.TargetProtocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                var listener = new TcpListener(IPAddress.Any, _config.TargetPort);
                listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                try
                {
                    listener.Start();
                    _logger($"Qinsy TCP Forwarder listening on port {_config.TargetPort}.");
                }
                catch (SocketException ex) when (ex.ErrorCode == 10048)
                {
                    _logger($"[!] ERROR: Port {_config.TargetPort} is already bound by another process.");
                    _logger($"[!] FIX: Run in PowerShell: Stop-Process -Id (Get-NetTCPConnection -LocalPort {_config.TargetPort}).OwningProcess -Force");
                    return;
                }
                catch (Exception ex)
                {
                    _logger($"[!] Failed to start listener: {ex.Message}");
                    return;
                }

                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        try
                        {
                            using TcpClient qinsyClient = await listener.AcceptTcpClientAsync(ct);
                            // Configure Keep-Alive on Qinsy client socket
                            qinsyClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                            qinsyClient.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 5);
                            qinsyClient.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 1);
                            qinsyClient.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
                            _logger("Qinsy client connected.");

                            // Flush accumulated historical pings to guarantee live timing
                            int droppedCount = 0;
                            while (_frameQueue.Reader.TryRead(out _))
                            {
                                droppedCount++;
                            }
                            if (droppedCount > 0)
                            {
                                _logger($"[CRITICAL] Flushed {droppedCount} stale frame(s) from queue for real-time sync.");
                            }

                            using NetworkStream qinsyStream = qinsyClient.GetStream();

                            await foreach (byte[] frame in _frameQueue.Reader.ReadAllAsync(ct))
                            {
                                byte[] processedFrame = S7KFrameProcessor.ProcessAndModifyS7KRecord(frame);
                                await qinsyStream.WriteAsync(processedFrame, 0, processedFrame.Length, ct);
                            }
                        }
                        catch (OperationCanceledException) { break; }
                        catch (Exception ex)
                        {
                            _logger($"Client session ended: {ex.Message}");
                        }
                    }
                }
                finally
                {
                    listener.Stop();
                    _logger("Qinsy TCP Listener stopped.");
                }
            }
            else
            {
                using var udpClient = new UdpClient();
                var targetEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), _config.TargetPort);

                try
                {
                    await foreach (byte[] frame in _frameQueue.Reader.ReadAllAsync(ct))
                    {
                        byte[] processedFrame = S7KFrameProcessor.ProcessAndModifyS7KRecord(frame);
                        await udpClient.SendAsync(processedFrame, processedFrame.Length, targetEndpoint);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    _logger($"UDP Forwarder Error: {ex.Message}");
                }
            }
        }
    }
}