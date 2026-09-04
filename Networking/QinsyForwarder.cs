using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using ShazrinSonar.Config;

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
                // Graceful fallback for unsupported platform socket options
            }
        }

        public async Task StartAsync(CancellationToken ct)
        {
            if (_config.TargetProtocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                var listener = new TcpListener(IPAddress.Any, _config.TargetPort);
                
                try
                {
                    listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
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
                            ConfigureKeepAlive(qinsyClient.Client);
                            
                            _logger("Qinsy client connected.");

                            using NetworkStream qinsyStream = qinsyClient.GetStream();

                            // Read pre-modified frames from queue and stream directly
                            while (!ct.IsCancellationRequested && qinsyClient.Connected)
                            {
                                if (await _frameQueue.Reader.WaitToReadAsync(ct))
                                {
                                    bool wroteAny = false;
                                    while (_frameQueue.Reader.TryRead(out byte[]? frame))
                                    {
                                        if (frame == null || frame.Length == 0) continue;

                                        // Write frame asynchronously using ReadOnlyMemory overload
                                        await qinsyStream.WriteAsync(frame.AsMemory(), ct);
                                        wroteAny = true;
                                    }

                                    // Flush network stream once per batch drain to optimize context switches
                                    if (wroteAny)
                                    {
                                        await qinsyStream.FlushAsync(ct);
                                    }
                                }
                            }
                        }
                        catch (OperationCanceledException) { break; }
                        catch (IOException ex)
                        {
                            _logger($"Client session ended: {ex.Message}");
                        }
                        catch (SocketException ex)
                        {
                            _logger($"Client socket exception: {ex.Message}");
                        }
                        catch (Exception ex)
                        {
                            _logger($"Client session error: {ex.Message}");
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
                
                string targetIpStr = string.IsNullOrWhiteSpace(_config.SourceIp) ? "127.0.0.1" : _config.SourceIp;
                if (!IPAddress.TryParse(targetIpStr, out var targetIp))
                {
                    targetIp = IPAddress.Loopback;
                }

                var targetEndpoint = new IPEndPoint(targetIp, _config.TargetPort);
                _logger($"Qinsy UDP Forwarder broadcasting to {targetEndpoint}...");

                try
                {
                    await foreach (byte[] frame in _frameQueue.Reader.ReadAllAsync(ct))
                    {
                        if (frame == null || frame.Length == 0) continue;
                        await udpClient.SendAsync(frame.AsMemory(), targetEndpoint, ct);
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