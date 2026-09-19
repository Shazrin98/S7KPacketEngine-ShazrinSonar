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
        private static readonly object _fileLock = new object();

        public QinsyForwarder(AppSettings config, Channel<byte[]> frameQueue, Action<string> logger)
        {
            _config = config;
            _frameQueue = frameQueue;
            _logger = logger;
        }

        private static void ConfigureSocketOptions(Socket socket)
        {
            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                socket.NoDelay = true; // Disable Nagle's algorithm for low-latency transmission
            }
            catch (Exception ex)
            {
                SafeLog("pipeline_debug.log", $"[WARN] Socket option warning: {ex.Message}");
            }
        }

        public async Task StartAsync(CancellationToken ct)
        {
            string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pipeline_debug.log");

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
                            ConfigureSocketOptions(qinsyClient.Client);

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

                                        SafeLog(logPath, $"[FORWARDER] Writing frame (Length: {frame.Length}) to Qinsy client on port {_config.TargetPort}");

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
                // Non-blocking catch to ensure logging never interrupts telemetry transmission
            }
        }
    }
}