using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace ShazrinSonar
{
    // Persistent configuration model
    public class AppSettings
    {
        public int ListenPort { get; set; } = 7000;
        public string ForwardIp { get; set; } = "127.0.0.1";
        public int ForwardPort { get; set; } = 7001;
    }

    internal class Program
    {
        private static readonly string ConfigPath = "ShazrinSonar_Config.json";
        private static AppSettings Config = new AppSettings();

        // High-throughput, zero-lock channel for UDP packet streaming
        private static readonly Channel<byte[]> PacketChannel = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true
        });

        private static long _packetsReceived = 0;
        private static long _packetsForwarded = 0;

        static async Task Main(string[] args)
        {
            LoadConfiguration();

            Console.Title = "ShazrinSonar Engine - UDP Interceptor Pipeline";
            Console.WriteLine("==================================================");
            Console.WriteLine("          SHAZRIN SONAR DATA PIPELINE            ");
            Console.WriteLine("==================================================");
            Console.WriteLine($"[+] Listening on UDP Port: {Config.ListenPort}");
            Console.WriteLine($"[+] Forwarding to UDP:     {Config.ForwardIp}:{Config.ForwardPort}");
            Console.WriteLine("--------------------------------------------------\n");

            using var cts = new CancellationTokenSource();

            // Fire off async background loops
            Task receiveTask = Task.Run(() => StartReceiverAsync(Config.ListenPort, PacketChannel.Writer, cts.Token));
            Task processTask = Task.Run(() => StartProcessorAndForwarderAsync(Config.ForwardIp, Config.ForwardPort, PacketChannel.Reader, cts.Token));
            Task statsTask = Task.Run(() => DisplayStatsAsync(cts.Token));

            Console.WriteLine("Press [ENTER] to stop the proxy pipeline...\n");
            Console.ReadLine();

            cts.Cancel();
            await Task.WhenAll(receiveTask, processTask, statsTask);
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

        private static async Task StartReceiverAsync(int port, ChannelWriter<byte[]> writer, CancellationToken ct)
        {
            using var udpClient = new UdpClient(port);
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult result = await udpClient.ReceiveAsync(ct);
                    Interlocked.Increment(ref _packetsReceived);
                    await writer.WriteAsync(result.Buffer, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n[ERROR Receiver] {ex.Message}");
                }
            }
        }

        private static async Task StartProcessorAndForwarderAsync(string targetIp, int targetPort, ChannelReader<byte[]> reader, CancellationToken ct)
        {
            using var udpClient = new UdpClient();
            var targetEndpoint = new IPEndPoint(IPAddress.Parse(targetIp), targetPort);

            await foreach (byte[] rawPacket in reader.ReadAllAsync(ct))
            {
                try
                {
                    // Processing logic (S7K Binary Decoder + Depth Modification will sit here)
                    byte[] processedPacket = ModifyS7KPacket(rawPacket);

                    await udpClient.SendAsync(processedPacket, processedPacket.Length, targetEndpoint);
                    Interlocked.Increment(ref _packetsForwarded);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n[ERROR Processor] {ex.Message}");
                }
            }
        }

        private static byte[] ModifyS7KPacket(byte[] packet)
        {
            // Direct pass-through for now
            return packet;
        }

        private static async Task DisplayStatsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                Console.SetCursorPosition(0, 8);
                Console.WriteLine($"Packets Ingested : {Interlocked.Read(ref _packetsReceived):N0}");
                Console.WriteLine($"Packets Forwarded: {Interlocked.Read(ref _packetsForwarded):N0}");
                await Task.Delay(250, ct);
            }
        }
    }
}