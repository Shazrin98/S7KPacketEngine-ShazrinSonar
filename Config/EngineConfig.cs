using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;

namespace ShazrinSonar.Config
{
    public class GeoCoordinate
    {
        public double Lat { get; set; }
        public double Lon { get; set; }
    }

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
        public double GpsOffsetX { get; set; } = 0.20;        // GPS to Transducer Starboard/Port offset (m)
        public double GpsOffsetY { get; set; } = 1.50;        // GPS to Transducer Bow/Stern offset (m)
        public bool FilterLowQualityBeams { get; set; } = true;
        public ushort MinQualityFlag { get; set; } = 0x01;

        // Targeted Depth Manipulation
        // Positive values push the seafloor deeper; Negative values pull the seafloor shallower.
        public double TargetDepthOffset { get; set; } = 0.0;

        // Dynamic Geofence Polygon
        // Allows users to define 3+ points to create an active spoofing zone.
        public List<GeoCoordinate> GeofencePolygon { get; set; } = new List<GeoCoordinate>();

        // Security Settings
        public string AuthorizedLicenseKey { get; set; } = "SHAZRIN-HWID-DEMO-KEY";

        // Converts AppSettings to HydrographicConfig for S7KFrameProcessor
        public HydrographicConfig ToHydrographicConfig()
        {
            return new HydrographicConfig
            {
                SoundVelocity = SoundVelocity,
                TransducerDraft = TransducerDraft,
                WaterLevelOffset = WaterLevelOffset,
                GpsOffsetX = GpsOffsetX,
                GpsOffsetY = GpsOffsetY,
                FilterLowQualityBeams = FilterLowQualityBeams,
                MinQualityFlag = MinQualityFlag,
                TargetDepthOffset = TargetDepthOffset // Pass the new variable
            };
        }
    }

    public class HydrographicConfig
    {
        public double SoundVelocity { get; set; } = 1500.0;     // m/s
        public double TransducerDraft { get; set; } = 0.85;     // Meters below surface
        public double WaterLevelOffset { get; set; } = -0.15;   // Tide / Datum correction (m)
        public double GpsOffsetX { get; set; } = 0.20;         // GPS to Transducer Starboard/Port offset (m)
        public double GpsOffsetY { get; set; } = 1.50;         // GPS to Transducer Bow/Stern offset (m)
        public bool FilterLowQualityBeams { get; set; } = true;
        public ushort MinQualityFlag { get; set; } = 0x01;     // Bit 0 = Valid Detection

        // Carried over to the processing engine
        public double TargetDepthOffset { get; set; } = 0.0;
    }

    public class ConfigManager : IDisposable
    {
        private readonly string _configPath;
        private AppSettings _currentSettings;
        private readonly object _lock = new object();
        private readonly FileSystemWatcher? _watcher;

        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        public event Action<AppSettings>? OnConfigReloaded;

        public ConfigManager(string configPath = "ShazrinSonar_Config.json")
        {
            _configPath = configPath;
            _currentSettings = LoadFromFile();

            try
            {
                string fullPath = Path.GetFullPath(_configPath);
                string? directory = Path.GetDirectoryName(fullPath);
                string fileName = Path.GetFileName(fullPath);

                if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory))
                {
                    _watcher = new FileSystemWatcher(directory, fileName)
                    {
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                        EnableRaisingEvents = true
                    };

                    _watcher.Changed += OnFileChanged;
                    _watcher.Renamed += OnFileChanged;
                }
            }
            catch
            {
                // Fallback gracefully if filesystem watching is restricted
            }
        }

        public AppSettings Current
        {
            get
            {
                lock (_lock)
                {
                    return _currentSettings;
                }
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // Pause briefly to allow external file write locks to release
            Thread.Sleep(150);

            if (TryReload(out AppSettings updatedSettings))
            {
                OnConfigReloaded?.Invoke(updatedSettings);
            }
        }

        public bool TryReload(out AppSettings updatedSettings)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    var newSettings = LoadFromFile();
                    lock (_lock)
                    {
                        _currentSettings = newSettings;
                    }
                    updatedSettings = newSettings;
                    return true;
                }
                catch (IOException)
                {
                    // Delay retry for active editor write locks
                    Thread.Sleep(100);
                }
                catch
                {
                    break;
                }
            }

            updatedSettings = Current;
            return false;
        }

        private AppSettings LoadFromFile()
        {
            if (!File.Exists(_configPath))
            {
                var defaultConfig = new AppSettings();
                string json = JsonSerializer.Serialize(defaultConfig, JsonOptions);
                File.WriteAllText(_configPath, json);
                return defaultConfig;
            }

            using var stream = new FileStream(_configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            string content = reader.ReadToEnd();

            return JsonSerializer.Deserialize<AppSettings>(content, JsonOptions) ?? new AppSettings();
        }

        public void Dispose()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Changed -= OnFileChanged;
                _watcher.Renamed -= OnFileChanged;
                _watcher.Dispose();
            }
        }
    }
}