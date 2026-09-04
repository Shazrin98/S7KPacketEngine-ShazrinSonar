using System;
using System.IO;
using System.Text.Json;

namespace ShazrinSonar.Config
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

    public class ConfigManager
    {
        private readonly string _configPath;
        private AppSettings _currentSettings;
        private readonly object _lock = new object();

        public ConfigManager(string configPath = "ShazrinSonar_Config.json")
        {
            _configPath = configPath;
            _currentSettings = LoadFromFile();
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

        public bool TryReload(out AppSettings updatedSettings)
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
            catch
            {
                updatedSettings = Current;
                return false;
            }
        }

        private AppSettings LoadFromFile()
        {
            if (!File.Exists(_configPath))
            {
                var defaultConfig = new AppSettings();
                string json = JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
                return defaultConfig;
            }

            string content = File.ReadAllText(_configPath);
            return JsonSerializer.Deserialize<AppSettings>(content) ?? new AppSettings();
        }
    }
}