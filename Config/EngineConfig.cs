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

        // Security Settings
        public string AuthorizedLicenseKey { get; set; } = "SHAZRIN-HWID-DEMO-KEY";

        // Targeted Depth Manipulation
        public double TargetDepthOffset { get; set; } = 0.0;

        // Dynamic Geofence Polygon
        public List<GeoCoordinate> GeofencePolygon { get; set; } = new List<GeoCoordinate>();
    }

    public class ConfigManager : IDisposable
    {
        private readonly string _configPath;
        private AppSettings _currentSettings;
        private readonly object _lock = new object();
        private readonly FileSystemWatcher? _watcher;
        private DateTime _lastRead = DateTime.MinValue; 

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
            catch { }
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
            if ((DateTime.Now - _lastRead).TotalMilliseconds < 500) return;

            if (TryReload(out AppSettings updatedSettings))
            {
                _lastRead = DateTime.Now;
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
                    Thread.Sleep(100); 
                }
                catch { break; }
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