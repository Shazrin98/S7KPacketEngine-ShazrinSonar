using System;
using System.IO;

namespace ShazrinSonar.Logging
{
    public class RollingFileLogger
    {
        private readonly string _filePath;
        private readonly long _maxSizeBytes;
        private readonly int _maxRollFiles;
        private readonly object _lock = new();

        public RollingFileLogger(string filePath = "s7k_debug.log", long maxSizeBytes = 10 * 1024 * 1024, int maxRollFiles = 5)
        {
            _filePath = filePath;
            _maxSizeBytes = maxSizeBytes; // Default: 10 MB per log file
            _maxRollFiles = maxRollFiles; // Retain up to 5 rotated archives
        }

        public void Log(string message)
        {
            lock (_lock)
            {
                try
                {
                    FileInfo fileInfo = new FileInfo(_filePath);
                    if (fileInfo.Exists && fileInfo.Length >= _maxSizeBytes)
                    {
                        RollFiles();
                    }

                    string logEntry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
                    File.AppendAllText(_filePath, logEntry);
                }
                catch
                {
                    // Guard against logging failures interrupting active packet ingestion
                }
            }
        }

        private void RollFiles()
        {
            for (int i = _maxRollFiles - 1; i >= 1; i--)
            {
                string source = $"s7k_debug_{i}.log";
                string target = $"s7k_debug_{i + 1}.log";
                if (File.Exists(source))
                {
                    if (File.Exists(target)) File.Delete(target);
                    File.Move(source, target);
                }
            }

            if (File.Exists(_filePath))
            {
                string firstArchive = "s7k_debug_1.log";
                if (File.Exists(firstArchive)) File.Delete(firstArchive);
                File.Move(_filePath, firstArchive);
            }
        }
    }
}