using System;
using System.IO;

namespace ShazrinSonar.Networking
{
    public static class StreamAuditor
    {
        private static readonly object _lock = new object();
        private static int _logCount = 0;
        private const int MAX_LOGS = 1000; // Stop logging after 1000 frames to save disk space

        public static void LogFrame(string stage, byte[] frame)
        {
            if (frame == null || frame.Length < 16) return;
            if (_logCount >= MAX_LOGS) return;

            // Grab the first 16 bytes of the frame (The S7K Sync Header)
            string hex = BitConverter.ToString(frame, 0, 16); 
            string log = $"[{DateTime.Now:HH:mm:ss.fff}] {stage,-8} | Size: {frame.Length,-6} | Head: {hex}";
            
            lock (_lock)
            {
                File.AppendAllText("s7k_pipeline_audit.log", log + Environment.NewLine);
                _logCount++;
            }
        }
    }
}