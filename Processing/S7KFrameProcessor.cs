using System;
using System.Buffers.Binary;
using System.IO;
using ShazrinSonar.Config;

namespace ShazrinSonar.Processing
{
    public static class S7KFrameProcessor
    {
        public static HydrographicConfig Settings { get; set; } = new HydrographicConfig();
        public static bool EnableDebugLogging { get; set; } = false;

        private static int _pingCounter = 0;
        private static readonly object _logLock = new object();

        private static void SafeLog(string message)
        {
            try
            {
                lock (_logLock)
                {
                    using var stream = new FileStream("angle_diagnostics.log", FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(stream);
                    writer.WriteLine(message);
                }
            }
            catch { } // Prevent logging exceptions from crashing the pipeline
        }

        public static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame == null || frame.Length < 132) return frame ?? Array.Empty<byte>();

            uint recType32 = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(68, 4));

            if (recType32 == 7027)
            {
                ProcessRecord7027(frame);
            }
            else if (recType32 == 1013) // Assuming 1013 handles geofence parsing
            {
                ProcessRecord1003(frame);
            }

            return frame;
        }

        private static void ProcessRecord7027(byte[] frame)
        {
            int syncOffset = -1;
            
            // 1. Locate S7K Sync Header
            for (int i = 0; i < frame.Length - 4; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(i, 4)) == 0x0000FFFF)
                {
                    syncOffset = i;
                    break;
                }
            }

            if (syncOffset < 4) return;

            int frameStart = syncOffset - 4;
            uint s7kSize = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(frameStart + 8, 4));
            
            if (frameStart + (int)s7kSize > frame.Length) return;

            int payloadStart = frameStart + 64;
            Span<byte> recordData = frame.AsSpan(payloadStart);

            ushort beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(14, 2));
            if (beamCount == 0 || beamCount > 2048) return;

            float liveSoundVelocity = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(20, 4));
            if (liveSoundVelocity < 1000f || liveSoundVelocity > 1650f) liveSoundVelocity = 1500f;

            int arrayStartOffset = 87;

            if (Settings.TargetDepthOffset != 0 && GeofenceManager.IsInsideTargetZone())
            {
                _pingCounter++;
                bool logThisPing = (_pingCounter % 50 == 0);

                if (logThisPing)
                {
                    SafeLog($"\n--- PING {_pingCounter} MODIFICATION TRACKER ---");
                }

                for (ushort i = 0; i < beamCount; i++)
                {
                    int currentBeamStructStart = arrayStartOffset + (i * 26);
                    if (currentBeamStructStart + 26 > recordData.Length) break;

                    int twttOffset = currentBeamStructStart + 4;
                    int sampleOffset = currentBeamStructStart + 14;
                    int angleOffset = currentBeamStructStart + 18;

                    float twtt = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(twttOffset, 4));
                    
                    // Skip dropped/invalid beams to prevent math errors (e.g., Beam 0)
                    if (twtt <= 0.0001f) continue;

                    float beamAngleRad = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(angleOffset, 4));
                    float cleanRad = beamAngleRad;
                    if (cleanRad < -3.1416f || cleanRad > 3.1416f || float.IsNaN(cleanRad))
                    {
                        cleanRad = 0f;
                    }

                    double cosAngle = Math.Cos(cleanRad);
                    if (cosAngle < 0.087) cosAngle = 0.087;

                    // Calculate Depth Addition
                    double extraTwtt = (Settings.TargetDepthOffset * 2.0) / (liveSoundVelocity * cosAngle);
                    float modifiedTwtt = twtt + (float)extraTwtt;

                    // Qinsy High-Precision Fallback: Scale the sub-sample index proportionally
                    float originalSample = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(sampleOffset, 4));
                    float modifiedSample = originalSample * (modifiedTwtt / twtt);

                    if (logThisPing && (i == 256 || i == 511))
                    {
                        SafeLog($"Beam {i,-3} | TWTT: {twtt,7:F5} -> {modifiedTwtt,7:F5} | Sample: {originalSample,7:F1} -> {modifiedSample,7:F1}");
                    }

                    // Overwrite both fields in the byte array
                    BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(twttOffset, 4), modifiedTwtt);
                    BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(sampleOffset, 4), modifiedSample);
                }

                // Keep the hardware's original bypass behavior (0)
                int checksumOffset = frameStart + (int)s7kSize - 4;
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(checksumOffset, 4), 0);
            }
        }

        public static void ProcessRecord1003(byte[] frame)
        {
            int syncOffset = -1;

            for (int i = 0; i < frame.Length - 4; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(i, 4)) == 0x0000FFFF)
                {
                    syncOffset = i;
                    break;
                }
            }

            if (syncOffset < 4) return;

            // CORRECTED: Apply the same true frame start logic to prevent geofence data drops
            int frameStart = syncOffset - 4;
            int payloadStart = frameStart + 64;

            if (payloadStart + 24 > frame.Length) return;

            Span<byte> recordData = frame.AsSpan(payloadStart);
            double latRadians = BinaryPrimitives.ReadDoubleLittleEndian(recordData.Slice(8, 8));
            double lonRadians = BinaryPrimitives.ReadDoubleLittleEndian(recordData.Slice(16, 8));

            double latDegrees = latRadians * (180.0 / Math.PI);
            double lonDegrees = lonRadians * (180.0 / Math.PI);

            GeofenceManager.UpdatePosition(latDegrees, lonDegrees);
        }
    }
}