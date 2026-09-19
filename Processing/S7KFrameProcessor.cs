using System;
using System.Buffers.Binary;
using ShazrinSonar.Config;

namespace ShazrinSonar.Processing
{
    public struct ExtractedBeamPoint
    {
        public ushort BeamIndex;
        public float Twtt;
        public float BeamAngleRad;
        public uint Quality;
        public double SlantRange;
        public double CorrectedDepthZ;
        public double AcrossTrackY;
        public double AlongTrackX;
        public double RelativeEasting;
        public double RelativeNorthing;

    }

    public static class S7KFrameProcessor
    {
        public static HydrographicConfig Settings { get; set; } = new HydrographicConfig();
        // Change EnableDebugLogging to "true" if want to create debug logs, else "false"
        // public static bool EnableDebugLogging { get; set; } = false; 
        public static bool EnableDebugLogging { get; set; } = true;
        // Mocked inside the zone for testing
        public static double CurrentLatitude { get; set; } = 2.925000;
        public static double CurrentLongitude { get; set; } = 101.338000;

        public static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame == null) return Array.Empty<byte>();

            // Total minimum length is 36 (Wrapper) + 64 (S7K Header) + 32 (Min Data) = 132 bytes
            if (frame.Length < 132) return frame;

            // Extract Record Type from the inner S7K header (Byte 68)
            uint recType32 = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(68, 4));

            if (recType32 == 7027)
            {
                ProcessRecord7027(frame);
            }

            return frame;
        }

        public static ExtractedBeamPoint[] ProcessRecord7027(
    byte[] frame,
    double vesselRollRad = 0.0,
    double vesselPitchRad = 0.0,
    double vesselHeadingRad = 0.0)
        {
            // Minimum theoretical size for a Record 7027 frame with at least 1 beam
            if (frame == null || frame.Length < 96) return Array.Empty<ExtractedBeamPoint>();

            double soundVelocity = Settings.SoundVelocity > 100.0 ? Settings.SoundVelocity : 1500.0;

            // 1. DYNAMIC OFFSET ALIGNMENT (Simulator-Safe)
            // Dynamically scan for the S7K Sync Pattern (0x0000FFFF)
            // The Sync Pattern is always located at bytes 4-7 of the 64-byte S7K Header.
            int syncOffset = -1;
            for (int i = 0; i < 64; i += 2)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(i, 4)) == 0x0000FFFF)
                {
                    syncOffset = i;
                    break;
                }
            }

            if (syncOffset < 4) return Array.Empty<ExtractedBeamPoint>(); // Invalid S7K header

            // The Record 7027 payload begins exactly 64 bytes after the start of the S7K header.
            // Since syncOffset is at byte 4 of the header, the payload starts at syncOffset - 4 + 64 = syncOffset + 60.
            int payloadStart = syncOffset + 60;
            if (payloadStart + 36 > frame.Length) return Array.Empty<ExtractedBeamPoint>();

            Span<byte> recordData = frame.AsSpan(payloadStart);

            // Ping Number is at payload offset 8; Beam Count is at payload offset 14
            uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(8, 4));
            ushort beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(14, 2));

            // [SIMULATOR FIX]: Default to 512 beams (as seen in terminal metrics) if header is corrupted
            if (beamCount == 0 || beamCount > 2048) beamCount = 512;

            // Data array offsets relative to the start of the payload
            int twttArrayOffset = 32;
            int qualityArrayOffset = twttArrayOffset + (int)(beamCount * 4);
            int angleArrayOffset = qualityArrayOffset + (int)(beamCount * 4);

            if (recordData.Length < twttArrayOffset + 4) return Array.Empty<ExtractedBeamPoint>();

            var validPoints = new ExtractedBeamPoint[beamCount];
            int validBeamCount = 0;

            // Evaluate Geofence Switch (Hardcoded to true for lab testing until GPS is integrated)
            bool insideTargetZone = true; // GeofenceManager.IsInside(CurrentLatitude, CurrentLongitude);
            ushort centerBeamIndex = (ushort)(beamCount / 2);

            for (ushort i = 0; i < beamCount; i++)
            {
                int currentTwttOffset = twttArrayOffset + (i * 4);
                if (currentTwttOffset + 4 > recordData.Length) break;

                float twtt = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(currentTwttOffset, 4));

                uint quality = 0x01;
                int currentQualityOffset = qualityArrayOffset + (i * 4);
                if (currentQualityOffset + 4 <= recordData.Length)
                {
                    quality = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(currentQualityOffset, 4));
                }

                float beamAngle = 0.0f;
                int currentAngleOffset = angleArrayOffset + (i * 4);
                if (currentAngleOffset + 4 <= recordData.Length)
                {
                    beamAngle = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(currentAngleOffset, 4));
                }

                // [SIMULATOR OVERRIDE]: Acoustic noise filters disabled for lab testing.
                // Simulator "air pings" have near-zero travel times and invalid quality flags.
                // if (twtt <= 0.0001f) continue;
                // if (Settings.FilterLowQualityBeams && Settings.MinQualityFlag != 0 && quality != 0)
                // {
                //     if ((quality & Settings.MinQualityFlag) == 0) continue;
                // }

                if (!insideTargetZone) continue;

                // 3D Spatial Computation
                double slantRange = (soundVelocity * twtt) / 2.0;
                double totalAngleRad = beamAngle + vesselRollRad;
                double depthZRaw = slantRange * Math.Cos(totalAngleRad) * Math.Cos(vesselPitchRad);
                double acrossTrackY = slantRange * Math.Sin(totalAngleRad);
                double alongTrackX = slantRange * Math.Sin(vesselPitchRad);

                // Apply dynamic Draft and Tide corrections to the raw depth
                double correctedDepthZ = depthZRaw + Settings.TransducerDraft + Settings.WaterLevelOffset;

                double sinHeading = Math.Sin(vesselHeadingRad);
                double cosHeading = Math.Cos(vesselHeadingRad);

                double relEasting = (alongTrackX * sinHeading) + (acrossTrackY * cosHeading) + Settings.GpsOffsetX;
                double relNorthing = (alongTrackX * cosHeading) - (acrossTrackY * sinHeading) + Settings.GpsOffsetY;

                // Recalculate TWTT float based on the newly modified depth
                float depthTwttModified = (float)((correctedDepthZ * 2.0) / soundVelocity);

                // Overwrite the original TWTT byte span directly in the frame buffer
                BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(currentTwttOffset, 4), depthTwttModified);

                // PROOF OF MATHEMATICS: Log the Nadir (center) beam modification to the console
                if (i == centerBeamIndex && EnableDebugLogging)
                {
                    Console.WriteLine($"[GEO-MOD ACTIVE] Beam {i} | Old Depth: {depthZRaw:F2}m -> New Depth: {correctedDepthZ:F2}m");
                }

                validPoints[validBeamCount++] = new ExtractedBeamPoint
                {
                    BeamIndex = i,
                    Twtt = depthTwttModified,
                    BeamAngleRad = beamAngle,
                    Quality = quality,
                    SlantRange = slantRange,
                    CorrectedDepthZ = correctedDepthZ,
                    AcrossTrackY = acrossTrackY,
                    AlongTrackX = alongTrackX,
                    RelativeEasting = relEasting,
                    RelativeNorthing = relNorthing
                };
            }

            Array.Resize(ref validPoints, validBeamCount);
            return validPoints;
        }
    }
}