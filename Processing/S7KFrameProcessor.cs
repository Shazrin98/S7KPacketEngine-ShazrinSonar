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
        public static bool EnableDebugLogging { get; set; } = false;
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
            if (frame == null || frame.Length < 132) return Array.Empty<ExtractedBeamPoint>();

            double soundVelocity = Settings.SoundVelocity > 100.0 ? Settings.SoundVelocity : 1500.0;

            // Skip the 36-byte wrapper and the 64-byte S7K header to reach the Record 7027 Data block
            Span<byte> recordData = frame.AsSpan(100);

            // Ping Number is at Record Header offset 8
            uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(8, 4));
            // Beam Count is at Record Header offset 14
            ushort beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(14, 2));

            if (beamCount == 0 || beamCount > 2048) beamCount = 1;

            int twttArrayOffset = 32; // This is relative to the recordData span (Absolute byte 132 in the frame)
            int qualityArrayOffset = twttArrayOffset + (int)(beamCount * 4);
            int angleArrayOffset = qualityArrayOffset + (int)(beamCount * 4);

            if (recordData.Length < twttArrayOffset + 4) return Array.Empty<ExtractedBeamPoint>();

            var validPoints = new ExtractedBeamPoint[beamCount];
            int validBeamCount = 0;

            // Evaluate Geofence Switch
            bool insideTargetZone = GeofenceManager.IsInside(CurrentLatitude, CurrentLongitude);
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

                if (twtt <= 0.0001f) continue;

                if (Settings.FilterLowQualityBeams && Settings.MinQualityFlag != 0 && quality != 0)
                {
                    if ((quality & Settings.MinQualityFlag) == 0) continue;
                }

                // If outside the geofence, skip modifications entirely (leaves the byte array as raw Norbit data)
                if (!insideTargetZone) continue;

                // 3D Spatial Computation
                double slantRange = (soundVelocity * twtt) / 2.0;
                double totalAngleRad = beamAngle + vesselRollRad;
                double depthZRaw = slantRange * Math.Cos(totalAngleRad) * Math.Cos(vesselPitchRad);
                double acrossTrackY = slantRange * Math.Sin(totalAngleRad);
                double alongTrackX = slantRange * Math.Sin(vesselPitchRad);

                double correctedDepthZ = depthZRaw + Settings.TransducerDraft + Settings.WaterLevelOffset;

                double sinHeading = Math.Sin(vesselHeadingRad);
                double cosHeading = Math.Cos(vesselHeadingRad);

                double relEasting = (alongTrackX * sinHeading) + (acrossTrackY * cosHeading) + Settings.GpsOffsetX;
                double relNorthing = (alongTrackX * cosHeading) - (acrossTrackY * sinHeading) + Settings.GpsOffsetY;

                float depthTwttModified = (float)((correctedDepthZ * 2.0) / soundVelocity);

                // Overwrite TWTT directly in the frame buffer 
                BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(currentTwttOffset, 4), depthTwttModified);

                // PROOF: Log the modification of the Nadir (center) beam to verify the math
                if (i == centerBeamIndex && EnableDebugLogging)
                {
                    double originalDepth = ((soundVelocity * twtt) / 2.0) * Math.Cos(beamAngle);
                    Console.WriteLine($"[GEO-MOD ACTIVE] Beam {i} | Old Depth: {originalDepth:F2}m -> New Depth: {correctedDepthZ:F2}m");
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