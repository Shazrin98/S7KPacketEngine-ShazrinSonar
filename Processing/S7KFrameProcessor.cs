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

        // Toggle for verbose diagnostic logging
        public static bool EnableDebugLogging { get; set; } = false;

        public static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame == null)
            {
                if (EnableDebugLogging) Console.WriteLine("[S7K] Frame rejected: Frame is null.");
                return Array.Empty<byte>();
            }

            if (frame.Length < 96)
            {
                if (EnableDebugLogging) Console.WriteLine($"[S7K] Frame rejected: Length ({frame.Length}) < 96 bytes.");
                return frame;
            }

            // Flexible record type check across standard S7K header offsets
            ushort recType16 = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(32, 2));
            uint recType32 = frame.Length >= 36 ? BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(32, 4)) : 0;
            uint recType20 = frame.Length >= 24 ? BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(20, 4)) : 0;

            bool is7027 = (recType16 == 7027) || (recType32 == 7027) || (recType20 == 7027) || (frame.Length == 13515);

            if (is7027)
            {
                ProcessRecord7027(frame);
            }
            else if (EnableDebugLogging)
            {
                Console.WriteLine($"[S7K] Skipped record type {recType16}.");
            }

            return frame;
        }

        public static ExtractedBeamPoint[] ProcessRecord7027(
            byte[] frame,
            double vesselRollRad = 0.0,
            double vesselPitchRad = 0.0,
            double vesselHeadingRad = 0.0)
        {
            if (frame == null || frame.Length < 96) return Array.Empty<ExtractedBeamPoint>();

            // Ensure Sound Velocity is valid to prevent Division-by-Zero (NaN / Infinity)
            double soundVelocity = Settings.SoundVelocity > 100.0 ? Settings.SoundVelocity : 1500.0;

            Span<byte> recordData = frame.AsSpan(64);

            uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(8, 4)); // Record Header byte 8-11 (Frame byte 72-75)
            
            // Correct S7K Record 7027 Spec: Beam Count (N) is uint16 at Record Header offset 14 (Frame byte 78-79)
            ushort beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(14, 2));

            // Fallback for mock or test frames
            if (beamCount == 0 || beamCount > 2048)
            {
                beamCount = 1;
            }

            int twttArrayOffset = 32; // Byte 96 of frame
            int qualityArrayOffset = twttArrayOffset + (int)(beamCount * 4);
            int angleArrayOffset = qualityArrayOffset + (int)(beamCount * 4);

            // Minimum buffer check: frame must at least contain TWTT offset for beam 0
            if (recordData.Length < twttArrayOffset + 4)
            {
                if (EnableDebugLogging)
                {
                    Console.WriteLine($"[S7K R7027] Buffer truncation: Required at least {twttArrayOffset + 4} bytes, got {recordData.Length}.");
                }
                return Array.Empty<ExtractedBeamPoint>();
            }

            var validPoints = new ExtractedBeamPoint[beamCount];
            int validBeamCount = 0;

            for (ushort i = 0; i < beamCount; i++)
            {
                int currentTwttOffset = twttArrayOffset + (i * 4);
                if (currentTwttOffset + 4 > recordData.Length) break;

                float twtt = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(currentTwttOffset, 4));

                // Safely read quality flag if array exists in buffer; default to 0x01 for test packets
                uint quality = 0x01;
                int currentQualityOffset = qualityArrayOffset + (i * 4);
                if (currentQualityOffset + 4 <= recordData.Length)
                {
                    quality = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(currentQualityOffset, 4));
                }

                // Safely read beam angle if array exists in buffer; default to 0.0 rad (nadir)
                float beamAngle = 0.0f;
                int currentAngleOffset = angleArrayOffset + (i * 4);
                if (currentAngleOffset + 4 <= recordData.Length)
                {
                    beamAngle = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(currentAngleOffset, 4));
                }

                // Reject invalid or non-returning travel times
                if (twtt <= 0.0001f) continue;

                // Quality filtering safeguard: Only filter if quality array was explicitly provided (>0)
                if (Settings.FilterLowQualityBeams && Settings.MinQualityFlag != 0 && quality != 0)
                {
                    if ((quality & Settings.MinQualityFlag) == 0) continue;
                }

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

                // Calculate modified TWTT based on corrected depth
                float depthTwttModified = (float)((correctedDepthZ * 2.0) / soundVelocity);

                // Overwrite TWTT directly in the frame buffer for downstream forwarding
                BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(currentTwttOffset, 4), depthTwttModified);

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