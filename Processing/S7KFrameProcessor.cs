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

        public static byte[] ProcessAndModifyS7KRecord(byte[] frame)
        {
            if (frame.Length >= 96)
            {
                ushort recType = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(32, 2));

                if (recType == 7027 || frame.Length == 13515)
                {
                    ProcessRecord7027(frame);
                }
            }

            return frame;
        }

        public static ExtractedBeamPoint[] ProcessRecord7027(
            byte[] frame,
            double vesselRollRad = 0.0,
            double vesselPitchRad = 0.0,
            double vesselHeadingRad = 0.0)
        {
            if (frame.Length < 96) return Array.Empty<ExtractedBeamPoint>();

            Span<byte> recordData = frame.AsSpan(64);

            uint pingNumber = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(0, 4));
            uint beamCount = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(8, 4));

            if (beamCount == 0 || beamCount > 2048)
            {
                beamCount = BinaryPrimitives.ReadUInt16LittleEndian(recordData.Slice(8, 2));
            }

            if (beamCount == 0 || beamCount > 2048) return Array.Empty<ExtractedBeamPoint>();

            int twttArrayOffset = 32;
            int qualityArrayOffset = twttArrayOffset + (int)(beamCount * 4);
            int angleArrayOffset = qualityArrayOffset + (int)(beamCount * 4);

            if (recordData.Length < angleArrayOffset + (beamCount * 4))
            {
                return Array.Empty<ExtractedBeamPoint>();
            }

            var validPoints = new ExtractedBeamPoint[beamCount];
            int validBeamCount = 0;

            for (ushort i = 0; i < beamCount; i++)
            {
                float twtt = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(twttArrayOffset + (i * 4), 4));
                uint quality = BinaryPrimitives.ReadUInt32LittleEndian(recordData.Slice(qualityArrayOffset + (i * 4), 4));
                float beamAngle = BinaryPrimitives.ReadSingleLittleEndian(recordData.Slice(angleArrayOffset + (i * 4), 4));

                if (twtt <= 0.0001f) continue;
                if (Settings.FilterLowQualityBeams && (quality & Settings.MinQualityFlag) == 0) continue;

                double slantRange = (Settings.SoundVelocity * twtt) / 2.0;
                double totalAngleRad = beamAngle + vesselRollRad;
                double depthZRaw = slantRange * Math.Cos(totalAngleRad) * Math.Cos(vesselPitchRad);
                double acrossTrackY = slantRange * Math.Sin(totalAngleRad);
                double alongTrackX = slantRange * Math.Sin(vesselPitchRad);

                double correctedDepthZ = depthZRaw + Settings.TransducerDraft + Settings.WaterLevelOffset;

                double sinHeading = Math.Sin(vesselHeadingRad);
                double cosHeading = Math.Cos(vesselHeadingRad);

                double relEasting = (alongTrackX * sinHeading) + (acrossTrackY * cosHeading) + Settings.GpsOffsetX;
                double relNorthing = (alongTrackX * cosHeading) - (acrossTrackY * sinHeading) + Settings.GpsOffsetY;

                float depthTwttModified = (float)((correctedDepthZ * 2.0) / Settings.SoundVelocity);
                BinaryPrimitives.WriteSingleLittleEndian(recordData.Slice(twttArrayOffset + (i * 4), 4), depthTwttModified);

                validPoints[validBeamCount++] = new ExtractedBeamPoint
                {
                    BeamIndex = i,
                    Twtt = twtt,
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