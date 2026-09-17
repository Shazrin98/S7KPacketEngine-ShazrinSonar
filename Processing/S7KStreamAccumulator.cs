using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ShazrinSonar.Processing
{
    public class S7KStreamAccumulator
    {
        private readonly List<byte> _buffer = new List<byte>();
        private readonly Action<string>? _diagnosticLogger;

        public S7KStreamAccumulator(Action<string>? diagnosticLogger = null)
        {
            _diagnosticLogger = diagnosticLogger;
        }

        public void Clear()
        {
            _buffer.Clear();
        }

        public (List<(byte[] Frame, ushort RecType)> Frames, int GarbageBytes) PushBytesAndExtractFrames(byte[] buffer, int bytesRead)
        {
            var frames = new List<(byte[] Frame, ushort RecType)>();
            if (buffer == null || bytesRead <= 0) return (frames, 0);

            int garbageSkipped = 0;

            for (int i = 0; i < bytesRead; i++)
            {
                _buffer.Add(buffer[i]);
            }

            // We need at least 36 bytes (Norbit Wrapper) + 64 bytes (S7K Header) = 100 bytes
            while (_buffer.Count >= 100)
            {
                Span<byte> bufferSpan = CollectionsMarshal.AsSpan(_buffer);

                // 1. Verify Norbit Wrapper Version (0x05) at Byte 0 and S7K Sync Pattern (0x0000FFFF) at Byte 40
                ushort wrapperVersion = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(0, 2));
                uint s7kSyncPattern = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(40, 4));

                if (wrapperVersion != 5 || s7kSyncPattern != 0x0000FFFF)
                {
                    garbageSkipped++;
                    _buffer.RemoveAt(0); // Slide window by 1 byte to find the next valid wrapped header
                    continue;
                }

                // 2. Extract Total Wrapped Frame Size from the Norbit Wrapper (Bytes 12-15)
                uint totalFrameSize = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(12, 4));

                if (totalFrameSize < 100 || totalFrameSize > 2097152)
                {
                    garbageSkipped++;
                    _buffer.RemoveAt(0);
                    continue;
                }

                // 3. Await complete network payload
                if (_buffer.Count < (int)totalFrameSize)
                {
                    break;
                }

                byte[] completeFrame = _buffer.GetRange(0, (int)totalFrameSize).ToArray();
                _buffer.RemoveRange(0, (int)totalFrameSize);

                // 4. Extract Record Type from the inner S7K header (Wrapper 36 + S7K Offset 32 = Byte 68)
                uint recType32 = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(68, 4));
                ushort foundRecType = (ushort)(recType32 & 0xFFFF);

                frames.Add((completeFrame, foundRecType));
            }

            return (frames, garbageSkipped);
        }
    }
}