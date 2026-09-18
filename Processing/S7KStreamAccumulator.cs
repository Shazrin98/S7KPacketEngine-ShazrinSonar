using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ShazrinSonar.Processing
{
    public class S7KStreamAccumulator
    {
        private readonly List<byte> _buffer = new List<byte>();

        public void Clear() => _buffer.Clear();

        public (List<(byte[] Frame, ushort RecType)> Frames, int GarbageBytes) PushBytesAndExtractFrames(byte[] buffer, int bytesRead)
        {
            var frames = new List<(byte[] Frame, ushort RecType)>();
            if (buffer == null || bytesRead <= 0) return (frames, 0);

            for (int i = 0; i < bytesRead; i++)
            {
                _buffer.Add(buffer[i]);
            }

            // A valid Norbit Wrapper is exactly 36 bytes. We need at least that to read the size.
            while (_buffer.Count >= 36)
            {
                Span<byte> bufferSpan = CollectionsMarshal.AsSpan(_buffer);

                ushort wrapperVersion = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(0, 2));
                ushort headerSize = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(2, 2));

                // 1. Verify the universal Norbit Wrapper (0x05, size 0x24)
                if (wrapperVersion != 5 || headerSize != 36)
                {
                    _buffer.RemoveAt(0); // Slide 1 byte to re-sync
                    continue;
                }

                // 2. Extract Total Frame Size from the Wrapper (Bytes 12-15)
                uint totalFrameSize = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(12, 4));

                if (totalFrameSize < 36 || totalFrameSize > 2097152)
                {
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

                ushort foundRecType = 0;

                // 4. If the payload contains an S7K record, extract its ID for the router
                if (completeFrame.Length >= 72)
                {
                    uint s7kSyncPattern = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(40, 4));
                    if (s7kSyncPattern == 0x0000FFFF)
                    {
                        uint recType32 = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(68, 4));
                        foundRecType = (ushort)(recType32 & 0xFFFF);
                    }
                }

                frames.Add((completeFrame, foundRecType));
            }

            return (frames, 0);
        }
    }
}