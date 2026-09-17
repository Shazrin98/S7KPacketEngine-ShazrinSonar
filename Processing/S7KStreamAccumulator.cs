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

            while (_buffer.Count > 0)
            {
                // We need at least 44 bytes to safely check the Wrapper (Byte 0) and S7K Sync Pattern (Byte 40)
                if (_buffer.Count < 44) break;

                Span<byte> bufferSpan = CollectionsMarshal.AsSpan(_buffer);
                ushort wrapperVersion = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(0, 2));
                uint s7kSyncPattern = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(40, 4));

                // 1. Is it a valid wrapped S7K record?
                if (wrapperVersion == 5 && s7kSyncPattern == 0x0000FFFF)
                {
                    uint totalFrameSize = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(12, 4));

                    if (totalFrameSize < 100 || totalFrameSize > 2097152)
                    {
                        // Corrupted size. Force 1 byte into Pass-Through to re-sync.
                        byte[] singleByte = new byte[] { _buffer[0] };
                        _buffer.RemoveAt(0);
                        frames.Add((singleByte, 0));
                        continue;
                    }

                    if (_buffer.Count < (int)totalFrameSize) break; // Wait for full frame

                    byte[] completeFrame = _buffer.GetRange(0, (int)totalFrameSize).ToArray();
                    _buffer.RemoveRange(0, (int)totalFrameSize);

                    uint recType32 = BinaryPrimitives.ReadUInt32LittleEndian(completeFrame.AsSpan(68, 4));
                    ushort foundRecType = (ushort)(recType32 & 0xFFFF);

                    frames.Add((completeFrame, foundRecType));
                }
                else
                {
                    // 2. LOSSLESS PASS-THROUGH (Applanix, Timetags, etc.)
                    // Scan ahead to find the NEXT valid S7K header so we can chunk this data cleanly.
                    int nextHeaderIndex = -1;
                    for (int i = 1; i <= _buffer.Count - 44; i++)
                    {
                        ushort nextVer = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(i, 2));
                        uint nextSync = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(i + 40, 4));
                        
                        if (nextVer == 5 && nextSync == 0x0000FFFF)
                        {
                            nextHeaderIndex = i;
                            break;
                        }
                    }

                    if (nextHeaderIndex > 0)
                    {
                        // Package everything before the next S7K header and pass it through
                        byte[] passThroughChunk = _buffer.GetRange(0, nextHeaderIndex).ToArray();
                        _buffer.RemoveRange(0, nextHeaderIndex);
                        frames.Add((passThroughChunk, 0));
                    }
                    else
                    {
                        // No S7K header found. Pass through all but the last 43 bytes (to avoid splitting an incoming header).
                        int safeToForward = _buffer.Count - 43;
                        if (safeToForward > 0)
                        {
                            byte[] passThroughChunk = _buffer.GetRange(0, safeToForward).ToArray();
                            _buffer.RemoveRange(0, safeToForward);
                            frames.Add((passThroughChunk, 0));
                        }
                        break;
                    }
                }
            }

            return (frames, 0); // 0 bytes dropped. 100% data retention.
        }
    }
}