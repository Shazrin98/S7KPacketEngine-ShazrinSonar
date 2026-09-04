using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace ShazrinSonar.Processing
{
    public class S7KStreamAccumulator
    {
        private readonly MemoryStream _stream = new MemoryStream();

        public void Clear()
        {
            _stream.SetLength(0);
            _stream.Position = 0;
        }

        public List<(byte[] Frame, ushort RecType)> PushBytesAndExtractFrames(byte[] buffer, int bytesRead)
        {
            var frames = new List<(byte[] Frame, ushort RecType)>();

            _stream.Write(buffer, 0, bytesRead);
            _stream.Position = 0;

            Span<byte> headerBuffer = stackalloc byte[64];

            while (_stream.Length - _stream.Position >= 64)
            {
                long frameStartPos = _stream.Position;
                headerBuffer.Clear();

                int read = _stream.Read(headerBuffer);
                if (read < 64)
                {
                    _stream.Position = frameStartPos;
                    break;
                }

                ushort syncVerLE = BinaryPrimitives.ReadUInt16LittleEndian(headerBuffer.Slice(0, 2));
                ushort syncVerBE = BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.Slice(0, 2));

                if (syncVerLE != 1 && syncVerBE != 1)
                {
                    _stream.Position = frameStartPos + 1;
                    continue;
                }

                uint frameSizeBE = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.Slice(8, 4));
                uint frameSizeLE = BinaryPrimitives.ReadUInt32LittleEndian(headerBuffer.Slice(8, 4));
                uint frameSize = (frameSizeBE >= 64 && frameSizeBE <= 2097152) ? frameSizeBE : frameSizeLE;

                if (frameSize < 64 || frameSize > 2097152)
                {
                    _stream.Position = frameStartPos + 1;
                    continue;
                }

                if (_stream.Length - frameStartPos < frameSize)
                {
                    _stream.Position = frameStartPos;
                    break;
                }

                _stream.Position = frameStartPos;
                byte[] completeFrame = new byte[frameSize];
                _stream.Read(completeFrame, 0, (int)frameSize);

                ushort foundRecType = 0;
                int maxScan = (int)Math.Min(frameSize - 2, 96);

                for (int offset = 32; offset <= maxScan; offset += 2)
                {
                    ushort valLE = BinaryPrimitives.ReadUInt16LittleEndian(completeFrame.AsSpan(offset, 2));
                    ushort valBE = BinaryPrimitives.ReadUInt16BigEndian(completeFrame.AsSpan(offset, 2));

                    if (valLE == 7027 || valLE == 7006 || valLE == 7004 || valLE == 7000 ||
                        valLE == 1012 || valLE == 1013 || valLE == 1015 || valLE == 1016)
                    {
                        foundRecType = valLE;
                        break;
                    }
                    if (valBE == 7027 || valBE == 7006 || valBE == 7004 || valBE == 7000 ||
                        valBE == 1012 || valBE == 1013 || valBE == 1015 || valBE == 1016)
                    {
                        foundRecType = valBE;
                        break;
                    }
                }

                // Match original classification priority logic
                if (foundRecType == 7027 || foundRecType == 7006 || foundRecType == 7004 || frameSize == 13515)
                {
                    foundRecType = (foundRecType == 0) ? (ushort)7027 : foundRecType;
                }
                else if (foundRecType == 1012 || foundRecType == 1013 || foundRecType == 1015 || foundRecType == 1016 || frameSize == 260)
                {
                    foundRecType = (foundRecType == 0) ? (ushort)1012 : foundRecType;
                }
                else
                {
                    foundRecType = (foundRecType == 0) ? (ushort)7000 : foundRecType;
                }

                frames.Add((completeFrame, foundRecType));
            }

            int remainingBytes = (int)(_stream.Length - _stream.Position);
            if (remainingBytes > 0)
            {
                byte[] internalBuffer = _stream.GetBuffer();
                Buffer.BlockCopy(internalBuffer, (int)_stream.Position, internalBuffer, 0, remainingBytes);
                streamSetLengthAndPos(remainingBytes);
            }
            else
            {
                streamSetLengthAndPos(0);
            }

            return frames;
        }

        private void streamSetLengthAndPos(int length)
        {
            _stream.SetLength(length);
            _stream.Position = length;
        }
    }
}