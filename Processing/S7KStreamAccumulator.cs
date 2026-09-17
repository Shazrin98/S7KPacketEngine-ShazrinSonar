using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ShazrinSonar.Processing
{
    public class S7KStreamAccumulator
    {
        private readonly List<byte> _buffer = new List<byte>();
        private int _consecutiveDropCount = 0;
        
        // NECESSARY CHANGE: Replaced SafeLog with a delegate so we can log to UI without locking the disk
        private readonly Action<string>? _diagnosticLogger;

        public S7KStreamAccumulator(Action<string>? diagnosticLogger = null)
        {
            _diagnosticLogger = diagnosticLogger;
        }

        public void Clear()
        {
            _buffer.Clear();
            _consecutiveDropCount = 0;
        }

        // NECESSARY CHANGE: Return type updated to a Tuple to pass GarbageBytes up to the dashboard
        public (List<(byte[] Frame, ushort RecType)> Frames, int GarbageBytes) PushBytesAndExtractFrames(byte[] buffer, int bytesRead)
        {
            var frames = new List<(byte[] Frame, ushort RecType)>();
            if (buffer == null || bytesRead <= 0) return (frames, 0);

            int garbageSkipped = 0;

            for (int i = 0; i < bytesRead; i++)
            {
                _buffer.Add(buffer[i]);
            }

            while (_buffer.Count >= 64)
            {
                Span<byte> bufferSpan = CollectionsMarshal.AsSpan(_buffer);

                // 1. Verify S7K Protocol Version (Bytes 0-1)
                ushort syncVerLE = BinaryPrimitives.ReadUInt16LittleEndian(bufferSpan.Slice(0, 2));
                ushort syncVerBE = BinaryPrimitives.ReadUInt16BigEndian(bufferSpan.Slice(0, 2));
                
                // 2. CRITICAL FIX: Verify the S7K Sync Pattern (Bytes 4-7). Must equal 0x0000FFFF (65535)
                uint syncPattern = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(4, 4));

                // If it doesn't have BOTH the version and the exact sync pattern, it's not a real header.
                if ((syncVerLE != 1 && syncVerBE != 1) || syncPattern != 0x0000FFFF)
                {
                    _consecutiveDropCount++;
                    garbageSkipped++;
                    _buffer.RemoveAt(0); // Shift 1 byte and search again
                    continue;
                }

                if (_consecutiveDropCount > 0)
                {
                    _diagnosticLogger?.Invoke($"[DROP] Resynchronized S7K header after dropping {_consecutiveDropCount} unaligned byte(s).");
                    _consecutiveDropCount = 0;
                }

                // 3. Extract Frame Size (Bytes 8-11)
                uint frameSizeBE = BinaryPrimitives.ReadUInt32BigEndian(bufferSpan.Slice(8, 4));
                uint frameSizeLE = BinaryPrimitives.ReadUInt32LittleEndian(bufferSpan.Slice(8, 4));
                uint frameSize = (frameSizeBE >= 64 && frameSizeBE <= 2097152) ? frameSizeBE : frameSizeLE;

                if (frameSize < 64 || frameSize > 2097152)
                {
                    _diagnosticLogger?.Invoke($"[DROP] Invalid FrameSize: {frameSize}. Resynchronizing...");
                    garbageSkipped++;
                    _buffer.RemoveAt(0);
                    continue;
                }

                // 4. Await complete frame payload before slicing
                if (_buffer.Count < (int)frameSize)
                {
                    break;
                }

                byte[] completeFrame = _buffer.GetRange(0, (int)frameSize).ToArray();
                _buffer.RemoveRange(0, (int)frameSize);

                ushort foundRecType = ExtractRecordType(completeFrame);

                frames.Add((completeFrame, foundRecType));
            }

            return (frames, garbageSkipped);
        }

        // EXACT OLD CODE LOGIC RESTORED
        private ushort ExtractRecordType(byte[] frame)
        {
            if (frame == null || frame.Length < 24) return 0;

            // Check Offset 32 (Standard S7K Data Record Frame Header)
            if (frame.Length >= 36)
            {
                uint rec32LE = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(32, 4));
                ushort rec16LE = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(32, 2));

                if (IsKnownRecordType(rec32LE)) return (ushort)rec32LE;
                if (IsKnownRecordType(rec16LE)) return rec16LE;
            }

            // Check Offset 20 (7K Network Frame Header)
            if (frame.Length >= 24)
            {
                uint rec20LE = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(20, 4));
                ushort rec20_16 = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(20, 2));

                if (IsKnownRecordType(rec20LE)) return (ushort)rec20LE;
                if (IsKnownRecordType(rec20_16)) return rec20_16;
            }

            // Check Offset 24
            if (frame.Length >= 28)
            {
                uint rec24LE = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(24, 4));
                if (IsKnownRecordType(rec24LE)) return (ushort)rec24LE;
            }

            // Fallback classification for Record 7027 by frame size
            if (frame.Length == 13515)
            {
                return 7027;
            }

            // Default fallback if not matched by standard rules
            if (frame.Length >= 36)
            {
                uint rec32LE = BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(32, 4));
                return (ushort)(rec32LE & 0xFFFF);
            }

            return 0;
        }

        // EXACT OLD CODE LOGIC RESTORED
        private bool IsKnownRecordType(uint id)
        {
            return id == 7027 || id == 1012 || id == 1013 || id == 7000 || 
                   id == 7004 || id == 7006 || id == 7050 || id == 7503 || 
                   (id >= 1000 && id <= 9999);
        }
    }
}