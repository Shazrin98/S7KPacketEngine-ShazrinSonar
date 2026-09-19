using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ShazrinSonar.Processing
{
    /// <summary>
    /// Accumulates raw heterogeneous TCP byte streams from Norbit hardware.
    /// Extracts S7K bathymetry records for modification while LOSSLESSLY forwarding 
    /// all unrecognized data (Applanix IMU, Timetags, NMEA) to prevent Qinsy disconnects.
    /// </summary>
    public class S7KStreamAccumulator
    {
        private readonly List<byte> _buffer = new List<byte>();

        public void Clear() => _buffer.Clear();

        public (List<(byte[] Frame, ushort RecType)> Frames, int GarbageBytes) PushBytesAndExtractFrames(byte[] buffer, int bytesRead)
        {
            var frames = new List<(byte[] Frame, ushort RecType)>();
            if (buffer == null || bytesRead <= 0) return (frames, 0);

            // Append incoming TCP chunk to our continuous buffer
            for (int i = 0; i < bytesRead; i++)
            {
                _buffer.Add(buffer[i]);
            }

            while (_buffer.Count > 0)
            {
                // --- SCENARIO A: WE HAVE A VALID NORBIT WRAPPED PACKET ---
                // We need at least 36 bytes to read the full Norbit Wrapper header.
                if (_buffer.Count >= 36)
                {
                    Span<byte> span = CollectionsMarshal.AsSpan(_buffer);
                    ushort ver = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(0, 2));
                    ushort size = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2, 2));

                    // Check for standard Norbit Wrapper (Version 5, Header Size 36)
                    if (ver == 5 && size == 36)
                    {
                        uint totalSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(12, 4));
                        
                        // Sanity check total size to prevent memory leaks from corrupted length values
                        if (totalSize >= 36 && totalSize <= 2097152)
                        {
                            // If we don't have the full packet yet, break and wait for next TCP read
                            if (_buffer.Count < totalSize) break; 
                            
                            // Extract the complete, unbroken packet
                            byte[] frame = _buffer.GetRange(0, (int)totalSize).ToArray();
                            _buffer.RemoveRange(0, (int)totalSize);
                            
                            ushort recType = 0;
                            
                            // If the payload inside the wrapper is an S7K record (starts at offset 36), 
                            // check its S7K Sync Pattern (0x0000FFFF at overall offset 40)
                            if (frame.Length >= 72 && BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(40, 4)) == 0x0000FFFF)
                            {
                                // Extract S7K Record Type (overall offset 68) for the math engine to route
                                recType = (ushort)(BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(68, 4)) & 0xFFFF);
                            }
                            
                            frames.Add((frame, recType));
                            continue; // Loop again to process the next packet
                        }
                    }
                }

                // --- SCENARIO B: UNRECOGNIZED DATA (LOSSLESS PASS-THROUGH) ---
                // We reached here because the data does NOT start with a Norbit Wrapper.
                // This is likely Applanix POS MV data, PPS time tags, or naked serial strings.
                // WE MUST NOT DELETE IT. We must package it and pass it through to Qinsy.
                
                int nextWrapperIndex = -1;
                Span<byte> searchSpan = CollectionsMarshal.AsSpan(_buffer);
                
                // Scan ahead to find where the NEXT valid Norbit Wrapper starts
                for (int i = 1; i <= _buffer.Count - 36; i++)
                {
                    if (BinaryPrimitives.ReadUInt16LittleEndian(searchSpan.Slice(i, 2)) == 5 &&
                        BinaryPrimitives.ReadUInt16LittleEndian(searchSpan.Slice(i + 2, 2)) == 36)
                    {
                        nextWrapperIndex = i;
                        break;
                    }
                }

                if (nextWrapperIndex > 0)
                {
                    // We found a wrapper further down the buffer. 
                    // Package everything BEFORE that wrapper as a raw chunk.
                    byte[] rawChunk = _buffer.GetRange(0, nextWrapperIndex).ToArray();
                    _buffer.RemoveRange(0, nextWrapperIndex);
                    
                    // RecType 0 tells the S7KFrameProcessor to ignore it and pass it straight to Qinsy
                    frames.Add((rawChunk, 0)); 
                }
                else
                {
                    // We scanned the whole buffer and found no wrappers.
                    // Forward everything EXCEPT the last 35 bytes to Qinsy.
                    // (We hold 35 bytes back just in case a valid 36-byte wrapper got cut in half by TCP).
                    int safeForwardBytes = _buffer.Count - 35;
                    if (safeForwardBytes > 0)
                    {
                        byte[] rawChunk = _buffer.GetRange(0, safeForwardBytes).ToArray();
                        _buffer.RemoveRange(0, safeForwardBytes);
                        frames.Add((rawChunk, 0));
                    }
                    
                    break; // Break and wait for more data from the network
                }
            }

            // Return extracted frames with 0 GarbageBytes (100% data retention achieved)
            return (frames, 0); 
        }
    }
}