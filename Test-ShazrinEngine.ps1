param (
    [string]$HostIp = "127.0.0.1",
    [int]$IngestPort = 7000,
    [int]$ForwardPort = 7001,
    [double]$ExpectedDraft = 0.85,
    [double]$ExpectedTide = -0.15,
    [double]$SoundVelocity = 1500.0,
    [int]$TwttByteOffset = 96  # recordData (64) + twttArrayOffset (32) = 96
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   SHAZRIN SONAR - AUTOMATED MATH ASSERTION TEST   " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Connect Client to Forwarder Receiver (Port 7001)
$forwardClient = New-Object System.Net.Sockets.TcpClient
try {
    $forwardClient.Connect($HostIp, $ForwardPort)
    $rxStream = $forwardClient.GetStream()
    Write-Host "[+] Connected to ShazrinSonar Forwarder on port $ForwardPort." -ForegroundColor Green
} catch {
    Write-Host "[!] ERROR: Could not connect to forwarder port $ForwardPort. Ensure engine is running." -ForegroundColor Red
    exit
}

# 2. Construct Structured S7K Record 7027 Frame (256 bytes)
$frameLength = 256
$rawFrame = New-Object byte[] $frameLength

# --- S7K FRAME HEADER ---
# Protocol Version = 1 (ushort LE at bytes 0-1)
$versionBytes = [System.BitConverter]::GetBytes([uint16]1)
[System.Array]::Copy($versionBytes, 0, $rawFrame, 0, 2)

# Total Frame Length at byte offset 8 (uint32 LE)
$lengthBytes = [System.BitConverter]::GetBytes([uint32]$frameLength)
[System.Array]::Copy($lengthBytes, 0, $rawFrame, 8, 4)

# Record Type 7027 at byte offset 32 (uint32 LE)
$recTypeBytes = [System.BitConverter]::GetBytes([uint32]7027)
[System.Array]::Copy($recTypeBytes, 0, $rawFrame, 32, 4)

# --- RECORD 7027 DATA HEADER (starts at byte offset 64) ---
# Ping Number = 1 at recordData[0..3] (frame byte 64)
$pingBytes = [System.BitConverter]::GetBytes([uint32]1)
[System.Array]::Copy($pingBytes, 0, $rawFrame, 64, 4)

# NumBeams = 1 at recordData[8..11] (frame byte 72)
$numBeamsBytes = [System.BitConverter]::GetBytes([uint16]1)
[System.Array]::Copy($numBeamsBytes, 0, $rawFrame, 72, 2)

# --- BEAM DATA ARRAYS ---
# 1. TWTT Array at recordData + 32 = Frame Offset 96
$rawTwtt = [single]0.0100
$rawTwttBytes = [System.BitConverter]::GetBytes($rawTwtt)
[System.Array]::Copy($rawTwttBytes, 0, $rawFrame, $TwttByteOffset, 4)

# 2. Quality Array at recordData + 36 = Frame Offset 100
$qualityBytes = [System.BitConverter]::GetBytes([uint32]::MaxValue)
[System.Array]::Copy($qualityBytes, 0, $rawFrame, 100, 4)

# 3. Beam Angle Array at recordData + 40 = Frame Offset 104 (0.0 radians)
$angleBytes = [System.BitConverter]::GetBytes([single]0.0)
[System.Array]::Copy($angleBytes, 0, $rawFrame, 104, 4)

# Checksum at end of frame (Safe PowerShell uint32 cast)
$checksumValue = [uint32][int64]0xABCD1234
$checksumBytes = [System.BitConverter]::GetBytes($checksumValue)
[System.Array]::Copy($checksumBytes, 0, $rawFrame, ($frameLength - 4), 4)

# Calculate Expected Modified TWTT and Depth
$rawDepth = ($rawTwtt * $SoundVelocity) / 2.0
$expectedDepth = $rawDepth + $ExpectedDraft + $ExpectedTide
$expectedTwtt = ($expectedDepth * 2.0) / $SoundVelocity

$msgRawTwtt = "{0:F6}" -f $rawTwtt
$msgRawDepth = "{0:F2}" -f $rawDepth
$msgDraft = "{0:F2}" -f $ExpectedDraft
$msgTide = "{0:F2}" -f $ExpectedTide
$msgExpDepth = "{0:F2}" -f $expectedDepth
$msgExpTwtt = "{0:F6}" -f $expectedTwtt

Write-Host "[+] Test Input Injecting:" -ForegroundColor Yellow
Write-Host "    |-- Target Offset  : Byte $TwttByteOffset"
Write-Host "    |-- Raw TWTT       : $msgRawTwtt s ($msgRawDepth m)"
Write-Host "    |-- Applied Draft  : +$msgDraft m"
Write-Host "    |-- Applied Tide   : $msgTide m"
Write-Host "    \-- Expected Depth : $msgExpDepth m (Expected TWTT: $msgExpTwtt s)"

# 3. Inject Packet into Ingestor (Port 7000)
try {
    $ingestClient = New-Object System.Net.Sockets.TcpClient
    $ingestClient.Connect($HostIp, $IngestPort)
    $txStream = $ingestClient.GetStream()
    $txStream.Write($rawFrame, 0, $rawFrame.Length)
    $txStream.Flush()
    Write-Host "[+] Successfully injected mock Record 7027 packet into port $IngestPort." -ForegroundColor Green
    $ingestClient.Close()
} catch {
    Write-Host "[!] ERROR: Failed to inject packet into port $IngestPort." -ForegroundColor Red
    $forwardClient.Close()
    exit
}

# 4. Read Response from Forwarder Stream (Port 7001)
$rxBuffer = New-Object byte[] 2048
$rxStream.ReadTimeout = 3000

try {
    $bytesRead = $rxStream.Read($rxBuffer, 0, $rxBuffer.Length)
} catch {
    $bytesRead = 0
}
$forwardClient.Close()

if ($bytesRead -gt 0) {
    $modifiedTwtt = [System.BitConverter]::ToSingle($rxBuffer, $TwttByteOffset)
    $calculatedDepth = ($modifiedTwtt * $SoundVelocity) / 2.0

    $msgOutTwtt = "{0:F6}" -f $modifiedTwtt
    $msgOutDepth = "{0:F2}" -f $calculatedDepth

    Write-Host "`n--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[+] RECEIVED MODIFIED FRAME FROM ENGINE" -ForegroundColor Cyan
    Write-Host "    |-- Output TWTT    : $msgOutTwtt s"
    Write-Host "    \-- Output Depth   : $msgOutDepth m"
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan

    $delta = [System.Math]::Abs($calculatedDepth - $expectedDepth)
    if ($delta -lt 0.001) {
        Write-Host "[PASS] MATH ASSERTION SUCCESSFUL: Depth output matches mathematical model perfectly!" -ForegroundColor Green
    } else {
        $msgExpF3 = "{0:F3}" -f $expectedDepth
        $msgCalcF3 = "{0:F3}" -f $calculatedDepth
        $msgDeltaF4 = "{0:F4}" -f $delta
        Write-Host "[FAIL] MATH ASSERTION ERROR: Expected $msgExpF3 m but calculated $msgCalcF3 m (Delta: $msgDeltaF4 m)" -ForegroundColor Red
    }
} else {
    Write-Host "[!] ERROR: No data received on forwarder port 7001." -ForegroundColor Red
}