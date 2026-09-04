# Use ' .\Test-ShazrinEngine.ps1 ' in powershell terminal to run output test of ShazrinSonar
# End-to-End Test Script with Socket Reuse and Reconnect Retry

$SourceIp   = "127.0.0.1"
$SourcePort = 7000   # Norbit Server Port
$TargetPort = 7001   # Qinsy Forwarder Port

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   SHAZRIN SONAR - STREAM & FORWARD TESTER        " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Start Norbit Server Simulator on Port 7000
$NorbitServerTask = [System.Threading.Tasks.Task]::Run([System.Action]{
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($SourceIp), $SourcePort)
        
        # Allow instant socket rebinding without waiting for OS TIME_WAIT cleanup
        $listener.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $listener.Start()
        
        Write-Host "[+] Norbit Simulator listening on TCP ${SourcePort}... Waiting for ShazrinSonar..." -ForegroundColor Green
        
        # Wait up to 10 seconds for ShazrinSonar to reconnect
        $timeoutCount = 0
        while (-not $listener.Pending() -and $timeoutCount -lt 50) {
            Start-Sleep -Milliseconds 200
            $timeoutCount++
        }

        if (-not $listener.Pending()) {
            Write-Host "[!] Timeout: ShazrinSonar did not connect to port ${SourcePort} within 10 seconds." -ForegroundColor Red
            $listener.Stop()
            return
        }
        
        $client = $listener.AcceptTcpClient()
        Write-Host "[!] ShazrinSonar connected to Norbit Simulator on Port ${SourcePort}!" -ForegroundColor Yellow
        $stream = $client.GetStream()

        # Construct synthetic 13,515 byte Bathymetry (7027) frame
        $frame = New-Object byte[] 13515
        [BitConverter]::GetBytes([ushort]7027).CopyTo($frame, 12) # Record Type 7027
        [BitConverter]::GetBytes([uint32]5001).CopyTo($frame, 64) # Ping # 5001
        [BitConverter]::GetBytes([uint32]256).CopyTo($frame, 72)  # 256 Beams

        for ($i = 1; $i -le 10; $i++) {
            $stream.Write($frame, 0, $frame.Length)
            $stream.Flush()
            Write-Host " -> Injected Frame $i (13,515 bytes) to Ingestor" -ForegroundColor Gray
            Start-Sleep -Milliseconds 200
        }

        Start-Sleep -Seconds 1
        $client.Close()
        $listener.Stop()
        Write-Host "[+] Norbit injection finished cleanly." -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Norbit Simulator Error: $($_.Exception.Message)" -ForegroundColor Red
    }
})

# Give the Norbit server time to bind
Start-Sleep -Seconds 1

# 2. Connect Qinsy Receiver Client to ShazrinSonar Forwarder on Port 7001
try {
    Write-Host "[+] Connecting Qinsy Receiver to ShazrinSonar (${SourceIp}:${TargetPort})..." -ForegroundColor Cyan
    $qinsyClient = New-Object System.Net.Sockets.TcpClient
    
    # Allow socket reuse on the receiver client
    $qinsyClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $qinsyClient.Connect($SourceIp, $TargetPort)
    Write-Host "[!] Connected to ShazrinSonar Forwarder on Port ${TargetPort}!" -ForegroundColor Yellow

    $stream = $qinsyClient.GetStream()
    $buffer = New-Object byte[] 16384
    $qinsyClient.ReceiveTimeout = 4000

    $totalReceived = 0
    try {
        while ($qinsyClient.Connected) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -eq 0) { break }
            $totalReceived += $bytesRead
            Write-Host "[SUCCESS] Qinsy Receiver got $bytesRead bytes (Total: $totalReceived bytes)" -ForegroundColor Green
        }
    }
    catch {
        # Read timeout after injection completes
    }

    $qinsyClient.Close()
    Write-Host "[+] Qinsy Receiver session finished. Total received: $totalReceived bytes" -ForegroundColor Cyan
}
catch {
    Write-Host "[!] Could not connect to Qinsy Forwarder on port ${TargetPort}. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Await background task safely
if ($null -ne $NorbitServerTask) {
    try {
        [System.Threading.Tasks.Task]::WaitAll($NorbitServerTask)
    }
    catch {
        Write-Host "[!] Task Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
}