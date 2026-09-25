$subnet = '172.30.1'
$commonPorts = 21, 22, 23, 25, 53, 80, 88, 135, 139, 443, 445, 3306, 3389, 5357, 5432, 5985, 8080

# ── 1) ARP 초기화 (관리자 권한 필요, 실패해도 무방) ──
arp -d * 2>$null

# ── 2) ARP 유도: 비동기 핑 254개 동시 발사 ──
Write-Host "ARP 유도 중..." -ForegroundColor Cyan
$tasks = 1..254 | ForEach-Object {
    (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$subnet.$_", 300)
}
[System.Threading.Tasks.Task]::WaitAll($tasks)   # 모든 핑 완료(또는 타임아웃)까지 대기
Start-Sleep -Milliseconds 200                     # 캐시 정착 여유

# ── 3) 살아있는 이웃 추출 (반드시 @()로 배열 강제) ──
$live = @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -like "$subnet.*" -and
        $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF'
    })
Write-Host ("살아있는 호스트 {0}대. 이름/포트 조회 시작...`n" -f $live.Count) -ForegroundColor Cyan

# 진단: 감지가 여전히 적으면 아래 주석을 풀어 전체 상태를 확인
# Get-NetNeighbor -AddressFamily IPv4 | Where-Object IPAddress -like "$subnet.*" |
#   Select IPAddress,LinkLayerAddress,State | Sort-Object {[version]$_.IPAddress} | Format-Table -AutoSize

# ── 4) 이름 조회 + 포트 스캔 병렬 실행 ──
$worker = {
    param($ip, $mac, $ports)
    $name = $null; $via = $null

    # 이름 조회
    try { $h = [System.Net.Dns]::GetHostEntry($ip); if ($h.HostName) { $name = $h.HostName; $via = 'DNS' } } catch {}
    if (-not $name) {
        $nb = nbtstat -A $ip 2>$null
        $line = $nb | Where-Object { $_ -match '<00>\s+UNIQUE\s+Registered' } | Select-Object -First 1
        if ($line) { $name = ($line -replace '\s*<00>.*$', '').Trim(); $via = 'NetBIOS' }
    }
    if (-not $name) {
        try {
            $r = Resolve-DnsName -Name $ip -LlmnrNetbiosOnly -ErrorAction Stop
            $hit = $r | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($hit) { $name = $hit.NameHost; $via = 'LLMNR' }
        }
        catch {}
    }

    # 포트 스캔
    $open = foreach ($p in $ports) {
        $c = New-Object Net.Sockets.TcpClient
        try {
            $async = $c.BeginConnect($ip, $p, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(250, $false) -and $c.Connected) {
                $c.EndConnect($async); $p
            }
        }
        catch {} finally { $c.Close() }
    }

    [PSCustomObject]@{
        IP = $ip; MAC = $mac
        Name = if ($name) { $name }else { '(확인 불가)' }
        Method = $via
        OpenPorts = if ($open) { ($open | Sort-Object) -join ',' } else { '-' }
    }
}

$pool = [runspacefactory]::CreateRunspacePool(1, 32); $pool.Open()
$jobs = foreach ($n in $live) {
    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript($worker).
    AddArgument($n.IPAddress).
    AddArgument($n.LinkLayerAddress).
    AddArgument($commonPorts)
    [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
}

# ── 5) 완료되는 대로 한 줄씩 출력 ──
$results = New-Object System.Collections.ArrayList
$pending = [System.Collections.ArrayList]@($jobs)
while ($pending.Count -gt 0) {
    for ($i = $pending.Count - 1; $i -ge 0; $i--) {
        if ($pending[$i].Handle.IsCompleted) {
            $r = $pending[$i].PS.EndInvoke($pending[$i].Handle) | Select-Object -First 1
            $pending[$i].PS.Dispose(); [void]$pending.RemoveAt($i); [void]$results.Add($r)
            if ($r.Method) {
                Write-Host ("[{0,-13}] {1,-18} 포트: {2}" -f $r.IP, $r.Name, $r.OpenPorts) -ForegroundColor Green
            }
            else {
                Write-Host ("[{0,-13}] {1,-18} 포트: {2}" -f $r.IP, '확인 불가', $r.OpenPorts) -ForegroundColor DarkGray
            }
        }
    }
    Start-Sleep -Milliseconds 30
}
$pool.Close(); $pool.Dispose()

Write-Host "`n=== 최종 결과 ===" -ForegroundColor Cyan
$results | Sort-Object { [version]($_.IP) } | Format-Table IP, Name, Method, OpenPorts, MAC -AutoSize