<#
    네트워크 스캐너 - 어댑터 선택형
    - 연결된 네트워크 어댑터와 각 IPv4 대역을 어댑터별로 그룹화하여 표시
    - 방향키(↑/↓)로 스캔할 대역을 선택 (Enter 확정, Esc 취소)
    - 선택한 대역의 실제 PrefixLength 기준으로 전체 호스트 대역을 스캔
    - 이름 조회는 Resolve-DnsName으로 통일 (DNS → LLMNR → NetBIOS 순, 프로토콜별 분리)
    - ARP 유도를 3회차 반복하고 결과를 합집합하여 감지 안정성 확보
    주의: 관리자 권한이 필요하며, 부족하면 승격된 창으로 자동 재실행됩니다.
          방향키 UI는 실제 콘솔(Windows Terminal, conhost, pwsh)에서 동작합니다.
          PowerShell ISE에서는 번호 입력 방식으로 자동 전환됩니다.
#>

$tcpPorts = 20, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 119, 135, 139, 143, 179, 194, 389, 443, 445, 465, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 4369, 4444, 5000, 5060, 5061, 5222, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 8000, 8009, 8080, 8081, 8086, 8088, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999
# $udpPorts = 53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 546, 547, 1194, 2049, 5060

# -- 0) 관리자 권한 확인 및 승격 --
# arp -d * 가 매 실행마다 동일하게 성공해야 결과 재현성이 보장되므로 관리자 권한을 강제합니다.
function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host '이 스크립트는 관리자 권한이 필요합니다.' -ForegroundColor Red
        Write-Host '콘솔에 직접 붙여넣은 경우 자동 승격이 불가하므로, 관리자 권한 PowerShell에서 다시 실행하십시오.' -ForegroundColor Yellow
        return
    }

    Write-Host '관리자 권한이 필요합니다. 승격된 창으로 다시 실행합니다...' -ForegroundColor Yellow
    $exe = (Get-Process -Id $PID).Path       # powershell.exe 또는 pwsh.exe
    $startArgs = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    try {
        Start-Process -FilePath $exe -Verb RunAs -ArgumentList $startArgs -ErrorAction Stop
    }
    catch {
        Write-Host '권한 승격이 취소되었거나 실패했습니다.' -ForegroundColor Red
    }
    return
}

# -- 스피너 상태 갱신 --
function Set-SpinnerStatus {
    <# 스피너 오른쪽에 표시되는 부가 문구를 갱신합니다. #>
    param(
        [Parameter(Mandatory)][hashtable] $State,
        [Parameter(Mandatory)][string]    $Status
    )
    $State.Status = $Status
}

# -- 스피너 관련 유틸 --
function Set-SpinnerDetail {
    <# 스피너 바로 아래 줄을 제자리에서 갱신합니다(줄바꿈 없음). #>
    param(
        [Parameter(Mandatory)][hashtable] $State,
        [string]                          $Text = '',
        [System.ConsoleColor]             $Color = 'DarkGray'
    )
    $State.Detail = $Text
    $State.DetailColor = $Color
}

# -- 스피너 한 줄 출력 --
function Write-SpinnerLine {
    <# 스피너 영역 위쪽에 영구적인 한 줄을 남기고 영역을 아래로 재배치합니다. #>
    param(
        [Parameter(Mandatory)][hashtable] $State,
        [Parameter(Mandatory)][string]    $Text,
        [System.ConsoleColor]             $Color = 'DarkGray'
    )
    [System.Threading.Monitor]::Enter($State.Lock)
    try {
        [Console]::SetCursorPosition(0, $State.Top)
        [Console]::Write(' ' * $State.LastLen)
        [Console]::SetCursorPosition(0, $State.Top + 1)
        [Console]::Write(' ' * $State.LastDetailLen)

        [Console]::SetCursorPosition(0, $State.Top)
        $prev = [Console]::ForegroundColor
        [Console]::ForegroundColor = $Color
        [Console]::WriteLine($Text)
        [Console]::ForegroundColor = $prev

        [Console]::Write("`n")                      # 상세 줄 자리 재확보
        $State.Top = [Console]::CursorTop - 1
        $State.LastLen = 0
        $State.LastDetailLen = 0
    }
    finally { [System.Threading.Monitor]::Exit($State.Lock) }
}

# -- 스피너 실행 --
function Invoke-WithSpinner {
    param(
        [Parameter(Mandatory)][scriptblock] $Work,
        [string]                            $Message = 'Working...',
        [System.ConsoleColor]               $Color = 'Cyan',
        [int]                               $IntervalMs = 100,
        [string]                            $SpinnerPos = 'Left'
    )

    $state = [hashtable]::Synchronized(@{
            Running       = $true
            Message       = $Message
            SpinnerPos    = $SpinnerPos
            Status        = ''
            Detail        = ''
            Color         = $Color
            DetailColor   = [System.ConsoleColor]::DarkGray
            Top           = 0
            LastLen       = 0
            LastDetailLen = 0
            Lock          = New-Object object
        })

    $renderLoop = {
        param($State, $IntervalMs)

        function Write-Region {
            param($State, [int]$Row, [string]$Text, $Color, [string]$LenKey)
            $max = [Console]::BufferWidth - 1
            if ($Text.Length -gt $max) { $Text = $Text.Substring(0, $max) }
            $pad = [math]::Max(0, $State[$LenKey] - $Text.Length)

            [Console]::SetCursorPosition(0, $Row)
            $prev = [Console]::ForegroundColor
            [Console]::ForegroundColor = $Color
            [Console]::Write($Text + (' ' * $pad))
            [Console]::ForegroundColor = $prev
            $State[$LenKey] = $Text.Length
        }

        $frames = '/', '-', '\', '|'
        $i = 0

        while ($State.Running) {
            [System.Threading.Monitor]::Enter($State.Lock)
            try {
                if ($State.Top + 1 -lt [Console]::BufferHeight) {
                    if ($State.SpinnerPos -eq 'Right') {
                        $line = "$($State.Message) $($frames[$i % $frames.Length])"
                    }
                    else {
                        # Left or default position
                        $line = "$($frames[$i % $frames.Length]) $($State.Message)"
                    }
                    if ($State.Status) { $line += "  $($State.Status)" }

                    Write-Region $State  $State.Top        $line          $State.Color       'LastLen'
                    Write-Region $State ($State.Top + 1)  $State.Detail   $State.DetailColor 'LastDetailLen'
                    [Console]::SetCursorPosition(0, $State.Top)
                }
            }
            catch { }
            finally { [System.Threading.Monitor]::Exit($State.Lock) }

            $i++
            Start-Sleep -Milliseconds $IntervalMs
        }
    }

    [Console]::Write("`n")                          # 상세 줄 자리 확보
    $state.Top = [Console]::CursorTop - 1

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()

    $shell = [powershell]::Create()
    $shell.Runspace = $runspace
    [void]$shell.AddScript($renderLoop).AddArgument($state).AddArgument($IntervalMs)
    $handle = $shell.BeginInvoke()

    try {
        [Console]::CursorVisible = $false
        & $Work $state
    }
    finally {
        $state.Running = $false
        try { $shell.EndInvoke($handle) } catch { }
        $shell.Dispose()
        $runspace.Dispose()

        [Console]::SetCursorPosition(0, $state.Top)
        [Console]::Write(' ' * $state.LastLen)
        [Console]::SetCursorPosition(0, $state.Top + 1)
        [Console]::Write(' ' * $state.LastDetailLen)
        [Console]::SetCursorPosition(0, $state.Top)
        [Console]::CursorVisible = $true
    }
}

# -- IP <-> 정수 변환 유틸 --
# 주의: Windows PowerShell 5.1은 0xFFFFFFFF를 Int32(-1)로 해석하므로
#       16진 리터럴 대신 10진 상수를 사용합니다.
$script:UINT32_MAX = [uint64]4294967295

function ConvertTo-IPUInt {
    param([Parameter(Mandatory)][string] $IPAddress)
    $bytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
    [Array]::Reverse($bytes)
    [uint64]([System.BitConverter]::ToUInt32($bytes, 0))
}

function ConvertFrom-IPUInt {
    param([Parameter(Mandatory)][uint64] $Value)
    $u = [uint32]($Value -band $script:UINT32_MAX)
    $bytes = [System.BitConverter]::GetBytes($u)
    [Array]::Reverse($bytes)
    ([System.Net.IPAddress]::new($bytes)).ToString()
}

# -- PrefixLength 기반 대역(네트워크/브로드캐스트/호스트 범위) 계산 --
function Get-ScanRange {
    param(
        [Parameter(Mandatory)][string] $IPAddress,
        [Parameter(Mandatory)][int]    $PrefixLength
    )
    $ipUint = ConvertTo-IPUInt $IPAddress
    $hostBits = 32 - $PrefixLength
    $hostMask = [uint64]([math]::Pow(2, $hostBits) - 1)
    $maskUint = $script:UINT32_MAX - $hostMask

    $network = [uint64]($ipUint -band $maskUint)
    $broadcast = [uint64]($network + $hostMask)

    if ($PrefixLength -ge 31) {
        $first = $network
        $last = $broadcast
    }
    else {
        $first = [uint64]($network + 1)
        $last = [uint64]($broadcast - 1)
    }

    [PSCustomObject]@{
        Network      = ConvertFrom-IPUInt $network
        Broadcast    = ConvertFrom-IPUInt $broadcast
        FirstHost    = $first
        LastHost     = $last
        HostCount    = [uint64]($last - $first + 1)
        PrefixLength = $PrefixLength
    }
}

# -- 방향키 메뉴 (헤더는 건너뛰고 선택 가능한 항목만 순회) --
function Read-MenuSelection {
    param(
        [Parameter(Mandatory)] $Items,
        [string] $Title = '스캔할 대역을 선택하세요  (↑/↓ 이동, Enter 선택, Esc 취소)'
    )

    $selectable = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        if (-not $Items[$i].IsHeader) { $selectable += $i }
    }
    if ($selectable.Count -eq 0) { return $null }

    $cursor = 0
    $prevVisible = [System.Console]::CursorVisible
    [System.Console]::CursorVisible = $false
    try {
        while ($true) {
            Clear-Host
            Write-Host $Title -ForegroundColor Cyan
            Write-Host ''
            for ($i = 0; $i -lt $Items.Count; $i++) {
                $item = $Items[$i]
                if ($item.IsHeader) {
                    Write-Host $item.Display -ForegroundColor Yellow
                }
                elseif ($selectable[$cursor] -eq $i) {
                    Write-Host ('  ▶ ' + $item.Display) -ForegroundColor Black -BackgroundColor Cyan
                }
                else {
                    Write-Host ('    ' + $item.Display) -ForegroundColor Gray
                }
            }
            $key = [System.Console]::ReadKey($true)
            switch ($key.Key) {
                'UpArrow' { $cursor = ($cursor - 1 + $selectable.Count) % $selectable.Count }
                'LeftArrow' { $cursor = ($cursor - 1 + $selectable.Count) % $selectable.Count }
                'DownArrow' { $cursor = ($cursor + 1) % $selectable.Count }
                'RightArrow' { $cursor = ($cursor + 1) % $selectable.Count }
                'Enter' { return $Items[$selectable[$cursor]] }
                'Escape' { return $null }
            }
        }
    }
    finally {
        [System.Console]::CursorVisible = $prevVisible
    }
}

# -- ISE 등 ReadKey 미지원 환경용 번호 입력 대체 --
function Read-MenuSelectionFallback {
    param([Parameter(Mandatory)] $Items)
    $map = @{}
    $n = 0
    foreach ($item in $Items) {
        if ($item.IsHeader) {
            Write-Host $item.Display -ForegroundColor Yellow
        }
        else {
            $n++
            $map[$n] = $item
            Write-Host ('  {0}. {1}' -f $n, $item.Display) -ForegroundColor Gray
        }
    }
    if ($n -eq 0) { return $null }
    $sel = Read-Host "`n번호 입력 (취소: Enter)"
    if ([string]::IsNullOrWhiteSpace($sel)) { return $null }
    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $map.ContainsKey($idx)) { return $map[$idx] }
    Write-Host '잘못된 입력입니다.' -ForegroundColor Red
    return $null
}

# -- 1) 어댑터 + IPv4 목록을 그룹화하여 메뉴 항목 구성 --
$adapters = Get-NetAdapter | Sort-Object ifIndex
$ipv4All = Get-NetIPAddress -AddressFamily IPv4

$items = New-Object System.Collections.Generic.List[object]
foreach ($ad in $adapters) {
    $items.Add([PSCustomObject]@{
            IsHeader = $true
            Display  = ('■ {0}  [{1}]  {2}' -f $ad.Name, $ad.Status, $ad.InterfaceDescription)
            Value    = $null
        })

    $addrs = @($ipv4All | Where-Object { $_.InterfaceIndex -eq $ad.ifIndex })
    if ($addrs.Count -eq 0) {
        $items.Add([PSCustomObject]@{
                IsHeader = $true     # 선택 불가 안내 → 헤더로 처리하여 커서가 건너뜀
                Display  = '      (IPv4 주소 없음)'
                Value    = $null
            })
        continue
    }

    foreach ($a in $addrs) {
        $range = Get-ScanRange -IPAddress $a.IPAddress -PrefixLength $a.PrefixLength
        $display = ('{0}/{1}   →  {2} ~ {3}  ({4} hosts)' -f `
                $a.IPAddress, $a.PrefixLength,
            (ConvertFrom-IPUInt $range.FirstHost),
            (ConvertFrom-IPUInt $range.LastHost),
            $range.HostCount)
        $items.Add([PSCustomObject]@{
                IsHeader = $false
                Display  = $display
                Value    = [PSCustomObject]@{
                    AdapterName = $ad.Name
                    IPAddress   = $a.IPAddress
                    Prefix      = $a.PrefixLength
                    Range       = $range
                }
            })
    }
}

# -- 2) 선택 --
if ($Host.Name -match 'ISE') {
    $selected = Read-MenuSelectionFallback -Items $items
}
else {
    $selected = Read-MenuSelection -Items $items
}
if (-not $selected) { Write-Host '선택이 취소되었습니다.' -ForegroundColor Yellow; return }

$range = $selected.Value.Range
Clear-Host
Write-Host ('선택: {0}  |  {1}/{2}' -f $selected.Value.AdapterName, $selected.Value.IPAddress, $selected.Value.Prefix) -ForegroundColor Cyan
Write-Host ("스캔 대역: {0} ~ {1}  ({2} hosts)`n" -f (ConvertFrom-IPUInt $range.FirstHost), (ConvertFrom-IPUInt $range.LastHost), $range.HostCount) -ForegroundColor Cyan

if ($range.HostCount -gt 1024) {
    Write-Host ('경고: 호스트 수가 {0}개로 많아 스캔에 시간이 오래 걸릴 수 있습니다.' -f $range.HostCount) -ForegroundColor Yellow
    $ans = Read-Host '계속하시겠습니까? (Y/N)'
    if ($ans -notin 'Y', 'y') { Write-Host '취소되었습니다.'; return }
}

# -- 3) ARP Table 초기화 (관리자 권한 확보 후이므로 성공 전제) --
Invoke-WithSpinner -Message "Clearing ARP Cache..." -Color Cyan -SpinnerPos 'Right' -Work {
    arp -d * 2>$null | Out-Null
}
Write-Host "ARP Cache Cleared.`n" -ForegroundColor Cyan

# -- 4) ARP 스윕: 다회차 스윕 후 결과 합집합 --
$netStart = ConvertTo-IPUInt $range.Network
$netEnd = ConvertTo-IPUInt $range.Broadcast

# 회차별 핑 스윕 (이미 확인된 IP는 건너뜀)
function Invoke-PingSweep {
    param(
        [Parameter(Mandatory)][uint64]    $First,
        [Parameter(Mandatory)][uint64]    $Last,
        [Parameter(Mandatory)][int]       $TimeoutMs,
        [Parameter(Mandatory)][int]       $BatchSize,
        [Parameter(Mandatory)][hashtable] $Known
    )
    $cur = $First
    while ($cur -le $Last) {
        $end = [uint64][math]::Min([double]$Last, [double]($cur + $BatchSize - 1))
        $pings = New-Object System.Collections.ArrayList
        $tasks = New-Object System.Collections.ArrayList
        try {
            for ($u = $cur; $u -le $end; $u++) {
                $ip = ConvertFrom-IPUInt $u
                if ($Known.ContainsKey($ip)) { continue }
                $ping = New-Object System.Net.NetworkInformation.Ping
                [void]$pings.Add($ping)
                [void]$tasks.Add($ping.SendPingAsync($ip, $TimeoutMs))
            }
            if ($tasks.Count -gt 0) {
                [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks.ToArray())
            }
        }
        finally {
            foreach ($ping in $pings) { $ping.Dispose() }   # 반드시 WaitAll 이후
        }
        Start-Sleep -Milliseconds 50   # 배치 간 간격: 브로드캐스트 폭주 완화
        $cur = $end + 1
    }
}

# 현재 ARP 캐시에서 선택 대역의 유효 이웃만 추출
function Get-LiveNeighbor {
    param(
        [Parameter(Mandatory)][uint64] $NetStart,
        [Parameter(Mandatory)][uint64] $NetEnd
    )
    Get-NetNeighbor -AddressFamily IPv4 | Where-Object {
        $u = ConvertTo-IPUInt $_.IPAddress
        $u -ge $NetStart -and $u -le $NetEnd -and
        $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF'
    }
}

$pingTimeoutMs = 1500
$pingBatchSize = 64
$sweepRounds = 5

$known = @{}
Invoke-WithSpinner -Message "ARP Scanning..." -Color Cyan -SpinnerPos 'Right' -Work {
    param($state)

    for ($round = 1; $round -le $sweepRounds; $round++) {
        Invoke-PingSweep -First $range.FirstHost -Last $range.LastHost `
            -TimeoutMs $pingTimeoutMs -BatchSize $pingBatchSize -Known $known
        Start-Sleep -Milliseconds 500   # 지연 응답이 캐시에 반영될 여유

        foreach ($n in (Get-LiveNeighbor -NetStart $netStart -NetEnd $netEnd)) {
            if (-not $known.ContainsKey($n.IPAddress)) {
                $known[$n.IPAddress] = $n
            }
        }
        Set-SpinnerDetail -State $state -Text ("Progress: {0}/{1} Scanned Count: {2}" -f $round, $sweepRounds, $known.Count) -Color DarkCyan
    }
}
Write-Host ("ARP Scanning Complete.`n") -ForegroundColor Cyan

# -- 5) 합집합 결과 확정 --
$live = @($known.Values)

# -- 6) 이름 조회 + 포트 스캔 워커 --
$worker = {
    param($ip, $mac, $ports)
    # -- 응답 레코드에서 호스트명 추출 --
    function Get-RecordHostName {
        param($Records)
        foreach ($rec in $Records) {
            $candidate = $null
            if ($rec.PSObject.Properties['NameHost'] -and $rec.NameHost) {
                $candidate = $rec.NameHost
            }
            elseif ($rec.PSObject.Properties['Name'] -and $rec.Name) {
                $candidate = $rec.Name
            }
            if ($candidate) { return ($candidate -replace '\.$', '').Trim() }
        }
        return $null
    }

    # -- 프로토콜별 역방향 조회 (DNS → LLMNR → NetBIOS 순) --
    function Resolve-TargetName {
        param([string] $Address)

        $attempts = @(
            [PSCustomObject]@{ Method = 'DNS'; Options = @{ DnsOnly = $true } },
            [PSCustomObject]@{ Method = 'LLMNR'; Options = @{ LlmnrOnly = $true } },
            [PSCustomObject]@{ Method = 'NetBIOS'; Options = @{ NetbiosFallback = $true } }
        )

        foreach ($attempt in $attempts) {
            $options = $attempt.Options
            try {
                $records = Resolve-DnsName -Name $Address -QuickTimeout @options -ErrorAction Stop
                $found = Get-RecordHostName -Records $records
                if ($found) {
                    return [PSCustomObject]@{ Name = $found; Method = $attempt.Method }
                }
            }
            catch {
                continue
            }
        }
        return $null
    }

    # 이름 조회
    $name = $null; $via = $null
    $resolved = Resolve-TargetName -Address $ip
    if ($resolved) { $name = $resolved.Name; $via = $resolved.Method }

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
        Name = if ($name) { $name }else { '(Unknown)' }
        Method = $via
        OpenPorts = if ($open) { ($open | Sort-Object) -join ',' } else { '-' }
    }
}

$results = New-Object System.Collections.ArrayList
Invoke-WithSpinner -Message ("Detected {0} hosts. Host/Port Scanning..." -f $live.Count) -Color Cyan -SpinnerPos 'Right' -Work {
    param($state)
    # -- 7) 런스페이스 풀 병렬 실행 --
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.ImportPSModule('DnsClient')
    $pool = [runspacefactory]::CreateRunspacePool(1, 32, $iss, $Host); $pool.Open()
    $jobs = foreach ($n in $live) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).
        AddArgument($n.IPAddress).
        AddArgument($n.LinkLayerAddress).
        AddArgument($tcpPorts)
        [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    
    # -- 8) 완료되는 대로 한 줄씩 출력 --
    $pending = [System.Collections.ArrayList]@($jobs)
    while ($pending.Count -gt 0) {
        for ($i = $pending.Count - 1; $i -ge 0; $i--) {
            if ($pending[$i].Handle.IsCompleted) {
                $r = $pending[$i].PS.EndInvoke($pending[$i].Handle) | Select-Object -First 1
                $pending[$i].PS.Dispose(); [void]$pending.RemoveAt($i); [void]$results.Add($r)
                Set-SpinnerStatus -State $state -Status ("Scanned: {0}/{1}" -f ($results.Count), $live.Count)
                if ($r.Method) {
                    Write-SpinnerLine -State $state -Text ("[{0,-15}] {1,-18} 포트: {2}" -f $r.IP, $r.Name, $r.OpenPorts)
                }
                else {
                    Write-SpinnerLine -State $state -Text ("[{0,-15}] {1,-18} 포트: {2}" -f $r.IP, 'Unknown', $r.OpenPorts)
                }
            }
        }
        Start-Sleep -Milliseconds 30
    }
    $pool.Close(); $pool.Dispose()
}

Write-Host "`n=== 최종 결과 ===" -ForegroundColor Cyan
$results | Sort-Object { [version]($_.IP) } | Format-Table IP, Name, Method, OpenPorts, MAC -AutoSize