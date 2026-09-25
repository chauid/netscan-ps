<#
    NetScan v4 - 실시간 네트워크 스캐너 (대시보드형)
    NetScan 모듈 엔진 : Start-NetScan (별칭 netscan) 이 이 파일을 실행한다.
    ------------------------------------------------------------
    - 선택한 어댑터/대역을 주기적으로 반복 스캔하여 htop 형태로 실시간 표시
    - ARP flush 는 지정한 간격(기본 10분)이 되었을 때만 수행
    - 핑 스윕 회차는 flush 직후 사이클과 일반 사이클을 분리 적용
    - 이름 조회는 DNS / LLMNR / NetBIOS / mDNS 4종을 모두 검사
        · 조회 엔진: Resolve-DnsName(기본) 또는 raw UDP (설정에서 선택)
        · mDNS 는 엔진과 무관하게 항상 raw UDP
        · LLMNR 이름도 엔진과 무관하게 raw UDP 로만 조회 (Resolve-DnsName -LlmnrOnly 미사용)
          - 이 cmdlet 은 멀티캐스트 조회로 LLMNR 과 mDNS 를 함께 보내므로,
            mDNS 응답(xxx.local)이 LLMNR 이름으로 잘못 표기되는 문제가 있었다.
    - UDP 포트(53/137/5355/5353) 개방 여부는 항상 raw UDP 프로브로 판정
    - MAC 제조사는 모듈 폴더의 oui.txt 로 조회 (OUI|약칭|정식명)
    - 설정값은 %ProgramData%\NetScan\scan_tool.config.json 에 저장되어 다음 실행 때 복원
        · 모듈 설치 폴더(Program Files)는 쓰기 대상이 아니므로 설정은 ProgramData 에 둔다.
    - 키보드 전용 UI (마우스 이벤트 없음)
    - [F3] 검색 : IP / 이름 / MAC / 제조사 / TCP 포트(번호·서비스명) 로 일치 호스트에 커서 이동
        · 입력 즉시 이동(incremental), F3·↓ 다음 / Shift+F3·↑ 이전, Enter 확정, Esc 취소
        · 다음/이전 이동은 검색 모드에서만 동작 (대시보드에서는 F3 = 검색 모드 진입만)
        · 필터가 걸려 있으면 필터 결과 안에서만 검색
    - [F4] 필터 : 검색과 같은 대상·규칙으로 일치하는 호스트만 목록에 표시
        · 입력 즉시 목록 반영(incremental), ↑↓ 이동, Enter 적용(빈 값이면 해제), Esc 취소
        · 표시(목록/상세/검색)에만 적용되며 스캔은 항상 대역 전체를 대상으로 진행
        · 필터는 설정 파일에 저장하지 않음 (실행할 때마다 해제 상태로 시작)

    주의: 관리자 권한이 필요하며, 부족하면 승격된 창으로 자동 재실행됩니다.
          PowerShell ISE 는 지원하지 않습니다.
#>

# ============================================================
# 0) 환경 점검 : ISE 미지원 → 즉시 종료 (권한 확인보다 먼저)
# ============================================================
if ($Host.Name -match 'ISE') {
    Write-Host 'NetScan v4 는 PowerShell ISE 를 지원하지 않습니다.' -ForegroundColor Red
    Write-Host 'Windows Terminal, conhost 또는 pwsh 콘솔에서 실행하십시오.' -ForegroundColor Yellow
    return
}

# ============================================================
# 1) 관리자 권한 확인 및 자동 승격
#    arp -d * 는 관리자 권한이 없으면 실행되지 않으므로 강제한다.
# ============================================================
function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Host '이 스크립트는 관리자 권한이 필요합니다.' -ForegroundColor Red
        Write-Host '콘솔에 직접 붙여넣은 경우 자동 승격이 불가하므로, 관리자 권한 PowerShell 에서 다시 실행하십시오.' -ForegroundColor Yellow
        return
    }
    Write-Host '관리자 권한이 필요합니다. 승격된 창으로 다시 실행합니다...' -ForegroundColor Yellow
    $exe = (Get-Process -Id $PID).Path
    # Program Files 처럼 공백이 있는 경로를 위해 따옴표로 감싼다 (Start-Process 는 인수를 공백으로만 이어 붙임)
    $startArgs = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    try {
        Start-Process -FilePath $exe -Verb RunAs -ArgumentList $startArgs -ErrorAction Stop
    }
    catch {
        Write-Host '권한 승격이 취소되었거나 실패했습니다.' -ForegroundColor Red
    }
    return
}

# ============================================================
# 2) 경로 / 기본 설정 / 설정 파일 로드·저장
# ============================================================
$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:ConfigDir = Join-Path $env:ProgramData 'NetScan'
$script:ConfigPath = Join-Path $script:ConfigDir 'scan_tool.config.json'
$script:OuiPath = Join-Path $script:ScriptDir 'oui.txt'

# 검사 대상 TCP 포트와 간단한 서비스명 표(상세 화면 표기용)
$script:TcpPorts = @(20, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 119, 135, 139, 143, 179, 194,
    389, 443, 445, 465, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2181,
    2375, 2376, 3000, 3128, 3268, 3306, 3389, 3392, 4369, 4444, 5000, 5060, 5061, 5222, 5432, 5601,
    5672, 5900, 5984, 6379, 6443, 8000, 8009, 8080, 8081, 8086, 8088, 8443, 8888, 9000, 9042,
    9092, 9200, 9300, 9418, 9999)

$script:ServiceNames = @{
    20 = 'ftp-data'; 21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'; 53 = 'dns'; 79 = 'finger'
    80 = 'http'; 88 = 'kerberos'; 110 = 'pop3'; 111 = 'rpcbind'; 119 = 'nntp'; 135 = 'msrpc'
    139 = 'netbios-ssn'; 143 = 'imap'; 179 = 'bgp'; 194 = 'irc'; 389 = 'ldap'; 443 = 'https'
    445 = 'microsoft-ds'; 465 = 'smtps'; 515 = 'printer'; 587 = 'submission'; 631 = 'ipp'
    636 = 'ldaps'; 993 = 'imaps'; 995 = 'pop3s'; 1080 = 'socks'; 1433 = 'mssql'; 1521 = 'oracle'
    1723 = 'pptp'; 1883 = 'mqtt'; 2049 = 'nfs'; 2181 = 'zookeeper'; 2375 = 'docker'; 2376 = 'docker-s'
    3000 = 'http-alt'; 3128 = 'squid'; 3268 = 'globalcat'; 3306 = 'mysql'; 3389 = 'rdp'; 3392 = 'efi-lm';
    4369 = 'epmd'; 4444 = 'krb-alt'; 5000 = 'upnp'; 5060 = 'sip'; 5061 = 'sips'; 5222 = 'xmpp'; 5432 = 'postgres'
    5601 = 'kibana'; 5672 = 'amqp'; 5900 = 'vnc'; 5984 = 'couchdb'; 6379 = 'redis'; 6443 = 'k8s-api'
    8000 = 'http-alt'; 8009 = 'ajp'; 8080 = 'http-proxy'; 8081 = 'http-alt'; 8086 = 'influxdb'
    8088 = 'http-alt'; 8443 = 'https-alt'; 8888 = 'http-alt'; 9000 = 'http-alt'; 9042 = 'cassandra'
    9092 = 'kafka'; 9200 = 'elastic'; 9300 = 'elastic-tr'; 9418 = 'git'; 9999 = 'http-alt'
}

function Get-DefaultConfig {
    [PSCustomObject]@{
        AdapterName     = ''            # 저장된 어댑터 이름(시작 시 기본 선택)
        AdapterIP       = ''            # 저장된 대역 대표 IP
        Engine          = 'ResolveDnsName'  # ResolveDnsName | RawUdp
        RescanSec       = 60
        FlushMin        = 10
        SweepAfterFlush = 5
        SweepNormal     = 2
        PingTimeoutMs   = 1500
        TcpTimeoutMs    = 250
        UdpTimeoutMs    = 700
    }
}

# 설정 항목 메타(설정 화면에서 사용) : 키, 라벨, 최소, 최대, 단위
$script:ConfigMeta = @(
    [PSCustomObject]@{ Key = 'RescanSec'; Label = '재스캔 주기'; Min = 10; Max = 3600; Unit = '초'; Default = 60 }
    [PSCustomObject]@{ Key = 'FlushMin'; Label = 'ARP flush 간격'; Min = 1; Max = 1440; Unit = '분'; Default = 10 }
    [PSCustomObject]@{ Key = 'SweepAfterFlush'; Label = '스윕 회차 (flush 직후)'; Min = 1; Max = 10; Unit = '회'; Default = 5 }
    [PSCustomObject]@{ Key = 'SweepNormal'; Label = '스윕 회차 (일반 사이클)'; Min = 1; Max = 10; Unit = '회'; Default = 2 }
    [PSCustomObject]@{ Key = 'PingTimeoutMs'; Label = '핑 타임아웃'; Min = 100; Max = 5000; Unit = 'ms'; Default = 1500 }
    [PSCustomObject]@{ Key = 'TcpTimeoutMs'; Label = 'TCP 포트 스캔 타임아웃'; Min = 50; Max = 3000; Unit = 'ms'; Default = 250 }
    [PSCustomObject]@{ Key = 'UdpTimeoutMs'; Label = 'UDP 질의 타임아웃'; Min = 100; Max = 5000; Unit = 'ms'; Default = 700 }
)

function Import-ScanConfig {
    $cfg = Get-DefaultConfig
    if (Test-Path -LiteralPath $script:ConfigPath) {
        try {
            $raw = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8
            $loaded = $raw | ConvertFrom-Json
            foreach ($prop in $cfg.PSObject.Properties.Name) {
                if ($loaded.PSObject.Properties.Name -contains $prop) {
                    $cfg.$prop = $loaded.$prop
                }
            }
        }
        catch {
            # 손상된 설정 파일은 무시하고 기본값 사용
        }
    }
    # 숫자 항목 범위 보정
    foreach ($m in $script:ConfigMeta) {
        $v = [int]$cfg.($m.Key)
        if ($v -lt $m.Min) { $v = $m.Min }
        if ($v -gt $m.Max) { $v = $m.Max }
        $cfg.($m.Key) = $v
    }
    if ($cfg.Engine -notin 'ResolveDnsName', 'RawUdp') { $cfg.Engine = 'ResolveDnsName' }
    return $cfg
}

function Export-ScanConfig {
    param([Parameter(Mandatory)] $Config)
    try {
        if (-not (Test-Path -LiteralPath $script:ConfigDir)) {
            New-Item -ItemType Directory -Path $script:ConfigDir -Force -ErrorAction Stop | Out-Null
        }
        $Config | ConvertTo-Json | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
        return $true
    }
    catch {
        return $false
    }
}

# ============================================================
# 3) 공유 함수 정의 (메인 세션 + 워커 런스페이스 공용)
#    런스페이스에서도 그대로 dot-source 할 수 있도록 문자열로 보관한다.
# ============================================================
$script:SharedFunctions = @'
# ---- 콘솔 표시폭 유틸 (동아시아 문자는 2칸으로 계산) ----
function Get-CharWidth {
    param([Parameter(Mandatory)][char] $Char)
    $code = [int]$Char
    if ($code -eq 0) { return 0 }
    # East Asian Wide / Fullwidth 주요 구간
    if (
        ($code -ge 0x1100 -and $code -le 0x115F) -or   # Hangul Jamo
        ($code -ge 0x2E80 -and $code -le 0x303E) -or   # CJK Radicals ~ Kangxi
        ($code -ge 0x3041 -and $code -le 0x33FF) -or   # Hiragana ~ CJK symbols
        ($code -ge 0x3400 -and $code -le 0x4DBF) -or   # CJK Ext A
        ($code -ge 0x4E00 -and $code -le 0x9FFF) -or   # CJK Unified
        ($code -ge 0xA000 -and $code -le 0xA4CF) -or   # Yi
        ($code -ge 0xAC00 -and $code -le 0xD7A3) -or   # Hangul Syllables
        ($code -ge 0xF900 -and $code -le 0xFAFF) -or   # CJK Compat
        ($code -ge 0xFE30 -and $code -le 0xFE4F) -or   # CJK Compat Forms
        ($code -ge 0xFF00 -and $code -le 0xFF60) -or   # Fullwidth Forms
        ($code -ge 0xFFE0 -and $code -le 0xFFE6)
    ) { return 2 }
    return 1
}

function Get-DisplayWidth {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    $w = 0
    foreach ($ch in $Text.ToCharArray()) { $w += Get-CharWidth -Char $ch }
    return $w
}

function Format-Cell {
    <# 표시폭 기준으로 문자열을 자르고( … ) 지정 폭에 맞춰 좌측 정렬 패딩 #>
    param(
        [string] $Text,
        [Parameter(Mandatory)][int] $Width,
        [switch] $Right
    )
    if ($null -eq $Text) { $Text = '' }
    $w = Get-DisplayWidth -Text $Text
    if ($w -gt $Width) {
        # 폭에 맞게 자르고 마지막에 … (…는 1칸)
        $sb = New-Object System.Text.StringBuilder
        $acc = 0
        foreach ($ch in $Text.ToCharArray()) {
            $cw = Get-CharWidth -Char $ch
            if ($acc + $cw -gt ($Width - 1)) { break }
            [void]$sb.Append($ch)
            $acc += $cw
        }
        [void]$sb.Append([char]0x2026)   # …
        $acc += 1
        $text2 = $sb.ToString()
        $pad = $Width - $acc
        if ($pad -lt 0) { $pad = 0 }
        return $text2 + (' ' * $pad)
    }
    $pad = $Width - $w
    if ($Right) { return (' ' * $pad) + $Text }
    return $Text + (' ' * $pad)
}

# ---- IP <-> uint32 변환 ----
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

# ---- raw UDP 질의 (임의 페이로드 송신 후 단일 응답 수신) ----
# 반환: @{ Verdict='open'|'closed'|'unknown'; Data=byte[] 또는 $null }
function Invoke-UdpQuery {
    param(
        [Parameter(Mandatory)][string] $Address,
        [Parameter(Mandatory)][int]    $Port,
        [Parameter(Mandatory)][byte[]] $Payload,
        [int] $TimeoutMs = 700
    )
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Client.ReceiveTimeout = $TimeoutMs
        # ICMP Port Unreachable 로 인한 재설정 예외를 정상 신호로 받기 위한 옵션(무해)
        [void]$client.Send($Payload, $Payload.Length, $Address, $Port)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $data = $client.Receive([ref]$remote)
        return @{ Verdict = 'open'; Data = $data }
    }
    catch [System.Net.Sockets.SocketException] {
        $code = $_.Exception.SocketErrorCode
        if ($code -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
            return @{ Verdict = 'closed'; Data = $null }   # ICMP Unreachable
        }
        return @{ Verdict = 'unknown'; Data = $null }       # 타임아웃 등
    }
    catch {
        return @{ Verdict = 'unknown'; Data = $null }
    }
    finally {
        if ($client) { $client.Close() }
    }
}

# ---- 멀티캐스트 UDP 질의 (LLMNR/mDNS: 그룹으로 송신, 소유 호스트의 유니캐스트 응답 수신) ----
# 임시 포트에 바인딩하므로 그룹 포트로 오는 멀티캐스트 잡음은 받지 않고, 우리 질의의 응답만 받는다.
function Invoke-McastQuery {
    param(
        [Parameter(Mandatory)][string] $Group,
        [Parameter(Mandatory)][int]    $Port,
        [Parameter(Mandatory)][byte[]] $Payload,
        [string] $ExpectIP = '',
        [string] $LocalIP = '',
        [int]    $TimeoutMs = 700
    )
    $client = $null
    try {
        if ($LocalIP) {
            try {
                $local = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIP), 0)
                $client = New-Object System.Net.Sockets.UdpClient($local)   # 선택 어댑터로 송신
            }
            catch { $client = New-Object System.Net.Sockets.UdpClient }
        }
        else { $client = New-Object System.Net.Sockets.UdpClient }
        try { $client.Ttl = 2 } catch {}
        $client.Client.ReceiveTimeout = $TimeoutMs
        [void]$client.Send($Payload, $Payload.Length, $Group, $Port)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $data = $client.Receive([ref]$remote)
        if ($ExpectIP -and $remote.Address.ToString() -ne $ExpectIP) {
            return @{ Answered = $false; Data = $null }
        }
        return @{ Answered = $true; Data = $data }
    }
    catch { return @{ Answered = $false; Data = $null } }
    finally { if ($client) { $client.Close() } }
}

# ---- 역방향 PTR 이름 (a.b.c.d -> d.c.b.a.in-addr.arpa) ----
function Get-ReversePtrName {
    param([Parameter(Mandatory)][string] $IPAddress)
    $o = $IPAddress.Split('.')
    return ('{0}.{1}.{2}.{3}.in-addr.arpa' -f $o[3], $o[2], $o[1], $o[0])
}

# ---- DNS/LLMNR/mDNS 메시지 QNAME 인코딩 ----
function ConvertTo-DnsQName {
    param([Parameter(Mandatory)][string] $Name)
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($label in $Name.Split('.')) {
        if ($label.Length -eq 0) { continue }
        $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$lb.Length)
        $bytes.AddRange($lb)
    }
    $bytes.Add([byte]0)
    return $bytes.ToArray()
}

# ---- DNS 계열 질의 패킷 생성 ----
# QType: 12=PTR, 1=A ; Flags: 0x0100=DNS표준RD, 0x0000=LLMNR/mDNS ; QClass: 1 또는 0x8001(mDNS QU)
function New-DnsQueryPacket {
    param(
        [Parameter(Mandatory)][string] $QName,
        [int] $QType = 12,
        [int] $Flags = 0x0100,
        [int] $QClass = 1,
        [int] $TxnId = 0
    )
    $pkt = New-Object System.Collections.Generic.List[byte]
    $pkt.Add([byte](($TxnId -shr 8) -band 0xFF)); $pkt.Add([byte]($TxnId -band 0xFF))
    $pkt.Add([byte](($Flags -shr 8) -band 0xFF)); $pkt.Add([byte]($Flags -band 0xFF))
    $pkt.Add(0); $pkt.Add(1)   # QDCOUNT=1
    $pkt.Add(0); $pkt.Add(0)   # ANCOUNT
    $pkt.Add(0); $pkt.Add(0)   # NSCOUNT
    $pkt.Add(0); $pkt.Add(0)   # ARCOUNT
    $pkt.AddRange([byte[]](ConvertTo-DnsQName -Name $QName))
    $pkt.Add([byte](($QType -shr 8) -band 0xFF)); $pkt.Add([byte]($QType -band 0xFF))
    $pkt.Add([byte](($QClass -shr 8) -band 0xFF)); $pkt.Add([byte]($QClass -band 0xFF))
    return $pkt.ToArray()
}

# ---- DNS 응답에서 이름 읽기 (압축 포인터 0xC0 처리) ----
function Read-DnsName {
    param(
        [Parameter(Mandatory)][byte[]] $Data,
        [Parameter(Mandatory)][int]    $Offset
    )
    $labels = New-Object System.Collections.Generic.List[string]
    $pos = $Offset
    $jumped = $false
    $next = $Offset
    $guard = 0
    while ($true) {
        if ($pos -ge $Data.Length) { break }
        $len = $Data[$pos]
        if ($len -eq 0) {
            if (-not $jumped) { $next = $pos + 1 }
            break
        }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($pos + 1 -ge $Data.Length) { break }
            $ptr = (($len -band 0x3F) -shl 8) -bor $Data[$pos + 1]
            if (-not $jumped) { $next = $pos + 2 }
            $pos = $ptr
            $jumped = $true
            $guard++
            if ($guard -gt 128) { break }
            continue
        }
        $pos++
        if ($pos + $len -gt $Data.Length) { break }
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Data, $pos, $len))
        $pos += $len
    }
    return [PSCustomObject]@{ Name = ($labels -join '.'); NextOffset = $next }
}

# ---- DNS 응답에서 첫 PTR 레코드의 이름 추출 ----
function Get-DnsPtrAnswer {
    param([Parameter(Mandatory)][byte[]] $Data)
    if ($Data.Length -lt 12) { return $null }
    $anCount = ($Data[6] -shl 8) -bor $Data[7]
    if ($anCount -lt 1) { return $null }
    $qd = ($Data[4] -shl 8) -bor $Data[5]
    $pos = 12
    # 질문 섹션 스킵
    for ($q = 0; $q -lt $qd; $q++) {
        $r = Read-DnsName -Data $Data -Offset $pos
        $pos = $r.NextOffset + 4
    }
    for ($a = 0; $a -lt $anCount; $a++) {
        $r = Read-DnsName -Data $Data -Offset $pos
        $pos = $r.NextOffset
        if ($pos + 10 -gt $Data.Length) { return $null }
        $type = ($Data[$pos] -shl 8) -bor $Data[$pos + 1]
        $rdlen = ($Data[$pos + 8] -shl 8) -bor $Data[$pos + 9]
        $rdStart = $pos + 10
        if ($type -eq 12) {
            $nm = Read-DnsName -Data $Data -Offset $rdStart
            if ($nm.Name) { return ($nm.Name -replace '\.$', '') }
        }
        $pos = $rdStart + $rdlen
    }
    return $null
}

# ---- NetBIOS 이름 인코딩 (첫 단계 인코딩) ----
function ConvertTo-NetbiosEncoded {
    param([Parameter(Mandatory)][byte[]] $NameBytes)   # 정확히 16바이트
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($b in $NameBytes) {
        $hi = ($b -shr 4) -band 0x0F
        $lo = $b -band 0x0F
        $out.Add([byte](0x41 + $hi))
        $out.Add([byte](0x41 + $lo))
    }
    return $out.ToArray()
}

# ---- NBSTAT(노드 상태) 질의 패킷 ----
function New-NbstatQueryPacket {
    param([int] $TxnId = 0x4E53)
    # NetBIOS 이름 '*' + 널패딩(총 16바이트)
    $name16 = New-Object 'byte[]' 16
    $name16[0] = 0x2A   # '*'
    $enc = ConvertTo-NetbiosEncoded -NameBytes $name16

    $pkt = New-Object System.Collections.Generic.List[byte]
    $pkt.Add([byte](($TxnId -shr 8) -band 0xFF)); $pkt.Add([byte]($TxnId -band 0xFF))
    $pkt.Add(0); $pkt.Add(0)   # flags
    $pkt.Add(0); $pkt.Add(1)   # QDCOUNT=1
    $pkt.Add(0); $pkt.Add(0)
    $pkt.Add(0); $pkt.Add(0)
    $pkt.Add(0); $pkt.Add(0)
    $pkt.Add([byte]0x20)       # 인코딩된 이름 길이 32
    $pkt.AddRange([byte[]]$enc)
    $pkt.Add(0)                # 이름 종료
    $pkt.Add(0); $pkt.Add(0x21)  # QTYPE = NBSTAT(0x21)
    $pkt.Add(0); $pkt.Add(0x01)  # QCLASS = IN
    return $pkt.ToArray()
}

# ---- NBSTAT 응답 파싱 : 컴퓨터명/워크그룹 추출 ----
function Get-NbstatNames {
    param([Parameter(Mandatory)][byte[]] $Data)
    if ($Data.Length -lt 57) { return $null }
    # 헤더(12) 스킵 후 응답 이름(0x20+32+1=34) + type/class/ttl/rdlen(10)
    $pos = 12
    if ($Data[$pos] -ne 0x20) {
        # 안전하게 0바이트(이름 종료) 탐색
        while ($pos -lt $Data.Length -and $Data[$pos] -ne 0) { $pos++ }
        $pos++
    }
    else {
        $pos += 1 + 32 + 1
    }
    $pos += 2 + 2 + 4   # type, class, ttl
    if ($pos + 2 -ge $Data.Length) { return $null }
    $rdlen = ($Data[$pos] -shl 8) -bor $Data[$pos + 1]
    $pos += 2
    if ($pos -ge $Data.Length) { return $null }
    $numNames = $Data[$pos]; $pos++
    $computer = $null; $group = $null
    for ($i = 0; $i -lt $numNames; $i++) {
        if ($pos + 18 -gt $Data.Length) { break }
        $nameRaw = [System.Text.Encoding]::ASCII.GetString($Data, $pos, 15).TrimEnd(' ', [char]0)
        $suffix = $Data[$pos + 15]
        $flags = ($Data[$pos + 16] -shl 8) -bor $Data[$pos + 17]
        $isGroup = ($flags -band 0x8000) -ne 0
        if ($suffix -eq 0x00) {
            if ($isGroup) { if (-not $group) { $group = $nameRaw } }
            else { if (-not $computer) { $computer = $nameRaw } }
        }
        $pos += 18
    }
    if (-not $computer -and -not $group) { return $null }
    return [PSCustomObject]@{ Computer = $computer; Group = $group }
}

# ---- 호스트에 4종 raw UDP 프로브 전송 → 이름/포트판정 ----
# 반환 객체: Names(@{DNS/LLMNR/NetBIOS/mDNS}), Udp(@{53/137/5355/5353}=verdict), Group
function Invoke-HostProbe {
    param(
        [Parameter(Mandatory)][string] $IP,
        [Parameter(Mandatory)][string] $Reverse,
        [int] $TimeoutMs = 700,
        [string[]] $DnsServers = @(),
        [string] $Engine = 'ResolveDnsName',
        [string] $LocalIP = ''
    )
    $names = @{ DNS = $null; LLMNR = $null; NetBIOS = $null; mDNS = $null }
    $udp = @{ 53 = 'unknown'; 137 = 'unknown'; 5355 = 'unknown'; 5353 = 'unknown' }
    $group = $null

    # 53 : 대상 호스트 직접 DNS 질의(개방 판정 전용). 이름은 사용하지 않음.
    $rid = Get-Random -Minimum 1 -Maximum 65535
    $q53 = New-DnsQueryPacket -QName $Reverse -QType 12 -Flags 0x0100 -QClass 1 -TxnId $rid
    $r53 = Invoke-UdpQuery -Address $IP -Port 53 -Payload $q53 -TimeoutMs $TimeoutMs
    $udp[53] = $r53.Verdict

    # 5355 : LLMNR PTR
    #   RawUdp 모드는 멀티캐스트(224.0.0.252)로 질의하고 소유 호스트의 유니캐스트 응답을 받는다.
    #   응답이 오면 그 호스트에서 LLMNR 응답기가 동작 중(= 5355 열림)으로 본다.
    #   ResolveDnsName 모드는 유니캐스트 프로브로 먼저 판정(open/closed/unknown)하고,
    #   이름을 얻지 못하면 멀티캐스트로 한 번 더 질의한다. 응답이 오면 열림으로 보정한다.
    #   (이름과 5355 판정이 항상 같은 LLMNR 프로토콜 응답에서 나오도록 보장)
    $rid = Get-Random -Minimum 1 -Maximum 65535
    $qll = New-DnsQueryPacket -QName $Reverse -QType 12 -Flags 0x0000 -QClass 1 -TxnId $rid
    if ($Engine -eq 'RawUdp') {
        $mll = Invoke-McastQuery -Group '224.0.0.252' -Port 5355 -Payload $qll -ExpectIP $IP -LocalIP $LocalIP -TimeoutMs $TimeoutMs
        if ($mll.Answered) {
            $udp[5355] = 'open'
            if ($mll.Data) { $nm = Get-DnsPtrAnswer -Data $mll.Data; if ($nm) { $names.LLMNR = $nm } }
        }
    }
    else {
        $rll = Invoke-UdpQuery -Address $IP -Port 5355 -Payload $qll -TimeoutMs $TimeoutMs
        $udp[5355] = $rll.Verdict
        if ($rll.Data) { $nm = Get-DnsPtrAnswer -Data $rll.Data; if ($nm) { $names.LLMNR = $nm } }
        if (-not $names.LLMNR -and $udp[5355] -ne 'closed') {
            $rid = Get-Random -Minimum 1 -Maximum 65535
            $qllm = New-DnsQueryPacket -QName $Reverse -QType 12 -Flags 0x0000 -QClass 1 -TxnId $rid
            $mll = Invoke-McastQuery -Group '224.0.0.252' -Port 5355 -Payload $qllm -ExpectIP $IP -LocalIP $LocalIP -TimeoutMs $TimeoutMs
            if ($mll.Answered) {
                $udp[5355] = 'open'
                if ($mll.Data) { $nm = Get-DnsPtrAnswer -Data $mll.Data; if ($nm) { $names.LLMNR = $nm } }
            }
        }
    }

    # 5353 : mDNS PTR (QU 비트 set → 유니캐스트 응답 요청)
    #   RawUdp 모드는 멀티캐스트(224.0.0.251)로 질의한다. ResolveDnsName 모드는 기존 유지.
    $rid = Get-Random -Minimum 1 -Maximum 65535
    $qmd = New-DnsQueryPacket -QName $Reverse -QType 12 -Flags 0x0000 -QClass 0x8001 -TxnId $rid
    if ($Engine -eq 'RawUdp') {
        $mmd = Invoke-McastQuery -Group '224.0.0.251' -Port 5353 -Payload $qmd -ExpectIP $IP -LocalIP $LocalIP -TimeoutMs $TimeoutMs
        if ($mmd.Answered) {
            $udp[5353] = 'open'
            if ($mmd.Data) { $nm = Get-DnsPtrAnswer -Data $mmd.Data; if ($nm) { $names.mDNS = $nm } }
        }
    }
    else {
        $rmd = Invoke-UdpQuery -Address $IP -Port 5353 -Payload $qmd -TimeoutMs $TimeoutMs
        $udp[5353] = $rmd.Verdict
        if ($rmd.Data) { $nm = Get-DnsPtrAnswer -Data $rmd.Data; if ($nm) { $names.mDNS = $nm } }
    }

    # 137 : NBSTAT (대상 직접)
    $qnb = New-NbstatQueryPacket
    $rnb = Invoke-UdpQuery -Address $IP -Port 137 -Payload $qnb -TimeoutMs $TimeoutMs
    $udp[137] = $rnb.Verdict
    if ($rnb.Data) {
        $nbt = Get-NbstatNames -Data $rnb.Data
        if ($nbt) { $names.NetBIOS = $nbt.Computer; $group = $nbt.Group }
    }

    # DNS 이름 : DNS 서버로 PTR 질의 (raw UDP 모드에서 사용)
    foreach ($srv in $DnsServers) {
        if (-not $srv) { continue }
        $rid = Get-Random -Minimum 1 -Maximum 65535
        $qd = New-DnsQueryPacket -QName $Reverse -QType 12 -Flags 0x0100 -QClass 1 -TxnId $rid
        $rd = Invoke-UdpQuery -Address $srv -Port 53 -Payload $qd -TimeoutMs $TimeoutMs
        if ($rd.Data) {
            $nm = Get-DnsPtrAnswer -Data $rd.Data
            if ($nm) { $names.DNS = $nm; break }
        }
    }

    return [PSCustomObject]@{ Names = $names; Udp = $udp; Group = $group }
}

# ---- TCP 포트 병렬 스캔 (호스트 내부에서 포트 동시 연결 시도) ----
function Invoke-TcpScan {
    param(
        [Parameter(Mandatory)][string] $IP,
        [Parameter(Mandatory)][int[]]  $Ports,
        [int] $TimeoutMs = 250
    )
    $clients = @{}
    $asyncs = @{}
    foreach ($p in $Ports) {
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $clients[$p] = $c
            $asyncs[$p] = $c.BeginConnect($IP, $p, $null, $null)
        }
        catch {
            try { $c.Close() } catch {}
            $clients.Remove($p)
        }
    }
    Start-Sleep -Milliseconds $TimeoutMs
    $open = New-Object System.Collections.Generic.List[int]
    foreach ($p in $Ports) {
        if (-not $clients.ContainsKey($p)) { continue }
        $c = $clients[$p]
        try {
            if ($asyncs[$p].IsCompleted -and $c.Connected) {
                $c.EndConnect($asyncs[$p])
                if ($c.Connected) { [void]$open.Add($p) }
            }
        }
        catch {}
        finally { try { $c.Close() } catch {} }
    }
    return ($open | Sort-Object)
}

# ---- 동기화 해시테이블 키 스냅샷 (열거 중 변경 예외 방지) ----
function Get-HostKeysSnapshot {
    param([Parameter(Mandatory)] $Hosts)
    $root = $Hosts.SyncRoot
    [System.Threading.Monitor]::Enter($root)
    try { return @($Hosts.Keys) }
    finally { [System.Threading.Monitor]::Exit($root) }
}

# ---- MAC 무작위(로컬 관리) 여부 ----
function Test-RandomMac {
    param([Parameter(Mandatory)][string] $Mac)
    $hex = ($Mac -replace '[:-]', '')
    if ($hex.Length -lt 2) { return $false }
    $first = [Convert]::ToInt32($hex.Substring(0, 2), 16)
    return (($first -band 0x02) -ne 0)
}

# ---- MAC → 제조사 (긴 접두사부터 조회) ----
function Get-Vendor {
    param(
        [Parameter(Mandatory)] $Oui,
        [Parameter(Mandatory)][string] $Mac
    )
    if (Test-RandomMac -Mac $Mac) {
        return [PSCustomObject]@{ Short = '(랜덤 MAC)'; Full = '(로컬 관리 / 랜덤 MAC)' }
    }
    if (-not $Oui.Loaded) {
        return [PSCustomObject]@{ Short = ''; Full = '' }
    }
    $hex = ($Mac -replace '[:-]', '').ToUpperInvariant()
    if ($hex.Length -ge 9 -and $Oui.P36.ContainsKey($hex.Substring(0, 9))) { return $Oui.P36[$hex.Substring(0, 9)] }
    if ($hex.Length -ge 7 -and $Oui.P28.ContainsKey($hex.Substring(0, 7))) { return $Oui.P28[$hex.Substring(0, 7)] }
    if ($hex.Length -ge 6 -and $Oui.P24.ContainsKey($hex.Substring(0, 6))) { return $Oui.P24[$hex.Substring(0, 6)] }
    return [PSCustomObject]@{ Short = '(미등록)'; Full = '(미등록 OUI)' }
}
'@

# 공유 함수를 메인 세션에 로드
. ([scriptblock]::Create($script:SharedFunctions))

# ============================================================
# 4) OUI(제조사) 테이블 로드 및 조회
# ============================================================
function Import-OuiTables {
    $result = [PSCustomObject]@{
        P24     = @{}
        P28     = @{}
        P36     = @{}
        Count   = 0
        Loaded  = $false
        Message = ''
    }
    if (-not (Test-Path -LiteralPath $script:OuiPath)) {
        $result.Message = 'OUI 목록 없음 (oui.txt)'
        return $result
    }
    try {
        $reader = New-Object System.IO.StreamReader($script:OuiPath, [System.Text.Encoding]::UTF8)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line.Length -lt 8) { continue }
                $parts = $line.Split('|')
                if ($parts.Count -lt 2) { continue }
                $prefix = $parts[0]
                $short = $parts[1]
                $full = if ($parts.Count -ge 3) { $parts[2] } else { $parts[1] }

                $slash = $prefix.IndexOf('/')
                $hex = ($prefix -replace '[:/-]', '').ToUpperInvariant()
                if ($slash -ge 0) {
                    $bits = [int]($prefix.Substring($slash + 1))
                    $hexBefore = ($prefix.Substring(0, $slash) -replace '[:-]', '').ToUpperInvariant()
                }
                else {
                    $bits = 24
                    $hexBefore = $hex
                }
                $obj = [PSCustomObject]@{ Short = $short; Full = $full }
                switch ($bits) {
                    36 { $result.P36[$hexBefore.Substring(0, 9)] = $obj }
                    28 { $result.P28[$hexBefore.Substring(0, 7)] = $obj }
                    default { if ($hexBefore.Length -ge 6) { $result.P24[$hexBefore.Substring(0, 6)] = $obj } }
                }
                $result.Count++
            }
        }
        finally { $reader.Close() }
        $result.Loaded = $true
        $result.Message = ("OUI {0:N0}건 로드됨" -f $result.Count)
    }
    catch {
        $result.Message = 'OUI 로드 실패'
    }
    return $result
}

# ============================================================
# 5) 대역(PrefixLength) 계산
# ============================================================
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
    if ($PrefixLength -ge 31) { $first = $network; $last = $broadcast }
    else { $first = [uint64]($network + 1); $last = [uint64]($broadcast - 1) }
    [PSCustomObject]@{
        Network      = ConvertFrom-IPUInt $network
        Broadcast    = ConvertFrom-IPUInt $broadcast
        FirstHost    = $first
        LastHost     = $last
        HostCount    = [uint64]($last - $first + 1)
        PrefixLength = $PrefixLength
    }
}

# ============================================================
# 6) 어댑터 / 대역 선택 메뉴 (방향키)
# ============================================================
function Get-AdapterMenuItems {
    $adapters = Get-NetAdapter | Sort-Object ifIndex
    $ipv4All = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($ad in $adapters) {
        $items.Add([PSCustomObject]@{
                IsHeader = $true
                Display  = ('■ {0}  [{1}]  {2}' -f $ad.Name, $ad.Status, $ad.InterfaceDescription)
                Value    = $null
            })
        $addrs = @($ipv4All | Where-Object { $_.InterfaceIndex -eq $ad.ifIndex })
        if ($addrs.Count -eq 0) {
            $items.Add([PSCustomObject]@{ IsHeader = $true; Display = '      (IPv4 주소 없음)'; Value = $null })
            continue
        }
        foreach ($a in $addrs) {
            $range = Get-ScanRange -IPAddress $a.IPAddress -PrefixLength $a.PrefixLength
            $display = ('{0}/{1}   ->  {2} ~ {3}  ({4} hosts)' -f `
                    $a.IPAddress, $a.PrefixLength, (ConvertFrom-IPUInt $range.FirstHost),
                (ConvertFrom-IPUInt $range.LastHost), $range.HostCount)
            $items.Add([PSCustomObject]@{
                    IsHeader = $false
                    Display  = $display
                    Value    = [PSCustomObject]@{
                        AdapterName = $ad.Name
                        IPAddress   = $a.IPAddress
                        Prefix      = $a.PrefixLength
                        Range       = $range
                        IfIndex     = $ad.ifIndex
                    }
                })
        }
    }
    return $items
}

function Read-MenuSelection {
    param(
        [Parameter(Mandatory)] $Items,
        [string] $Title = '스캔할 대역을 선택하세요  (↑/↓ 이동, Enter 선택, Esc 취소)',
        [int] $StartIndex = 0
    )
    $selectable = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        if (-not $Items[$i].IsHeader) { $selectable += $i }
    }
    if ($selectable.Count -eq 0) { return $null }

    $cursor = 0
    for ($i = 0; $i -lt $selectable.Count; $i++) {
        if ($selectable[$i] -eq $StartIndex) { $cursor = $i; break }
    }

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
                'DownArrow' { $cursor = ($cursor + 1) % $selectable.Count }
                'Enter' { return $Items[$selectable[$cursor]] }
                'Escape' { return $null }
            }
        }
    }
    finally { [System.Console]::CursorVisible = $prevVisible }
}

# 저장된 어댑터에 해당하는 항목 인덱스 찾기
function Find-SavedSelectionIndex {
    param($Items, [string] $AdapterName, [string] $IP)
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        if (-not $it.IsHeader -and $it.Value.AdapterName -eq $AdapterName -and $it.Value.IPAddress -eq $IP) {
            return $i
        }
    }
    return -1
}

# ============================================================
# 7) 스캔 로직 : 핑 스윕 / 이웃 조회 / 사이클
#    (백그라운드 런스페이스에서 실행)
# ============================================================
$script:ScanLoopBody = @'
param($AppState, $FuncDefs, $Oui)
. ([scriptblock]::Create($FuncDefs))

# 호스트 결과를 공유 상태에 병합 (루프 런스페이스 내부 함수)
function Merge-HostResult {
    param($AppState, $Res, $NewIps, $Oui)
    $ip = $Res.IP
    $existing = $AppState.Hosts[$ip]
    $ven = Get-Vendor -Oui $Oui -Mac $Res.MAC
    $now = Get-Date

    $state = 'active'
    $prevPorts = @()
    $firstSeen = $now
    $firstCycle = [int]$AppState.Cycle
    $history = New-Object System.Collections.ArrayList
    if ($existing) {
        $firstSeen = $existing.FirstSeen
        $firstCycle = $existing.FirstCycle
        $prevPorts = @($existing.Tcp)
        $history = $existing.History
    }
    if ($NewIps -contains $ip) { $state = 'new' }
    elseif ($existing -and (@(Compare-Object $prevPorts @($Res.Tcp)).Count -gt 0)) {
        $state = 'changed'
        $added = @(@($Res.Tcp) | Where-Object { $prevPorts -notcontains $_ })
        foreach ($p in $added) {
            [void]$history.Insert(0, ('{0}  TCP {1} 열림 (사이클 #{2})' -f $now.ToString('HH:mm:ss'), $p, [int]$AppState.Cycle))
        }
    }
    if (-not $existing) {
        [void]$history.Insert(0, ('{0}  최초 발견' -f $now.ToString('HH:mm:ss')))
    }

    $AppState.Hosts[$ip] = [PSCustomObject]@{
        IP         = $ip
        MAC        = $Res.MAC
        Vendor     = $ven.Short
        VendorFull = $ven.Full
        Names      = $Res.Names
        DnsVia     = $Res.DnsVia
        Group      = $Res.Group
        Udp        = $Res.Udp
        Tcp        = @($Res.Tcp)
        State      = $state
        FirstSeen  = $firstSeen
        FirstCycle = $firstCycle
        LastSeen   = $now
        History    = $history
    }
}

function Invoke-PingSweep {
    param([uint64]$First, [uint64]$Last, [int]$TimeoutMs, [int]$BatchSize, [hashtable]$Known)
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
        catch {}
        finally { foreach ($p in $pings) { $p.Dispose() } }
        Start-Sleep -Milliseconds 40
        $cur = $end + 1
    }
}

function Get-LiveNeighbor {
    param([uint64]$NetStart, [uint64]$NetEnd)
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $u = ConvertTo-IPUInt $_.IPAddress
        $u -ge $NetStart -and $u -le $NetEnd -and
        $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF'
    }
}

# 이름 조회 워커 스크립트블록 (호스트별 병렬)
$worker = {
    param($ip, $mac, $ports, $engine, $localIp, $dnsServers, $tcpTimeout, $udpTimeout, $funcDefs)
    . ([scriptblock]::Create($funcDefs))

    $reverse = Get-ReversePtrName -IPAddress $ip

    # raw UDP 프로브 (포트 판정 + LLMNR/NetBIOS/mDNS 이름, raw 모드는 DNS도)
    $probeDns = if ($engine -eq 'RawUdp') { $dnsServers } else { @() }
    $probe = Invoke-HostProbe -IP $ip -Reverse $reverse -TimeoutMs $udpTimeout -DnsServers $probeDns -Engine $engine -LocalIP $localIp

    $names = $probe.Names
    $group = $probe.Group
    $dnsVia = $null

    if ($engine -eq 'ResolveDnsName') {
        # DNS : Resolve-DnsName -DnsOnly (순수 DNS 프로토콜만).
        #       GetHostEntry 폴백은 제거함 — 그 결과는 실제로 LLMNR/NetBIOS 로 조회된
        #       이름일 수 있어 137/5355 프로브와 중복되고, DNS 로 라벨하면 부정확하다.
        try {
            $rec = Resolve-DnsName -Name $ip -DnsOnly -QuickTimeout -ErrorAction Stop
            $hit = $rec | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($hit) { $names.DNS = ($hit.NameHost -replace '\.$', ''); $dnsVia = 'DNS' }
        }
        catch {}
        # LLMNR : Resolve-DnsName -LlmnrOnly 는 사용하지 않는다.
        #         (Windows 가 멀티캐스트 조회로 mDNS 도 함께 보내 mDNS 이름이 섞임)
        #         이름은 Invoke-HostProbe 의 raw LLMNR 결과만 사용한다.
        # NetBIOS : nbtstat, 실패 시 프로브 결과 유지
        if (-not $names.NetBIOS) {
            try {
                $nb = nbtstat -A $ip 2>$null
                $line = $nb | Where-Object { $_ -match '<00>\s+UNIQUE\s+Registered' } | Select-Object -First 1
                if ($line) { $names.NetBIOS = ($line -replace '\s*<00>.*$', '').Trim() }
            }
            catch {}
        }
    }
    else {
        $dnsVia = if ($names.DNS) { 'DNS' } else { $null }
    }

    # 포트 스캔 (TCP 병렬)
    $openTcp = @(Invoke-TcpScan -IP $ip -Ports $ports -TimeoutMs $tcpTimeout)

    [PSCustomObject]@{
        IP     = $ip
        MAC    = $mac
        Names  = $names
        DnsVia = $dnsVia
        Group  = $group
        Udp    = $probe.Udp
        Tcp    = $openTcp
    }
}

# --- 스캔 루프 본체 ---
try {
    while (-not $AppState.Quit) {
        if ($AppState.Paused) { Start-Sleep -Milliseconds 200; continue }

        $cfg = $AppState.Config
        $range = $AppState.Range
        $netStart = ConvertTo-IPUInt $range.Network
        $netEnd = ConvertTo-IPUInt $range.Broadcast

        # flush 판단
        $now = Get-Date
        $doFlush = $false
        if ($AppState.FlushNow -or $null -eq $AppState.NextFlushAt -or $now -ge $AppState.NextFlushAt) {
            $doFlush = $true
        }
        $AppState.FlushNow = $false

        $AppState.Cycle = [int]$AppState.Cycle + 1
        $AppState.Phase = 'Ping Sweep'
        $AppState.Progress = 0
        $AppState.ProgressTotal = 0

        if ($doFlush) {
            $AppState.Phase = 'ARP flush'
            try { arp -d * 2>$null | Out-Null } catch {}
            $AppState.NextFlushAt = $now.AddMinutes([int]$cfg.FlushMin)
            $rounds = [int]$cfg.SweepAfterFlush
        }
        else {
            $rounds = [int]$cfg.SweepNormal
        }

        # 핑 스윕
        $AppState.Phase = 'Ping Sweep'
        $known = @{}
        for ($r = 1; $r -le $rounds; $r++) {
            if ($AppState.Quit) { break }
            $AppState.SweepRound = $r
            $AppState.SweepTotal = $rounds
            Invoke-PingSweep -First $range.FirstHost -Last $range.LastHost `
                -TimeoutMs ([int]$cfg.PingTimeoutMs) -BatchSize 64 -Known $known
            Start-Sleep -Milliseconds 400
            foreach ($n in (Get-LiveNeighbor -NetStart $netStart -NetEnd $netEnd)) {
                if (-not $known.ContainsKey($n.IPAddress)) { $known[$n.IPAddress] = $n }
            }
        }
        if ($AppState.Quit) { break }

        $live = @($known.Values)
        $liveIps = @($live | ForEach-Object { $_.IPAddress })

        # 신규 / 이탈 판정
        $prevIps = @(Get-HostKeysSnapshot -Hosts $AppState.Hosts)
        $newIps = @($liveIps | Where-Object { $prevIps -notcontains $_ })
        $leftIps = @($prevIps | Where-Object { $liveIps -notcontains $_ })
        $AppState.CountNew = $newIps.Count
        $AppState.CountLeft = $leftIps.Count

        # 이탈 호스트 상태 표시(다음 사이클에 제거)
        foreach ($ip in $prevIps) {
            $h = $AppState.Hosts[$ip]
            if ($null -eq $h) { continue }
            if ($leftIps -contains $ip) {
                if ($h.State -eq 'left') { $AppState.Hosts.Remove($ip) }
                else { $h.State = 'left' }
            }
        }

        # 이름/포트 병렬 스캔
        $AppState.Phase = '이름/포트 스캔'
        $AppState.Progress = 0
        $AppState.ProgressTotal = $live.Count

        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $pool = [runspacefactory]::CreateRunspacePool(1, 32, $iss, $Host)
        $pool.Open()
        $jobs = New-Object System.Collections.ArrayList
        foreach ($n in $live) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($worker.ToString()).
                AddArgument($n.IPAddress).
                AddArgument($n.LinkLayerAddress).
                AddArgument($AppState.TcpPorts).
                AddArgument($cfg.Engine).
                AddArgument($AppState.Selection.IPAddress).
                AddArgument($AppState.DnsServers).
                AddArgument([int]$cfg.TcpTimeoutMs).
                AddArgument([int]$cfg.UdpTimeoutMs).
                AddArgument($FuncDefs)
            [void]$jobs.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }

        $pending = [System.Collections.ArrayList]@($jobs)
        while ($pending.Count -gt 0 -and -not $AppState.Quit) {
            for ($i = $pending.Count - 1; $i -ge 0; $i--) {
                if ($pending[$i].Handle.IsCompleted) {
                    $res = $null
                    try { $res = $pending[$i].PS.EndInvoke($pending[$i].Handle) | Select-Object -First 1 } catch {}
                    $pending[$i].PS.Dispose()
                    [void]$pending.RemoveAt($i)
                    $AppState.Progress = [int]$AppState.Progress + 1
                    if ($res) { Merge-HostResult -AppState $AppState -Res $res -NewIps $newIps -Oui $Oui }
                }
            }
            Start-Sleep -Milliseconds 30
        }
        try { $pool.Close(); $pool.Dispose() } catch {}

        $AppState.Phase = '완료'
        $AppState.LastComplete = Get-Date
        $AppState.Found = $AppState.Hosts.Count

        # 재스캔 대기 (Quit/RescanNow/FlushNow 로 조기 종료)
        $AppState.NextScanAt = (Get-Date).AddSeconds([int]$cfg.RescanSec)
        while ((Get-Date) -lt $AppState.NextScanAt -and -not $AppState.Quit -and -not $AppState.RescanNow -and -not $AppState.FlushNow) {
            if ($AppState.Paused) { $AppState.NextScanAt = (Get-Date).AddSeconds([int]$AppState.Config.RescanSec) }
            Start-Sleep -Milliseconds 150
        }
        $AppState.RescanNow = $false
    }
}
catch {
    $AppState.WorkerError = $_.Exception.Message
}
'@

# ============================================================
# 8) 렌더링 (메인 스레드)
# ============================================================
function Write-Line {
    param([int]$Row, [string]$Text, [System.ConsoleColor]$Color = 'Gray', [System.ConsoleColor]$BackgroundColor = 'Black')
    # 콘솔 크기 조정 중에는 Row 가 버퍼 범위를 벗어날 수 있으므로 방어한다.
    try {
        if ($Row -lt 0 -or $Row -ge [Console]::BufferHeight) { return }
        $w = [Console]::BufferWidth - 1
        if ($w -lt 1) { return }
        $disp = Format-Cell -Text $Text -Width $w
        [Console]::SetCursorPosition(0, $Row)
        $prev = [Console]::ForegroundColor
        [Console]::ForegroundColor = $Color
        $prevBg = [Console]::BackgroundColor
        [Console]::BackgroundColor = $BackgroundColor
        [Console]::Write($disp)
        [Console]::ForegroundColor = $prev
        [Console]::BackgroundColor = $prevBg
    }
    catch { }
}

function Format-MethodString {
    param($HostObj, [int]$MaxWidth)
    $parts = New-Object System.Collections.Generic.List[string]
    # DNS
    if ($HostObj.Names.DNS) {
        $tag = 'DNS'
        if ($HostObj.Udp[53] -eq 'open') { $tag += '(53)' }
        $parts.Add($tag)
    }
    elseif ($HostObj.Udp[53] -eq 'open') { $parts.Add('DNS(53)') }
    # LLMNR
    if ($HostObj.Names.LLMNR -or $HostObj.Udp[5355] -eq 'open') {
        $t = 'LLMNR'; if ($HostObj.Udp[5355] -eq 'open') { $t += '(5355)' }; $parts.Add($t)
    }
    # NetBIOS (약칭 없이 전체 표기)
    if ($HostObj.Names.NetBIOS -or $HostObj.Udp[137] -eq 'open') {
        $t = 'NetBIOS'; if ($HostObj.Udp[137] -eq 'open') { $t += '(137)' }; $parts.Add($t)
    }
    # mDNS
    if ($HostObj.Names.mDNS -or $HostObj.Udp[5353] -eq 'open') {
        $t = 'mDNS'; if ($HostObj.Udp[5353] -eq 'open') { $t += '(5353)' }; $parts.Add($t)
    }
    if ($parts.Count -eq 0) { return '-' }

    # 폭 초과 시 앞부분만 보이고 +N
    $full = $parts -join ', '
    if ((Get-DisplayWidth -Text $full) -le $MaxWidth) { return $full }
    $shown = New-Object System.Collections.Generic.List[string]
    $rest = $parts.Count
    foreach ($p in $parts) {
        $cand = (($shown + $p) -join ', ') + (' +{0}' -f ($rest - $shown.Count - 1))
        if ((Get-DisplayWidth -Text $cand) -gt $MaxWidth -and $shown.Count -gt 0) { break }
        $shown.Add($p);
        if ((Get-DisplayWidth -Text (($shown -join ', '))) -gt $MaxWidth) { $shown.RemoveAt($shown.Count - 1); break }
    }
    $remain = $parts.Count - $shown.Count
    if ($remain -gt 0) { return (($shown -join ', ') + (' +{0}' -f $remain)) }
    return ($shown -join ', ')
}

function Format-NameString {
    param($HostObj)
    $segs = New-Object System.Collections.Generic.List[string]
    if ($HostObj.Names.DNS) { $segs.Add(('{0}(DNS)' -f $HostObj.Names.DNS)) }
    if ($HostObj.Names.LLMNR) { $segs.Add(('{0}(LLMNR)' -f $HostObj.Names.LLMNR)) }
    if ($HostObj.Names.NetBIOS) { $segs.Add(('{0}(NetBIOS)' -f $HostObj.Names.NetBIOS)) }
    if ($HostObj.Names.mDNS) { $segs.Add(('{0}(mDNS)' -f $HostObj.Names.mDNS)) }
    if ($segs.Count -eq 0) { return '(Unknown)' }
    return ($segs -join ' / ')
}

function Get-SortedHostIps {
    <#
        화면 표시용 IP 목록 (정렬 + 필터 적용).
        목록/상세/검색이 모두 이 목록을 기준으로 인덱스를 쓰므로 필터는 여기서 한 번만 적용한다.
        -All 이면 필터를 무시한다.
        주의: 결과가 1건이면 문자열 스칼라로 풀리므로 호출부에서 반드시 @( ) 로 감쌀 것.
    #>
    param($AppState, [switch]$All)
    $ips = @(Get-HostKeysSnapshot -Hosts $AppState.Hosts)
    $sorted = switch ($AppState.SortMode) {
        'Name' { @($ips | Sort-Object { $h = $AppState.Hosts[$_]; Format-NameString -HostObj $h }) }
        'Vendor' { @($ips | Sort-Object { $AppState.Hosts[$_].Vendor }) }
        default { @($ips | Sort-Object { [uint64](ConvertTo-IPUInt $_) }) }
    }
    $sorted = @($sorted)
    if ($All -or [string]::IsNullOrWhiteSpace($AppState.FilterQuery)) { return $sorted }
    $filtered = New-Object System.Collections.Generic.List[string]
    foreach ($ip in $sorted) {
        if (Test-HostMatch -HostObj $AppState.Hosts[$ip] -Query $AppState.FilterQuery -ServiceNames $AppState.ServiceNames) {
            $filtered.Add($ip)
        }
    }
    return $filtered.ToArray()
}

function Get-CursorHostIp {
    <# 현재 커서가 가리키는 호스트 IP (없으면 $null) #>
    param($AppState)
    $ips = @(Get-SortedHostIps -AppState $AppState)
    $c = [int]$AppState.Cursor
    if ($c -ge 0 -and $c -lt $ips.Count) { return $ips[$c] }
    return $null
}

function Set-CursorToHostIp {
    <# 지정 IP 가 현재(필터 적용) 목록에 있으면 그 위치로, 없으면 맨 위로 커서 이동 #>
    param($AppState, [string]$Ip)
    $ips = @(Get-SortedHostIps -AppState $AppState)
    $idx = -1
    if ($Ip) { $idx = [Array]::IndexOf([string[]]$ips, $Ip) }
    $AppState.Cursor = if ($idx -ge 0) { $idx } else { 0 }
    $AppState.ScrollTop = 0   # 렌더링 시 커서가 보이도록 다시 계산됨
}

function Update-FilterLive {
    <# 필터 입력 중 : 입력값을 즉시 적용하고 기준 호스트에 커서 유지 #>
    param($AppState)
    $AppState.FilterQuery = $AppState.FilterBuffer.Trim()
    Set-CursorToHostIp -AppState $AppState -Ip $AppState.FilterAnchorIp
}

function Format-Countdown {
    param($Target)
    if ($null -eq $Target) { return '--:--' }
    $span = $Target - (Get-Date)
    if ($span.TotalSeconds -lt 0) { $span = [TimeSpan]::Zero }
    return ('{0:00}:{1:00}' -f [int]$span.TotalMinutes, $span.Seconds)
}

function Show-Dashboard {
    param($AppState, [ValidateSet('', 'search', 'filter')][string]$InputMode = '')
    $width = [Console]::BufferWidth
    $height = [Math]::Min([Console]::WindowHeight, [Console]::BufferHeight)

    # 열 폭 정의 (표시폭 기준)
    $colState = 4; $colIp = 16; $colTcp = 18; $colVendor = 13; $colMac = 17
    # 선두 3칸 + 열 사이 공백 5칸 = 8칸 고정
    $reserved = $colState + $colIp + $colTcp + $colVendor + $colMac + 8
    $flex = $width - 1 - $reserved           # 이름 + Method 가 나눠 쓰는 폭
    $colMethodMax = [Math]::Min(24, [Math]::Max(12, $flex - 14))
    $colName = [Math]::Max(8, $flex - $colMethodMax)
    if (($colName + $colMethodMax) -gt $flex -and $flex -gt 16) { $colMethodMax = $flex - $colName }

    $sel = $AppState.Selection
    $header = ' NetScan v4   {0} ({1})   {2} ~ {3} (/{4}, {5} hosts)   엔진: {6}' -f `
        $sel.AdapterName, $AppState.AdapterDesc, (ConvertFrom-IPUInt $AppState.Range.FirstHost),
    (ConvertFrom-IPUInt $AppState.Range.LastHost), $AppState.Range.PrefixLength,
    $AppState.Range.HostCount, $AppState.Config.Engine
    Write-Line -Row 0 -Text $header -Color Cyan
    Write-Line -Row 1 -Text ('─' * ($width - 1)) -Color DarkGray

    # 상태 영역
    $frames = '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'
    $spin = $frames[$AppState.SpinIndex % 10]
    if ($AppState.Paused) {
        $statusLine = ' 사이클 #{0}  일시정지' -f $AppState.Cycle
    }
    elseif ($AppState.Phase -eq '완료') {
        $statusLine = ' 사이클 #{0}  대기 중' -f $AppState.Cycle
    }
    else {
        $bar = ''
        if ([int]$AppState.ProgressTotal -gt 0) {
            $ratio = [double]$AppState.Progress / [double]$AppState.ProgressTotal
            $filled = [int]($ratio * 20)
            $bar = ('█' * $filled) + ('░' * (20 - $filled)) + (' {0}/{1}' -f $AppState.Progress, $AppState.ProgressTotal)
        }
        elseif ($AppState.Phase -eq 'Ping Sweep') {
            $bar = '스윕 {0}/{1}' -f $AppState.SweepRound, $AppState.SweepTotal
        }
        $statusLine = ' 사이클 #{0}  {1} {2}  [{3}]  {4}' -f $AppState.Cycle, $spin, '스캔 중', $AppState.Phase, $bar
    }
    $counts = '발견: {0}   신규: {1}   이탈: {2}' -f $AppState.Found, $AppState.CountNew, $AppState.CountLeft
    $line2 = Format-Cell -Text $statusLine -Width ($width - 1 - (Get-DisplayWidth $counts) - 1)
    Write-Line -Row 2 -Text ($line2 + $counts) -Color White

    $nextScan = if ($AppState.Paused) { '정지' } elseif ($AppState.Phase -ne '완료') { '-' } else { Format-Countdown $AppState.NextScanAt }
    $lastDone = if ($AppState.LastComplete) { $AppState.LastComplete.ToString('HH:mm:ss') } else { '-' }
    $line3 = ' 다음 스캔: {0}      ARP flush까지: {1}      마지막 완료: {2}' -f $nextScan, (Format-Countdown $AppState.NextFlushAt), $lastDone
    Write-Line -Row 3 -Text $line3 -Color DarkGray
    Write-Line -Row 4 -Text ('─' * ($width - 1)) -Color DarkGray

    # 테이블 헤더 (데이터 행의 접두 폭 3칸에 맞춤)
    $hrow = '   ' +
    (Format-Cell '' $colState) + (Format-Cell 'IP' $colIp) + ' ' +
    (Format-Cell '이름' $colName) + ' ' + (Format-Cell 'Method' $colMethodMax) + ' ' +
    (Format-Cell 'TCP 포트' $colTcp) + ' ' + (Format-Cell '제조사' $colVendor) + ' ' +
    (Format-Cell 'MAC' $colMac)
    Write-Line -Row 5 -Text $hrow -Color Yellow
    Write-Line -Row 6 -Text ('─' * ($width - 1)) -Color DarkGray

    # 본문
    $topRow = 7
    $footRows = 3
    $maxRows = $height - $topRow - $footRows
    if ($maxRows -lt 1) { $maxRows = 1 }

    $ips = @(Get-SortedHostIps -AppState $AppState)
    $total = $ips.Count
    if ($AppState.Cursor -ge $total) { $AppState.Cursor = [Math]::Max(0, $total - 1) }
    # 스크롤 오프셋
    if ($AppState.Cursor -lt $AppState.ScrollTop) { $AppState.ScrollTop = $AppState.Cursor }
    if ($AppState.Cursor -ge $AppState.ScrollTop + $maxRows) { $AppState.ScrollTop = $AppState.Cursor - $maxRows + 1 }
    $start = $AppState.ScrollTop
    $end = [Math]::Min($total, $start + $maxRows)

    $row = $topRow
    for ($idx = $start; $idx -lt $end; $idx++) {
        $ip = $ips[$idx]
        $h = $AppState.Hosts[$ip]
        if ($null -eq $h) { continue }
        $cursorMark = if ($idx -eq $AppState.Cursor) { '▶' } else { ' ' }
        $stateMark = switch ($h.State) { 'new' { ' ● ' } 'changed' { ' ▲ ' } 'left' { ' ○ ' } default { '   ' } }
        $tcpStr = if ($h.Tcp.Count -gt 0) { ($h.Tcp -join ',') } else { '-' }
        $method = Format-MethodString -HostObj $h -MaxWidth $colMethodMax
        $name = Format-NameString -HostObj $h

        $lineText = ' ' + $cursorMark + ' ' +
        (Format-Cell $stateMark $colState) + (Format-Cell $ip $colIp) + ' ' +
        (Format-Cell $name $colName) + ' ' + (Format-Cell $method $colMethodMax) + ' ' +
        (Format-Cell $tcpStr $colTcp) + ' ' + (Format-Cell $h.Vendor $colVendor) + ' ' +
        (Format-Cell $h.MAC $colMac)

        if ($idx -eq $AppState.Cursor) {
            $color = [System.ConsoleColor]::Black
            $bgColor = [System.ConsoleColor]::DarkCyan
        }
        else {
            $color = switch ($h.State) {
                'new' { [System.ConsoleColor]::Green }
                'changed' { [System.ConsoleColor]::Yellow }
                'left' { [System.ConsoleColor]::DarkGray }
                default { [System.ConsoleColor]::Gray }
            }
            $bgColor = [System.ConsoleColor]::Black
        }
        Write-Line -Row $row -Text $lineText -Color $color -BackgroundColor $bgColor
        $row++
    }
    # 남은 줄 지우기
    while ($row -lt ($topRow + $maxRows)) { Write-Line -Row $row -Text '' ; $row++ }

    # 하단
    $footTop = $height - $footRows
    Write-Line -Row $footTop -Text ('─' * ($width - 1)) -Color DarkGray
    $info = ' {0}    ({1}/{2} 표시)  (●: 신규, ▲: 갱신, ○: 이탈)   정렬: {3}' -f $AppState.OuiMessage, ([Math]::Min($maxRows, $total)), $total, $AppState.SortMode
    if ($InputMode -ne 'filter' -and $AppState.FilterQuery) {
        $info += ('   필터: "{0}" ({1}/{2})' -f $AppState.FilterQuery, $total, $AppState.Hosts.Count)
    }
    Write-Line -Row ($footTop + 1) -Text $info -Color DarkCyan
    if ($InputMode -eq 'search') {
        Show-SearchBar -AppState $AppState -Row ($footTop + 2) -Ips $ips
    }
    elseif ($InputMode -eq 'filter') {
        Show-FilterBar -AppState $AppState -Row ($footTop + 2) -Ips $ips
    }
    else {
        $keys = ' [F2]설정  [F3]검색  [F4]필터  [R]즉시 재스캔  [F5]ARP flush  [P]일시정지  [F6]정렬  [↑↓]이동  [Enter]상세  [F10]종료'
        Write-Line -Row ($footTop + 2) -Text $keys -Color Gray
    }
}

# ============================================================
# 8-1) 검색 (F3) / 필터 (F4) 공용 일치 판정
#      대상 : IP(부분 일치) / 이름(DNS·LLMNR·NetBIOS·mDNS 부분 일치)
#             / MAC(구분자 무시) / 제조사(약칭·정식명)
#             / TCP 포트(숫자는 포트 번호 정확 일치, 문자는 서비스명 부분 일치)
#      대소문자 구분 없음.
#      검색은 커서 이동으로, 필터는 목록 축소로 반영한다. 검색은 필터 결과 안에서만 수행.
# ============================================================
function Test-HostMatch {
    param($HostObj, [string]$Query, $ServiceNames)
    if ($null -eq $HostObj) { return $false }
    $q = ([string]$Query).Trim().ToLowerInvariant()
    if ($q.Length -eq 0) { return $false }

    # IP
    if ($HostObj.IP -and $HostObj.IP.Contains($q)) { return $true }

    # 이름 (DNS / LLMNR / NetBIOS / mDNS)
    if ($HostObj.Names) {
        foreach ($nk in 'DNS', 'LLMNR', 'NetBIOS', 'mDNS') {
            $nv = $HostObj.Names[$nk]
            if ($nv -and ([string]$nv).ToLowerInvariant().Contains($q)) { return $true }
        }
    }

    # MAC (':' '-' '.' 공백 무시)
    $qHex = $q -replace '[:\-\.\s]', ''
    if ($qHex.Length -gt 0 -and $HostObj.MAC) {
        $macHex = ($HostObj.MAC -replace '[:\-]', '').ToLowerInvariant()
        if ($macHex.Contains($qHex)) { return $true }
    }

    # 제조사
    if ($HostObj.Vendor -and $HostObj.Vendor.ToLowerInvariant().Contains($q)) { return $true }
    if ($HostObj.VendorFull -and $HostObj.VendorFull.ToLowerInvariant().Contains($q)) { return $true }

    # TCP 포트
    $tcp = @($HostObj.Tcp)
    if ($tcp.Count -gt 0) {
        if ($q -match '^\d+$') {
            $num = 0
            if ([int]::TryParse($q, [ref]$num) -and ($tcp -contains $num)) { return $true }
        }
        else {
            foreach ($p in $tcp) {
                if ($ServiceNames.ContainsKey([int]$p) -and $ServiceNames[[int]$p].ToLowerInvariant().Contains($q)) { return $true }
            }
        }
    }
    return $false
}

function Get-SearchMatchIndexes {
    <# 정렬된 IP 목록 기준으로 일치하는 인덱스 목록을 반환 #>
    param($AppState, [string]$Query, $Ips)
    $result = New-Object System.Collections.Generic.List[int]
    if ([string]::IsNullOrWhiteSpace($Query)) { return , $result }
    for ($i = 0; $i -lt $Ips.Count; $i++) {
        if (Test-HostMatch -HostObj $AppState.Hosts[$Ips[$i]] -Query $Query -ServiceNames $AppState.ServiceNames) {
            $result.Add($i)
        }
    }
    return , $result
}

function Find-SearchMatch {
    <#
        StartIndex 기준으로 다음(Direction=1) 또는 이전(Direction=-1) 일치 인덱스를 찾는다.
        IncludeStart 이면 StartIndex 자체도 후보로 본다. 끝에 닿으면 반대쪽으로 순환.
        일치 없음 : -1
    #>
    param($AppState, [string]$Query, [int]$StartIndex, [int]$Direction = 1, [switch]$IncludeStart)
    $ips = @(Get-SortedHostIps -AppState $AppState)
    $found = Get-SearchMatchIndexes -AppState $AppState -Query $Query -Ips $ips
    if ($found.Count -eq 0) { return -1 }
    if ($Direction -ge 0) {
        foreach ($m in $found) {
            if ($m -gt $StartIndex -or ($IncludeStart -and $m -eq $StartIndex)) { return $m }
        }
        return $found[0]
    }
    for ($k = $found.Count - 1; $k -ge 0; $k--) {
        $m = $found[$k]
        if ($m -lt $StartIndex -or ($IncludeStart -and $m -eq $StartIndex)) { return $m }
    }
    return $found[$found.Count - 1]
}

function Write-At {
    <# 지정 열/행에 색상 문자열 출력 (화면 폭 초과분은 자름) #>
    param([int]$Col, [int]$Row, [string]$Text, [System.ConsoleColor]$Color = 'Gray')
    try {
        if ($Row -lt 0 -or $Row -ge [Console]::BufferHeight) { return }
        $avail = [Console]::BufferWidth - 1 - $Col
        if ($avail -lt 1) { return }
        if ((Get-DisplayWidth -Text $Text) -gt $avail) { $Text = Format-Cell -Text $Text -Width $avail }
        [Console]::SetCursorPosition($Col, $Row)
        $prev = [Console]::ForegroundColor
        [Console]::ForegroundColor = $Color
        [Console]::Write($Text)
        [Console]::ForegroundColor = $prev
    }
    catch { }
}

function Show-SearchBar {
    <# 하단 키 안내 줄 자리에 검색 입력창 + 일치 현황 표시 #>
    param($AppState, [int]$Row, $Ips)
    $found = Get-SearchMatchIndexes -AppState $AppState -Query $AppState.SearchBuffer -Ips $Ips
    $left = ' 검색: {0}_   ' -f $AppState.SearchBuffer
    if ([string]::IsNullOrWhiteSpace($AppState.SearchBuffer)) {
        $status = '(IP / 이름 / MAC / 제조사 / TCP 포트)'
        $statusColor = [System.ConsoleColor]::DarkGray
    }
    elseif ($found.Count -eq 0) {
        $status = '일치 없음'
        $statusColor = [System.ConsoleColor]::Red
    }
    else {
        $pos = $found.IndexOf([int]$AppState.Cursor)
        $posText = if ($pos -ge 0) { [string]($pos + 1) } else { '-' }
        $status = '일치 {0}/{1}' -f $posText, $found.Count
        $statusColor = [System.ConsoleColor]::Green
    }
    $hint = '   [F3/↓]다음  [Shift+F3/↑]이전  [Enter]확정  [Esc]취소'

    Write-Line -Row $Row -Text ($left + $status + $hint) -Color White
    $col = Get-DisplayWidth -Text $left
    Write-At -Col $col -Row $Row -Text $status -Color $statusColor
    Write-At -Col ($col + (Get-DisplayWidth -Text $status)) -Row $Row -Text $hint -Color DarkGray
}

function Show-FilterBar {
    <# 하단 키 안내 줄 자리에 필터 입력창 + 표시 건수 #>
    param($AppState, [int]$Row, $Ips)
    $allCount = $AppState.Hosts.Count
    $shown = @($Ips).Count
    $left = ' 필터: {0}_   ' -f $AppState.FilterBuffer
    if ([string]::IsNullOrWhiteSpace($AppState.FilterBuffer)) {
        $status = '(IP / 이름 / MAC / 제조사 / TCP 포트)  전체 {0}' -f $allCount
        $statusColor = [System.ConsoleColor]::DarkGray
    }
    elseif ($shown -eq 0) {
        $status = '표시 0/{0}' -f $allCount
        $statusColor = [System.ConsoleColor]::Red
    }
    else {
        $status = '표시 {0}/{1}' -f $shown, $allCount
        $statusColor = [System.ConsoleColor]::Green
    }
    $hint = '   [↑↓]이동  [Enter]적용(빈 값=해제)  [Esc]취소'

    Write-Line -Row $Row -Text ($left + $status + $hint) -Color White
    $col = Get-DisplayWidth -Text $left
    Write-At -Col $col -Row $Row -Text $status -Color $statusColor
    Write-At -Col ($col + (Get-DisplayWidth -Text $status)) -Row $Row -Text $hint -Color DarkGray
}

function Show-Settings {
    param($AppState)
    $width = [Console]::BufferWidth
    Write-Line -Row 0 -Text (' NetScan v4 ─ 설정          저장 위치: %ProgramData%\NetScan\scan_tool.config.json') -Color Cyan
    Write-Line -Row 1 -Text ('─' * ($width - 1)) -Color DarkGray

    $rows = $AppState.SettingsRows
    $row = 3
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $item = $rows[$i]
        $mark = if ($i -eq $AppState.SettingsCursor) { '▶' } else { ' ' }
        if ($item.Type -eq 'adapter') {
            $sel = $AppState.Selection
            $val = '{0}  {1}/{2}' -f $sel.AdapterName, $sel.IPAddress, $sel.Prefix
            $text = ' {0}  {1,-26} {2,-38} [Enter] 목록에서 선택' -f $mark, $item.Label, $val
        }
        elseif ($item.Type -eq 'engine') {
            $val = '◀ {0} ▶' -f $AppState.EditConfig.Engine
            $text = ' {0}  {1,-26} {2,-38} mDNS는 항상 raw UDP' -f $mark, $item.Label, $val
        }
        else {
            $meta = $item.Meta
            $changed = if ([int]$AppState.EditConfig.($meta.Key) -ne [int]$AppState.Config.($meta.Key)) { '*' } else { ' ' }
            $val = '{0} ◀ {1} ▶ {2}' -f $changed, $AppState.EditConfig.($meta.Key), $meta.Unit
            $hint = '범위 {0} ~ {1}  (기본 {2})' -f $meta.Min, $meta.Max, $meta.Default
            $text = ' {0}  {1,-26} {2,-24} {3}' -f $mark, $meta.Label, $val, $hint
        }
        $color = if ($i -eq $AppState.SettingsCursor) { [System.ConsoleColor]::White } else { [System.ConsoleColor]::Gray }
        Write-Line -Row $row -Text $text -Color $color
        $row++
    }

    $height = [Math]::Min([Console]::WindowHeight, [Console]::BufferHeight)
    Write-Line -Row ($height - 3) -Text ('─' * ($width - 1)) -Color DarkGray
    Write-Line -Row ($height - 2) -Text (' 스캔은 백그라운드에서 계속 진행 중 (사이클 #{0})' -f $AppState.Cycle) -Color DarkCyan
    Write-Line -Row ($height - 1) -Text ' [↑↓]이동  [←→]값 변경  [Enter]직접 입력/어댑터  [D]기본값  [F10]저장 후 닫기  [Esc]취소' -Color Gray
}

function Show-Detail {
    param($AppState)
    $width = [Console]::BufferWidth
    $h = $AppState.DetailHost
    Write-Line -Row 0 -Text ' NetScan v4 ─ 호스트 상세                                        [Esc] 목록으로' -Color Cyan
    Write-Line -Row 1 -Text ('─' * ($width - 1)) -Color DarkGray
    if ($null -eq $h) {
        Write-Line -Row 3 -Text '  (호스트 정보 없음)' -Color DarkGray
        return
    }
    $row = 3
    Write-Line -Row $row -Text ('  IP 주소      {0}' -f $h.IP) -Color Gray; $row++
    Write-Line -Row $row -Text ('  MAC 주소     {0}' -f $h.MAC) -Color Gray; $row++
    Write-Line -Row $row -Text ('  제조사       {0}' -f $h.VendorFull) -Color Gray; $row++
    $stat = '온라인'; if ($h.State -eq 'left') { $stat = '이탈' }
    Write-Line -Row $row -Text ('  상태         {0}    최초 발견 {1} (사이클 #{2})    마지막 응답 {3}' -f `
            $stat, $h.FirstSeen.ToString('HH:mm:ss'), $h.FirstCycle, $h.LastSeen.ToString('HH:mm:ss')) -Color Gray
    $row += 2

    Write-Line -Row $row -Text '  이름 조회                                          UDP 포트' -Color Yellow; $row++
    $udpText = @{
        53   = Get-UdpVerdictText $h.Udp[53]
        5355 = Get-UdpVerdictText $h.Udp[5355]
        137  = Get-UdpVerdictText $h.Udp[137]
        5353 = Get-UdpVerdictText $h.Udp[5353]
    }
    $dnsName = if ($h.Names.DNS) { $h.Names.DNS } else { '-' }
    $llName = if ($h.Names.LLMNR) { $h.Names.LLMNR } else { '-' }
    $nbName = if ($h.Names.NetBIOS) { $h.Names.NetBIOS } else { '-' }
    if ($h.Group) { $nbName += ('   워크그룹: {0}' -f $h.Group) }
    $mdName = if ($h.Names.mDNS) { $h.Names.mDNS } else { '-' }
    Write-Line -Row $row -Text ('    DNS      {0}' -f (Format-Cell $dnsName 40) + ('53/udp    {0}' -f $udpText[53])) -Color Gray; $row++
    Write-Line -Row $row -Text ('    LLMNR    {0}' -f (Format-Cell $llName 40) + ('5355/udp  {0}' -f $udpText[5355])) -Color Gray; $row++
    Write-Line -Row $row -Text ('    NetBIOS  {0}' -f (Format-Cell $nbName 40) + ('137/udp   {0}' -f $udpText[137])) -Color Gray; $row++
    Write-Line -Row $row -Text ('    mDNS     {0}' -f (Format-Cell $mdName 40) + ('5353/udp  {0}' -f $udpText[5353])) -Color Gray; $row += 2

    Write-Line -Row $row -Text ('  TCP 포트 (열림 {0} / 검사 {1})' -f $h.Tcp.Count, $AppState.TcpPorts.Count) -Color Yellow; $row++
    if ($h.Tcp.Count -gt 0) {
        $portTexts = foreach ($p in $h.Tcp) {
            $svc = if ($AppState.ServiceNames.ContainsKey([int]$p)) { $AppState.ServiceNames[[int]$p] } else { '' }
            ('{0} {1}' -f $p, $svc).Trim()
        }
        Write-Line -Row $row -Text ('    ' + ($portTexts -join '   ')) -Color Gray; $row++
    }
    else { Write-Line -Row $row -Text '    (열린 포트 없음)' -Color DarkGray; $row++ }
    $row++

    Write-Line -Row $row -Text '  변경 이력' -Color Yellow; $row++
    $shown = 0
    foreach ($ev in $h.History) {
        if ($shown -ge 6) { break }
        Write-Line -Row $row -Text ('    ' + $ev) -Color DarkGray; $row++; $shown++
    }
}

function Get-UdpVerdictText {
    param([string]$Verdict)
    switch ($Verdict) {
        'open' { return '열림' }
        'closed' { return '닫힘 (ICMP Unreachable)' }
        default { return '불명 (무응답)' }
    }
}

# ============================================================
# 9) 시작 : 설정/OUI 로드, 어댑터 선택, 상태 초기화
# ============================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$config = Import-ScanConfig
$oui = Import-OuiTables

Write-Host $oui.Message -ForegroundColor DarkCyan
Start-Sleep -Milliseconds 300

$menuItems = Get-AdapterMenuItems
$startIdx = Find-SavedSelectionIndex -Items $menuItems -AdapterName $config.AdapterName -IP $config.AdapterIP
if ($startIdx -lt 0) { $startIdx = 0 }
$selected = Read-MenuSelection -Items $menuItems -StartIndex $startIdx
if (-not $selected) { Write-Host '선택이 취소되었습니다.' -ForegroundColor Yellow; return }

$selValue = $selected.Value
$config.AdapterName = $selValue.AdapterName
$config.AdapterIP = $selValue.IPAddress
[void](Export-ScanConfig -Config $config)

# 선택 어댑터의 DNS 서버 목록
$dnsServers = @()
try {
    $dnsServers = @((Get-DnsClientServerAddress -InterfaceIndex $selValue.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
}
catch {}

$adapterDesc = ''
try { $adapterDesc = (Get-NetAdapter -Name $selValue.AdapterName -ErrorAction SilentlyContinue).InterfaceDescription } catch {}

# 공유 상태
$appState = [hashtable]::Synchronized(@{
        Quit           = $false
        Paused         = $false
        RescanNow      = $false
        FlushNow       = $false
        Cycle          = 0
        Phase          = '시작'
        Progress       = 0
        ProgressTotal  = 0
        SweepRound     = 0
        SweepTotal     = 0
        Found          = 0
        CountNew       = 0
        CountLeft      = 0
        NextScanAt     = $null
        NextFlushAt    = $null
        LastComplete   = $null
        Hosts          = [hashtable]::Synchronized(@{})
        Config         = $config
        EditConfig     = $null
        Range          = $selValue.Range
        Selection      = $selValue
        AdapterDesc    = $adapterDesc
        DnsServers     = $dnsServers
        TcpPorts       = $script:TcpPorts
        ServiceNames   = $script:ServiceNames
        SortMode       = 'IP'
        Cursor         = 0
        ScrollTop      = 0
        SpinIndex      = 0
        OuiMessage     = $oui.Message
        WorkerError    = $null
        SettingsRows   = $null
        SettingsCursor = 0
        EditConfigRef  = $null
        DetailHost     = $null
        SearchQuery    = ''      # 마지막으로 확정한 검색어 (다음 검색 모드 진입 시 미리 채움)
        SearchBuffer   = ''      # 검색창에서 편집 중인 검색어
        SearchOrigin   = 0       # 검색창을 열 때의 커서 위치 (Esc 시 복원, incremental 기준점)
        FilterQuery    = ''      # 현재 적용 중인 필터 (저장하지 않음)
        FilterBuffer   = ''      # 필터창에서 편집 중인 값
        FilterOrigin   = ''      # 필터창을 열 때의 필터 (Esc 시 복원)
        FilterEnterIp  = $null   # 필터창을 열 때 커서가 있던 호스트 (Esc 시 복원)
        FilterAnchorIp = $null   # 필터 변경 시 커서를 유지할 기준 호스트
    })

# ============================================================
# 10) 백그라운드 스캔 루프 시작
# ============================================================
$loopRunspace = [runspacefactory]::CreateRunspace()
$loopRunspace.ApartmentState = 'MTA'
$loopRunspace.Open()
$loopRunspace.SessionStateProxy.SetVariable('AppState', $appState)
$loopShell = [powershell]::Create()
$loopShell.Runspace = $loopRunspace
[void]$loopShell.AddScript($script:ScanLoopBody).AddArgument($appState).AddArgument($script:SharedFunctions).AddArgument($oui)
$loopHandle = $loopShell.BeginInvoke()

# ============================================================
# 11) 메인 입력/렌더 루프
# ============================================================
$screen = 'dashboard'   # dashboard | settings | detail | search | filter
[Console]::CursorVisible = $false
Clear-Host

function Enter-Settings {
    param($AppState)
    # 편집용 설정 사본
    $edit = Get-DefaultConfig
    foreach ($p in $edit.PSObject.Properties.Name) { $edit.$p = $AppState.Config.$p }
    $AppState.EditConfig = $edit
    # 설정 행 구성
    $rows = New-Object System.Collections.Generic.List[object]
    $rows.Add([PSCustomObject]@{ Type = 'adapter'; Label = '네트워크 어댑터 / 대역' })
    $rows.Add([PSCustomObject]@{ Type = 'engine'; Label = '이름 조회 엔진' })
    foreach ($m in $script:ConfigMeta) {
        $rows.Add([PSCustomObject]@{ Type = 'number'; Meta = $m })
    }
    $AppState.SettingsRows = $rows
    $AppState.SettingsCursor = 0
}

function Step-SettingValue {
    param($AppState, [int]$Direction)
    $item = $AppState.SettingsRows[$AppState.SettingsCursor]
    if ($item.Type -eq 'engine') {
        $AppState.EditConfig.Engine = if ($AppState.EditConfig.Engine -eq 'ResolveDnsName') { 'RawUdp' } else { 'ResolveDnsName' }
    }
    elseif ($item.Type -eq 'number') {
        $m = $item.Meta
        $step = if ($m.Unit -eq 'ms') { 50 } elseif ($m.Key -eq 'RescanSec') { 5 } else { 1 }
        $v = [int]$AppState.EditConfig.($m.Key) + ($step * $Direction)
        if ($v -lt $m.Min) { $v = $m.Min }
        if ($v -gt $m.Max) { $v = $m.Max }
        $AppState.EditConfig.($m.Key) = $v
    }
}

try {
    while (-not $appState.Quit) {
        $appState.SpinIndex = [int]$appState.SpinIndex + 1

        # 콘솔 크기 변경 감지 시 화면을 정리해 잔상/좌표 어긋남을 방지
        $curW = [Console]::BufferWidth; $curH = [Console]::WindowHeight
        if ($curW -ne $script:LastW -or $curH -ne $script:LastH) {
            $script:LastW = $curW; $script:LastH = $curH
            try { Clear-Host } catch { }
        }

        switch ($screen) {
            'dashboard' { Show-Dashboard -AppState $appState }
            'search' { Show-Dashboard -AppState $appState -InputMode 'search' }
            'filter' { Show-Dashboard -AppState $appState -InputMode 'filter' }
            'settings' { Show-Settings -AppState $appState }
            'detail' { Show-Detail -AppState $appState }
        }

        # 키 입력 (비차단)
        $waited = 0
        $key = $null
        while ($waited -lt 50) {
            if ([Console]::KeyAvailable) { $key = [Console]::ReadKey($true); break }
            Start-Sleep -Milliseconds 10
            $waited += 10
        }
        if ($null -eq $key) { continue }

        if ($screen -eq 'dashboard') {
            switch ($key.Key) {
                'Q' { $appState.Quit = $true }
                'F10' { $appState.Quit = $true }
                'F2' { Enter-Settings -AppState $appState; $screen = 'settings'; Clear-Host }
                'P' { $appState.Paused = -not $appState.Paused }
                'R' { $appState.RescanNow = $true }
                'F5' { $appState.FlushNow = $true; $appState.RescanNow = $true }
                'F3' {
                    # 검색 모드 진입만 수행 (Shift+F3 는 대시보드에서 무시)
                    #   다음/이전 이동은 검색 모드에서만 허용한다.
                    $isShift = ($key.Modifiers -band [ConsoleModifiers]::Shift) -ne 0
                    if (-not $isShift) {
                        $appState.SearchBuffer = $appState.SearchQuery   # 직전 검색어 미리 채움
                        $appState.SearchOrigin = [int]$appState.Cursor
                        $screen = 'search'
                    }
                }
                'F4' {
                    # 필터 모드 진입 (현재 필터 값을 미리 채움)
                    $curIp = Get-CursorHostIp -AppState $appState
                    $appState.FilterBuffer = $appState.FilterQuery
                    $appState.FilterOrigin = $appState.FilterQuery
                    $appState.FilterEnterIp = $curIp
                    $appState.FilterAnchorIp = $curIp
                    $screen = 'filter'
                }
                'F6' {
                    $appState.SortMode = switch ($appState.SortMode) { 'IP' { 'Name' } 'Name' { 'Vendor' } default { 'IP' } }
                }
                'UpArrow' { if ($appState.Cursor -gt 0) { $appState.Cursor = [int]$appState.Cursor - 1 } }
                'DownArrow' { $appState.Cursor = [int]$appState.Cursor + 1 }
                'Enter' {
                    $ips = @(Get-SortedHostIps -AppState $appState)
                    if ($appState.Cursor -lt $ips.Count) {
                        $appState.DetailHost = $appState.Hosts[$ips[$appState.Cursor]]
                        $screen = 'detail'; Clear-Host
                    }
                }
            }
        }
        elseif ($screen -eq 'settings') {
            switch ($key.Key) {
                'Escape' { $screen = 'dashboard'; Clear-Host }
                'Q' { $screen = 'dashboard'; Clear-Host }
                'UpArrow' { if ($appState.SettingsCursor -gt 0) { $appState.SettingsCursor-- } }
                'DownArrow' { if ($appState.SettingsCursor -lt $appState.SettingsRows.Count - 1) { $appState.SettingsCursor++ } }
                'LeftArrow' { Step-SettingValue -AppState $appState -Direction -1 }
                'RightArrow' { Step-SettingValue -AppState $appState -Direction 1 }
                'D' {
                    $def = Get-DefaultConfig
                    $item = $appState.SettingsRows[$appState.SettingsCursor]
                    if ($item.Type -eq 'number') { $appState.EditConfig.($item.Meta.Key) = $def.($item.Meta.Key) }
                    elseif ($item.Type -eq 'engine') { $appState.EditConfig.Engine = $def.Engine }
                }
                'Enter' {
                    $item = $appState.SettingsRows[$appState.SettingsCursor]
                    if ($item.Type -eq 'adapter') {
                        # 어댑터 재선택
                        $items2 = Get-AdapterMenuItems
                        $si = Find-SavedSelectionIndex -Items $items2 -AdapterName $appState.Selection.AdapterName -IP $appState.Selection.IPAddress
                        if ($si -lt 0) { $si = 0 }
                        $newSel = Read-MenuSelection -Items $items2 -StartIndex $si
                        if ($newSel) {
                            $nv = $newSel.Value
                            $appState.Selection = $nv
                            $appState.Range = $nv.Range
                            $appState.Config.AdapterName = $nv.AdapterName
                            $appState.Config.AdapterIP = $nv.IPAddress
                            try { $appState.DnsServers = @((Get-DnsClientServerAddress -InterfaceIndex $nv.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses) } catch {}
                            try { $appState.AdapterDesc = (Get-NetAdapter -Name $nv.AdapterName -ErrorAction SilentlyContinue).InterfaceDescription } catch {}
                            # 목록 초기화 + 즉시 flush 재시작
                            $appState.Hosts.Clear()
                            $appState.Cursor = 0
                            $appState.FlushNow = $true
                            $appState.RescanNow = $true
                        }
                        Clear-Host
                    }
                    elseif ($item.Type -eq 'number') {
                        # 직접 입력
                        [Console]::SetCursorPosition(0, [Math]::Min([Console]::WindowHeight, [Console]::BufferHeight) - 1)
                        [Console]::Write((' ' * ([Console]::BufferWidth - 1)))
                        [Console]::SetCursorPosition(0, [Math]::Min([Console]::WindowHeight, [Console]::BufferHeight) - 1)
                        $m = $item.Meta
                        [Console]::CursorVisible = $true
                        $raw = Read-Host (' {0} 입력 ({1}~{2})' -f $m.Label, $m.Min, $m.Max)
                        [Console]::CursorVisible = $false
                        $num = 0
                        if ([int]::TryParse($raw, [ref]$num)) {
                            if ($num -lt $m.Min) { $num = $m.Min }
                            if ($num -gt $m.Max) { $num = $m.Max }
                            $appState.EditConfig.($m.Key) = $num
                        }
                        Clear-Host   # Read-Host 로 인한 버퍼 스크롤 보정
                    }
                }
                'F10' {
                    # 편집값을 실제 설정으로 반영 + 저장
                    foreach ($p in $appState.EditConfig.PSObject.Properties.Name) {
                        $appState.Config.$p = $appState.EditConfig.$p
                    }
                    [void](Export-ScanConfig -Config $appState.Config)
                    $screen = 'dashboard'; Clear-Host
                }
            }
        }
        elseif ($screen -eq 'search') {
            $isShift = ($key.Modifiers -band [ConsoleModifiers]::Shift) -ne 0
            $direction = 0
            switch ($key.Key) {
                'Escape' {
                    # 취소 : 커서 원위치, 검색어는 확정하지 않음
                    $appState.Cursor = [int]$appState.SearchOrigin
                    $screen = 'dashboard'
                }
                'Enter' {
                    $appState.SearchQuery = $appState.SearchBuffer.Trim()
                    $screen = 'dashboard'
                }
                'F3' { $direction = if ($isShift) { -1 } else { 1 } }
                'DownArrow' { $direction = 1 }
                'UpArrow' { $direction = -1 }
                'Backspace' {
                    if ($appState.SearchBuffer.Length -gt 0) {
                        $appState.SearchBuffer = $appState.SearchBuffer.Substring(0, $appState.SearchBuffer.Length - 1)
                        if ($appState.SearchBuffer.Trim().Length -eq 0) {
                            $appState.Cursor = [int]$appState.SearchOrigin
                        }
                        else {
                            $m = Find-SearchMatch -AppState $appState -Query $appState.SearchBuffer -StartIndex ([int]$appState.SearchOrigin) -Direction 1 -IncludeStart
                            if ($m -ge 0) { $appState.Cursor = $m }
                        }
                    }
                }
                default {
                    # 출력 가능한 ASCII 문자만 입력 (한글 IME 조합 입력은 지원하지 않음)
                    $ch = $key.KeyChar
                    $code = [int]$ch
                    if ($code -ge 0x20 -and $code -le 0x7E -and $appState.SearchBuffer.Length -lt 40) {
                        $appState.SearchBuffer += $ch
                        $m = Find-SearchMatch -AppState $appState -Query $appState.SearchBuffer -StartIndex ([int]$appState.SearchOrigin) -Direction 1 -IncludeStart
                        if ($m -ge 0) { $appState.Cursor = $m }
                    }
                }
            }
            if ($direction -ne 0 -and -not [string]::IsNullOrWhiteSpace($appState.SearchBuffer)) {
                $m = Find-SearchMatch -AppState $appState -Query $appState.SearchBuffer -StartIndex ([int]$appState.Cursor) -Direction $direction
                if ($m -ge 0) { $appState.Cursor = $m }
            }
        }
        elseif ($screen -eq 'filter') {
            switch ($key.Key) {
                'Escape' {
                    # 취소 : 필터 원복, 커서도 진입 시 호스트로
                    $appState.FilterQuery = $appState.FilterOrigin
                    Set-CursorToHostIp -AppState $appState -Ip $appState.FilterEnterIp
                    $screen = 'dashboard'
                }
                'Enter' {
                    # 적용 (빈 값이면 필터 해제)
                    $appState.FilterAnchorIp = Get-CursorHostIp -AppState $appState
                    $appState.FilterBuffer = $appState.FilterBuffer.Trim()
                    Update-FilterLive -AppState $appState
                    $screen = 'dashboard'
                }
                'UpArrow' {
                    if ($appState.Cursor -gt 0) { $appState.Cursor = [int]$appState.Cursor - 1 }
                    $appState.FilterAnchorIp = Get-CursorHostIp -AppState $appState
                }
                'DownArrow' {
                    $cnt = @(Get-SortedHostIps -AppState $appState).Count
                    if ($appState.Cursor -lt $cnt - 1) { $appState.Cursor = [int]$appState.Cursor + 1 }
                    $appState.FilterAnchorIp = Get-CursorHostIp -AppState $appState
                }
                'Backspace' {
                    if ($appState.FilterBuffer.Length -gt 0) {
                        $appState.FilterBuffer = $appState.FilterBuffer.Substring(0, $appState.FilterBuffer.Length - 1)
                        Update-FilterLive -AppState $appState
                    }
                }
                default {
                    # 출력 가능한 ASCII 문자만 입력 (한글 IME 조합 입력은 지원하지 않음)
                    $ch = $key.KeyChar
                    $code = [int]$ch
                    if ($code -ge 0x20 -and $code -le 0x7E -and $appState.FilterBuffer.Length -lt 40) {
                        $appState.FilterBuffer += $ch
                        Update-FilterLive -AppState $appState
                    }
                }
            }
        }
        elseif ($screen -eq 'detail') {
            switch ($key.Key) {
                'Escape' { $screen = 'dashboard'; Clear-Host }
                'Q' { $screen = 'dashboard'; Clear-Host }
            }
        }
    }
}
finally {
    $appState.Quit = $true
    try { $loopShell.EndInvoke($loopHandle) } catch {}
    try { $loopShell.Dispose() } catch {}
    try { $loopRunspace.Dispose() } catch {}
    [Console]::CursorVisible = $true
    Clear-Host
    Write-Host 'NetScan v4 를 종료했습니다.' -ForegroundColor Cyan
    if ($appState.WorkerError) {
        Write-Host ('워커 오류: {0}' -f $appState.WorkerError) -ForegroundColor DarkYellow
    }
}
