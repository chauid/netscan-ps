<#
    NetScan 시스템 설치판(setup.exe) 빌드
    ------------------------------------------------------------
    - NetScan\NetScan.psd1 의 ModuleVersion 을 읽어 Inno Setup 컴파일러(ISCC.exe)에 넘긴다.
      → dist\NetScan-<버전>-setup.exe
    - 버전은 psd1 한 곳에서만 관리한다 (NetScan.iss 에는 기본값만 있음).
    - ISCC.exe 탐색 순서
        1) -IsccPath 인수
        2) PATH 의 ISCC.exe
        3) 레지스트리 설치 정보 (Inno Setup 7 / 6)
        4) 기본 설치 경로 (Program Files / Program Files (x86))

    사용법:
        powershell -ExecutionPolicy Bypass -File .\Build-Setup.ps1
        powershell -ExecutionPolicy Bypass -File .\Build-Setup.ps1 -IsccPath 'D:\Tools\Inno Setup 7\ISCC.exe'
#>
[CmdletBinding()]
param(
    [string] $IsccPath
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$issPath = Join-Path $root 'NetScan.iss'
$manifest = Test-ModuleManifest -Path (Join-Path $root 'NetScan\NetScan.psd1')
$version = $manifest.Version.ToString()

function Find-Iscc {
    param([string] $Hint)

    if ($Hint) {
        if (Test-Path -LiteralPath $Hint) { return (Resolve-Path -LiteralPath $Hint).Path }
        throw ('지정한 ISCC.exe 를 찾을 수 없습니다: {0}' -f $Hint)
    }

    $cmd = Get-Command -Name 'ISCC.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($appKey in @('Inno Setup 7_is1', 'Inno Setup 6_is1')) {
        foreach ($base in $uninstallKeys) {
            $key = Join-Path $base $appKey
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $location = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).InstallLocation
            if ($location) {
                $candidate = Join-Path $location 'ISCC.exe'
                if (Test-Path -LiteralPath $candidate) { return $candidate }
            }
        }
    }

    $programDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object -FilterScript { $_ }
    foreach ($dir in $programDirs) {
        foreach ($name in @('Inno Setup 7', 'Inno Setup 6')) {
            $candidate = Join-Path $dir (Join-Path $name 'ISCC.exe')
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    return $null
}

if (-not (Test-Path -LiteralPath $issPath)) {
    throw ('Inno Setup 스크립트가 없습니다: {0}' -f $issPath)
}

$iscc = Find-Iscc -Hint $IsccPath
if (-not $iscc) {
    Write-Host 'ISCC.exe 를 찾지 못했습니다. Inno Setup 을 설치하거나 -IsccPath 로 경로를 지정하십시오.' -ForegroundColor Red
    Write-Host '  예) winget install JRSoftware.InnoSetup.7' -ForegroundColor Yellow
    exit 1
}

$distDir = Join-Path $root 'dist'
if (-not (Test-Path -LiteralPath $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host ('ISCC    : {0}' -f $iscc) -ForegroundColor DarkGray
Write-Host ('버전    : {0}' -f $version) -ForegroundColor DarkGray
Write-Host ('스크립트: {0}' -f $issPath) -ForegroundColor DarkGray

& $iscc ('/DAppVersion={0}' -f $version) ('/O{0}' -f $distDir) $issPath
if ($LASTEXITCODE -ne 0) {
    Write-Host ('빌드 실패 (ISCC 종료 코드 {0})' -f $LASTEXITCODE) -ForegroundColor Red
    exit $LASTEXITCODE
}

$setupPath = Join-Path $distDir ('NetScan-{0}-setup.exe' -f $version)
Write-Host ('생성 완료: {0}' -f $setupPath) -ForegroundColor Green
