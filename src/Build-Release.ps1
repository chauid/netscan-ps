<#
    NetScan 배포용 zip 생성
    ------------------------------------------------------------
    - NetScan\NetScan.psd1 의 ModuleVersion 을 읽어 dist\NetScan-<버전>.zip 을 만든다.
    - zip 구성 : NetScan\ (모듈), install.bat, uninstall.bat, Install.ps1, Uninstall.ps1, README.txt(있으면)

    사용법:
        powershell -ExecutionPolicy Bypass -File .\Build-Release.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$manifest = Test-ModuleManifest -Path (Join-Path $root 'NetScan\NetScan.psd1')
$version = $manifest.Version.ToString()

$distDir = Join-Path $root 'dist'
if (-not (Test-Path -LiteralPath $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}
$zipPath = Join-Path $distDir ('NetScan-{0}.zip' -f $version)
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

# 필수 항목이 없으면 중단, README.txt 는 있을 때만 포함
$required = @('NetScan', 'install.bat', 'uninstall.bat', 'Install.ps1', 'Uninstall.ps1')
$optional = @('README.txt')
$items = New-Object System.Collections.Generic.List[string]
foreach ($name in $required) {
    $path = Join-Path $root $name
    if (-not (Test-Path -LiteralPath $path)) { throw ('필수 파일이 없습니다: {0}' -f $path) }
    $items.Add($path)
}
foreach ($name in $optional) {
    $path = Join-Path $root $name
    if (Test-Path -LiteralPath $path) { $items.Add($path) }
}
Compress-Archive -Path $items.ToArray() -DestinationPath $zipPath
Write-Host ('생성 완료: {0}' -f $zipPath) -ForegroundColor Green
