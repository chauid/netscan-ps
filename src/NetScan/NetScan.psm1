<#
    NetScan 모듈
    ------------------------------------------------------------
    - Start-NetScan (별칭 netscan) 으로 대시보드를 실행한다.
    - 실제 동작은 같은 폴더의 NetScan.Engine.ps1 이 담당한다.
      엔진은 최상위 스크립트 코드·런스페이스·관리자 승격 재실행을 포함하므로
      모듈 스코프에 풀어 넣지 않고 독립 스크립트로 호출한다.
    - 설정 파일 : %ProgramData%\NetScan\scan_tool.config.json
#>

$script:EnginePath = Join-Path $PSScriptRoot 'NetScan.Engine.ps1'

function Start-NetScan {
    <#
    .SYNOPSIS
        실시간 네트워크 스캐너 대시보드를 실행합니다.
    .DESCRIPTION
        선택한 어댑터/대역을 주기적으로 스캔하여 htop 형태로 표시합니다.
        관리자 권한이 필요하며, 부족하면 승격된 새 창으로 다시 실행합니다.
        PowerShell ISE 는 지원하지 않습니다.
    .EXAMPLE
        netscan
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:EnginePath)) {
        Write-Error ('엔진 파일을 찾을 수 없습니다: {0}' -f $script:EnginePath)
        return
    }
    & $script:EnginePath
}

Set-Alias -Name netscan -Value Start-NetScan
Export-ModuleMember -Function Start-NetScan -Alias netscan
