@{
    RootModule           = 'NetScan.psm1'
    ModuleVersion        = '0.41'
    GUID                 = 'f264a7a2-98a7-47a7-a4d9-a8c563610958'
    Author               = 'chauid'
    Copyright            = '(c) chauid. All rights reserved.'
    Description          = 'htop 형태의 실시간 네트워크 스캐너 대시보드 (DNS/LLMNR/NetBIOS/mDNS 이름 조회, TCP/UDP 포트, OUI 제조사)'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Start-NetScan')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('netscan')
    FileList             = @('NetScan.psd1', 'NetScan.psm1', 'NetScan.Engine.ps1', 'oui.txt')
    PrivateData          = @{
        PSData = @{
            Tags = @('network', 'scanner', 'dashboard', 'arp', 'windows')
        }
    }
}
