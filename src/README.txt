## NetScan - 실시간 네트워크 스캐너 (PowerShell 모듈)

요구 사항
  - Windows 10/11, Windows PowerShell 5.1 또는 PowerShell 7
  - 관리자 권한 (ARP 캐시 초기화에 필요)
  - Windows Terminal / conhost / pwsh 콘솔 (PowerShell ISE 미지원)

설치
  1. zip 을 원하는 위치에 압축 해제
  2. 압축을 푼 폴더에서 PowerShell 실행 후:
       powershell -ExecutionPolicy Bypass -File .\Install.ps1
     실행 정책이 Restricted 인 PC 라면 -SetExecutionPolicy 를 붙이면
     RemoteSigned(LocalMachine)로 변경한다.
  3. 새 PowerShell 또는 cmd 창에서:
       netscan

  설치 위치 : %ProgramFiles%\WindowsPowerShell\Modules\NetScan\<버전>
  설정 파일 : %ProgramData%\NetScan\scan_tool.config.json
  cmd 실행  : %windir%\System32\netscan.bat (설치 시 생성, 제거 시 삭제)

실행
  netscan            (= Start-NetScan)
  관리자 권한이 아닌 창에서 실행하면 승격된 새 창에서 다시 실행된다.

제거
  powershell -ExecutionPolicy Bypass -File .\Uninstall.ps1
  설정까지 삭제하려면 -RemoveConfig 를 붙인다.
