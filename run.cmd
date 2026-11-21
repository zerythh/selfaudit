@echo off
setlocal
set "BASE=https://raw.githubusercontent.com/zerythh/selfaudit/main"
set "WORK=%TEMP%\SelfAudit-%RANDOM%%RANDOM%"
mkdir "%WORK%" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue';try{iwr -useb ($env:BASE+'/SelfAudit.ps1') -OutFile ($env:WORK+'\SelfAudit.ps1') -EA Stop;iwr -useb ($env:BASE+'/WebhookUrl.txt') -OutFile ($env:WORK+'\WebhookUrl.txt') -EA Stop}catch{Write-Host ('Download failed: '+$_.Exception.Message) -f Red;exit 1}"
if errorlevel 1 ( pause & exit /b 1 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%WORK%\SelfAudit.ps1" -WebhookFile "%WORK%\WebhookUrl.txt" %*
pause