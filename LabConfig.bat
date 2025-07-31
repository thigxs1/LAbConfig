@echo off
setlocal EnableDelayedExpansion

:: Caminho do log na área de trabalho (somente erros)
set "LOG=%USERPROFILE%\Desktop\Otimizacao_Erros.txt"
echo [INICIO - %DATE% %TIME%] > "%LOG%"

:: Executar como administrador se necessário
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 1. Desativar UAC (nível sistema)
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f 2>> "%LOG%"

:: 2. Perfil de energia e desligamento de disco
powercfg /setactive SCHEME_MIN 2>> "%LOG%"
powercfg -change -disk-timeout-ac 0 2>> "%LOG%"

:: 3. Desativar Firewall
netsh advfirewall set allprofiles state off 2>> "%LOG%"

:: 4. Desativar IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f 2>> "%LOG%"

:: 5. Desativar gerenciamento de energia da placa de rede (NICs)
for /f "tokens=*" %%a in ('wmic nic where "NetEnabled='true'" get Name /value ^| find "="') do (
    set "nic=%%a"
    set "nic=!nic:~5!"
    powershell -Command "Get-WmiObject -Namespace root\wmi -Class MSNdis_EthernetPermanentAddress | ForEach-Object { $_.InstanceName }" > nul 2>> "%LOG%"
)

:: 6. Forçar Windows Update via PowerShell
powershell -ExecutionPolicy Bypass -Command ^
"try { ^
  Set-ExecutionPolicy RemoteSigned -Scope Process -Force; ^
  Install-PackageProvider -Name NuGet -Force -Scope CurrentUser; ^
  Install-Module PSWindowsUpdate -Force -Scope CurrentUser; ^
  Import-Module PSWindowsUpdate; ^
  Get-WindowsUpdate -AcceptAll -Install -AutoReboot ^
} catch { $_ | Out-File -FilePath '%LOG%' -Append }" 2>> "%LOG%"

:: 7. Habilitar .NET Frameworks
dism /online /enable-feature /featurename:NetFx3 /All /LimitAccess /NoRestart 2>> "%LOG%"
dism /online /enable-feature /featurename:NetFx4 /All /NoRestart 2>> "%LOG%"
dism /online /enable-feature /featurename:NetFx4-AdvSrvs /All /NoRestart 2>> "%LOG%"
dism /online /enable-feature /featurename:WCF-Services45 /All /NoRestart 2>> "%LOG%"
dism /online /enable-feature /featurename:WCF-HTTP-Activation45 /All /NoRestart 2>> "%LOG%"
dism /online /enable-feature /featurename:WCF-NonHTTP-Activation /All /NoRestart 2>> "%LOG%"

:: 8, 9, 10, 11. Configurações de Internet (nível de sistema via Default User)
reg load HKU\Default "C:\Users\Default\NTUSER.DAT" 2>> "%LOG%"

:: Internet - baixar segurança e desativar modo protegido
reg add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1200 /t REG_DWORD /d 0 /f 2>> "%LOG%"  :: Executar scripts
reg add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 2500 /t REG_DWORD /d 3 /f 2>> "%LOG%"  :: Modo protegido = desativado

:: Habilitar Java Plugin (se aplicável)
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION" /v java.exe /t REG_DWORD /d 11000 /f 2>> "%LOG%"

:: Avançado - ativar protocolos SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3
reg add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v SecureProtocols /t REG_DWORD /d 0xA80 /f 2>> "%LOG%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 1 /f 2>> "%LOG%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 1 /f 2>> "%LOG%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v TLS13Enabled /t REG_DWORD /d 1 /f 2>> "%LOG%"

:: Avançado - desativar verificações de certificados
reg add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 0 /f 2>> "%LOG%"
reg add "HKU\Default\Software\Microsoft\Internet Explorer\Download" /v CheckExeSignatures /t REG_SZ /d "no" /f 2>> "%LOG%"
reg add "HKU\Default\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v State /t REG_DWORD /d 146944 /f 2>> "%LOG%"

reg unload HKU\Default 2>> "%LOG%"

:: Finalização
echo [FIM - %DATE% %TIME%] >> "%LOG%"
shutdown /r /t 15 /f
