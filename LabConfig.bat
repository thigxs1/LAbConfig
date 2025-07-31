@echo off
setlocal EnableDelayedExpansion

:: Caminho do log
set "logDir=C:\Brasinfo"
set "logFile=%logDir%\Otimizacao_Erros.txt"

:: Criar pasta de log, se não existir
if not exist "%logDir%" (
    mkdir "%logDir%"
)

:: Função para logar erro
set "logError=echo [ERRO %%~1] >> "%logFile%""

:: Registrar início
echo [INICIO - %date% %time%] > "%logFile%"

:: 1. Desativar UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f || echo [ERRO UAC] >> "%logFile%"

:: 2. Perfil de energia: alto desempenho e sem desligamento de disco
powercfg /s SCHEME_MIN || echo [ERRO PERFIL ENERGIA] >> "%logFile%"
powercfg -change -disk-timeout-ac 0 || echo [ERRO DISCO AC] >> "%logFile%"
powercfg -change -disk-timeout-dc 0 || echo [ERRO DISCO DC] >> "%logFile%"

:: 3. Desativar Firewall
netsh advfirewall set allprofiles state off || echo [ERRO FIREWALL] >> "%logFile%"

:: 4. Desativar IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f || echo [ERRO IPV6] >> "%logFile%"

:: 5. Desativar desligamento de energia da placa de rede
for /f "tokens=*" %%A in ('wmic path win32_networkadapter where "PhysicalAdapter=True" get DeviceID /value ^| find "DeviceID"') do (
    set "dev=%%A"
    set "dev=!dev:~9!"
    powercfg -devicequery wake_armed | findstr /i "%%A" >nul && powercfg -devicedisablewake "%%A"
)

:: 6. Forçar update do Windows
dism /online /cleanup-image /restorehealth || echo [ERRO DISM RESTORE] >> "%logFile%"
sfc /scannow || echo [ERRO SFC] >> "%logFile%"

:: 7. Habilitar .NET Framework 3.5 e 4.8
dism /online /enable-feature /featurename:NetFx3 /All /norestart || echo [ERRO .NET 3.5] >> "%logFile%"
dism /online /enable-feature /featurename:NetFx4 /All /norestart || echo [ERRO .NET 4.8] >> "%logFile%"

:: 8. Opções de internet - Segurança
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A10" /t REG_DWORD /d 0 /f || echo [ERRO ZONA SEGURANÇA] >> "%logFile%"

:: 9. Habilitar Java Plugin (Internet Explorer)
reg add "HKLM\Software\Microsoft\Internet Explorer\Main" /v "EnableJava" /t REG_DWORD /d 1 /f || echo [ERRO JAVA] >> "%logFile%"

:: 10. Avançado - Ativar TLS e SSL
for %%A in ("SSL 3.0" "TLS 1.0" "TLS 1.1" "TLS 1.2" "TLS 1.3") do (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d 0xA80 /f >nul 2>nul
)

:: 11. Avançado - Desativar verificação de certificados
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d 0 /f || echo [ERRO REVOGAÇÃO CERTIFICADOS] >> "%logFile%"
reg add "HKCU\Software\Microsoft\Internet Explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "no" /f || echo [ERRO ASSINATURA DOWNLOAD] >> "%logFile%"
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "CheckCertPublisherRevocation" /t REG_DWORD /d 0 /f || echo [ERRO REVOGAÇÃO FORNECEDOR] >> "%logFile%"

:: Final do script
echo [FIM - %date% %time%] >> "%logFile%"
timeout /t 10 >nul
shutdown -r -t 15
exit
