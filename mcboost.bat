echo off

title BoostMC v1.1.0


mode 114,23

rem variaveis===-

set id=%username%
set count=0
set install=false
set cor=d
set _*=boostmc_priv102
set c=chances


goto adm

:adm
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
Cls & color c & title BoostMC - Erro
echo    "    _                                     _                
echo   "    / \  _  _  ._ ._ _            ._ _    |_ ._ ._ _    |   
echo "      \_/ (_ (_) |  | (/_ |_|   |_| | | |   |_ |  | (_)   o   
echo.                      
echo --= voce deve executar o BoostMC como administrador para prosseguir.                        
pause >nul
exit
)
cls
goto:verificar

:verificar
if exist "C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\install.data" (
   
   goto arquivo1

) else (

cls
goto install

)

:arquivo1
@echo off
cls
if exist "C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\creditos\credits.txt" (
   
   goto arquivo2

) else (

cls
goto arquivonaoencontrado

)

:arquivo2
@echo off
cls
if exist "C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\msg\tuto.txt" (
   
   goto arquivo3

) else (

cls
goto arquivonaoencontrado

)

:arquivo3
@echo off
cls
if exist "C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\cores" (
   
   goto menu

) else (

cls
goto arquivonaoencontrado

)

:arquivonaoencontrado
cls
@echo off
color c
echo     " _                                     _                
echo    " / \  _  _  ._ ._ _            ._ _    |_ ._ ._ _    |   
echo   "  \_/ (_ (_) |  | (/_ |_|   |_| | | |   |_ |  | (_)   o   
echo.
echo.
echo alguns arquivos nao foram encontrados; 
set/p instalarnv="deseja reinstalar o BoostMC? (y/n) "                                                        
if '%instalarnv%' == 'y' goto install

if '%instalarnv%' == 'n' goto aviso04__

if '%instalarnv%' == ' ' goto arquivonaoencontrado

:aviso04__
cls
@echo off
echo obs: o programa pode nao funcionar corretamente.
echo.
echo redirecionando..
del /q C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\msg\sucess.vbs
timeout /nobreak -t 3 >nul
goto menu 



:install
cls
set install=false
md C:\Users\%id%\AppData\Roaming\BoostMC
cd C:\Users\%id%\AppData\Roaming\BoostMC
md bykayyo
cd bykayyo
echo %install~2,0%***************>> install.data
cd C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo
md v1.3.1
cd v1.3.1
md cores
cd C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1
md creditos
cd creditos
echo. >> credits.txt
echo BoostMC INFO >> credits.txt
echo criado apenas para uso privado, por favor não divulgar. >> credits.txt
echo. >> credits.txt
echo discord: kayu#2878 (827095034242531369) >> credits.txt
attrib +h install.data
echo twitter: https://twitter.com/_kaayo14 >> credits.txt
cd C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1
md msg
cd msg
echo # Tutorial - Desempenho Máximo >> tuto.txt
echo. >> tuto.txt
echo 1) aperte a tecla windows >> tuto.txt
echo. >> tuto.txt
echo 2) pesquise por "configurações de energia e suspensão" >> tuto.txt
echo. >> tuto.txt
echo 3) após isso aperte em configurações de energia adicionais: https://cdn.discordapp.com/attachments/832500280724684820/836536684056412220/unknown.png >> tuto.txt
echo. >> tuto.txt
echo 4) https://cdn.discordapp.com/attachments/832500280724684820/836536881969233920/unknown.png >> tuto.txt
echo. >> tuto.txt
echo 5) https://cdn.discordapp.com/attachments/832500280724684820/836537161334521876/unknown.png >> tuto.txt
echo. >> tuto.txt
echo após isso reinicie o seu computador;
echo. >> tuto.txt
echo. >> tuto.txt
echo obs: apenas e compatível com windows 10 versao 1803 >> tuto.txt
echo obs: não é recomendável usar em notebooks, pois gastará a bateria muito rápido, porém ainda dará o desempenho prometido. >> tuto.txt
echo. >> tuto.txt
echo duvidas no meu pv: kayu#2878 (827095034242531369) >> tuto.txt
echo. >> tuto.txt
echo ---------------------------------------------------- >> tuto.txt
cd C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1
cd msg 
echo x=msgbox("Boost MC foi instalado com sucesso, obrigado." ,48, "BoostMC Instalado!") >> sucess.vbs
timeout -2 >nul
cls
goto sucess

:sucess
cls
start C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\msg\sucess.vbs
timeout /nobreak -t 1.8 >nul
goto menu

:menu
cls
@echo off
echo "   ___                             _   __   __
echo "  / o.)   _     _    __   /7      / \,' / ,'_/
echo " / o \  ,'o|  ,'o|  (c'  /_7     / \,' / / /_ 
echo "/___,'  |_,'  |_,' /__) //      /_/ /_/  |__/                                                                                                                                        
echo.
color %cor%                                                                                                                                           
echo 1 - FpsCleaner   2 - Otimizar conexão      3 - Desempenho Maximo
echo.
echo 4 - Creditos     5 - Desinstalar
echo.
echo.
set/p op="escolha: "

if '%op%' == '1' goto cleaner

if '%op%' == '2' goto ping

if '%op%' == '3' goto dmaximo

if '%op%' == '4' goto credits

if '%op%' == '5' goto unistall

if "%op%"=="" goto menu


:credits
cls
@echo off

start C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\creditos\credits.txt
timeout /nobreak -t 2 
goto menu

:dmaximo
cls
@echo off
echo.
echo obs: essa funcao apenas funciona apartir do windows 10 versao 1803 ou superior.
set /p tuto="deseja abrir o tutorial? (y/n) "


if '%tuto%' == 'y' start C:\Users\%id%\AppData\Roaming\BoostMC\bykayyo\v1.3.1\msg\tuto.txt & timeout /nobreak -t 5 >nul & goto desempenhomaximo

if '%tuto%' == 'n' goto desempenhomaximo

if '%tuto%' == '' goto dmaximo

:desempenhomaximo
cls
echo.
echo.
echo              Ativado!
echo.
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
echo.
timeout /nobreak -t 5 >nul
cls
goto menu

:ping
cls
netsh int tcp set global chimney=enable
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global ecncapability=disabled
netsh interface tcp set global ecncapability=disabled
netsh interface ipv4 set subinterface "Local Area Connection" mtu=150 store=persistent
netsh interface ipv4 set subinterface "Internet" mtu=80 store=persistent
netsh int tcp set global rss=default
netsh int tcp set global congestion provider=ctcp
netsh int tcp set heuristics disabled
netsh int ip reset c:resetlog.txt
netsh int ip reset C:\tcplog.txt
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global dca=disabled
netsh int tcp set global netdma=disabled
cd %temp%
ECHO > SG_Vista_TcpIp_Patch.reg Windows Registry Editor Version 5.00 
ECHO >> SG_Vista_TcpIp_Patch.reg [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters] 
ECHO >> SG_Vista_TcpIp_Patch.reg "Disable Bandwidth Throttling"=dword:00000001
regedit /s SG_Vista_TcpIp_Patch.reg
del SG_Vista_TcpIp_Patch.reg
ipconfig /flushdns
timeout -t 1 >nul
echo reduzindo Latencia..
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh int tcp set global congestionprovider=none
netsh int tcp set global autotuninglevel=high
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enable
netsh int tcp set global netdma=enable
netsh int tcp set heuristics enable
netsh int tcp set global rss=enabled
netsh int tcp set global timestamps=enable
timeout -t 3 >nul
nets interface ipv4 set subinterface "Ethenet" mtu=1500 store=persistent
cls
goto menu

:cleaner 
cls
del /S /q c:\Windows\Recent\*.*

del /S /q c:\Windows\temp\*.*

PowerShell.exe -NoProfile -Command Clear-RecycleBin -Confirm:$false

del /S /q c:\temp\*.*

del /S /q C:\Users\%id%\AppData\Local\Temp\*.*

del /S /q C:\Users\%id%\AppData\Local\Tmp\*.*

timeout -t 2 >nul & echo aguarde..
cleanmgr  /d C:
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\80e3c60e-bb94-4ad8-bbe0-0d3195efc663" /v "Attributes" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "Attributes" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\03680956-93BC-4294-BBA6-4E0F09BB717F" /v "Attributes" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60" /v "Attributes" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\dab60367-53fe-4fbc-825e-521d069d2456" /v "Attributes" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "4864" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "KeepAliveTime" /t REG_DWORD /d "7200000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "QualifyingDestinationThreshold" /t REG_DWORD /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
@echo off
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RemoteComputer\NameSpace\{D6277990-4C6A-11CF-8D87-00AA0060F5BF}" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TcpNoDelay" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "5" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "AutoRun" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\NDIS\Parameters" /v "MaxNumRssCpus" /t REG_DWORD /d "4" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableLargeMTU" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPMaxDataRetransmissions" /t REG_DWORD /d "5" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcPMaxDataRetransmissions" /t REG_DWORD /d "5" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "1280" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "25" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "25344" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "100" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "100" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "KeepConn" /t REG_DWORD /d "86400" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Software\Mojang" /v "TcpNoDelay" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Mojang" /v "TCPDelAckTicks" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Software\Mojang" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Mojang\Minecraft" /v "TcpNoDelay" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Mojang\Minecraft" /v "TCPDelAckTicks" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Software\Mojang\Minecraft" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AsynchronousCredits" /t REG_DWORD /d "1024" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableDos" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxThreadsPerQueue" /t REG_DWORD /d "256" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "32768" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
@echo off
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TreatHostAsStableStorage" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "AllowUnqualifiedQuery" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableMediaSenseEventLog" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableRss" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTcpChimneyOffload" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DnsOutstandingQueriesCount" /t REG_DWORD /d "1000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableAddrMaskReply" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableBcastArpReply" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableDca" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableHeuristics" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "QualifyingDestinationThreshold" /t REG_DWORD /d "4294967295" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TCPMaxDataRetransmissions" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*SpeedDuplex" /t REG_SZ /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*FlowControl" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*RSS" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPConnectionOffloadIPv4" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPConnectionOffloadIPv6" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV1IPv4" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPUDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPUDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "CopyBufferSize" /t REG_DWORD /d "65536" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileBufferedSynchronousIo" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileChunkSize" /t REG_DWORD /d "16384" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileOverlappedCount" /t REG_DWORD /d "16" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "RestoreConnection" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "RestoreTimeout" /t REG_DWORD /d "20" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "DeferConnection" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "ReconnectTimeout" /t REG_DWORD /d "5" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\SharedAccessConnection" /v "EnableControl" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\SharedAccessConnection" /v "DeviceTimeout" /t REG_DWORD /d "1000" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NetLinkTimeout" /t REG_DWORD /d "1000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "24" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MapAllocationFragment" /t REG_DWORD /d "131072" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemCacheLimit" /t REG_DWORD /d "512" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "GroupPolicyDisallowCaches" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "AllowNewCachesByDefault" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\rdyboost" /v "Start" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "64000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000000a0000000000000004001000000000000800200000000000000050000000000" /f
@echo off
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000" /f
@echo off
Reg.exe add "HKCR\CLSID\{77708248-f839-436b-8919-527c410f48b9}\Shell\Open\Command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\regedit.exe" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Winsock" /v "HelperDllName" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\wshtcpip.dll" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Winsock" /v "Mapping" /t REG_BINARY /d "08000000030000000200000001000000060000000200000001000000000000000200000000000000060000000200000002000000110000000200000002000000000000000200000000000000110000000200000003000000ff000000020000000300000000000000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "2" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1050" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3400" /f
@echo off
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "69" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "255" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "52" /f
@echo off
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Current\Version\Explorer\Advanced" /v "LastActiveClick" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Current\Version\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Disk" /v "TimeOutValue" /t REG_DWORD /d "60" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "8" /f
@echo off
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "8" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "8" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "8" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "Win31FileSystem" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "Win95TruncatedExtensions" /t REG_DWORD /d "1" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "0" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundFlashCount" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
@echo off
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "0" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundFlashCount" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
@echo off
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "10" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveTime" /t REG_DWORD /d "7200000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1000" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v "MaxWorkItems" /t REG_DWORD /d "8196" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v "MaxRawWorkItems" /t REG_DWORD /d "512" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v "MaxFreeConnections" /t REG_DWORD /d "100" /f
@echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v "MinFreeConnections" /t REG_DWORD /d "32" /f
@echo off
echo computador limpo.
timeout /nobreak -t 2 >nul
cls
