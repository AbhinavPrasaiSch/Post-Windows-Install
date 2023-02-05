@echo off

:: Rek OS Startup Optimizer

timeout 5 >nul

taskkill /IM "RuntimeBroker.exe" /F
taskkill /IM "dllhost.exe" /F

net stop UserManager
net stop W3SVC
net stop msiserver
net stop AppHostSvc
net stop ProfSvc
net stop CryptSvc

rd %temp% /s /q
md %temp%

echo All Tasks Completed Successfully!

timeout 2 >nul