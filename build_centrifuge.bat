@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
rem Build core lib with its canonical name first (exe links Release\centrifuge_core.lib)
msbuild C:\Users\scree\kimi\workspace\centrifuge\build\centrifuge.sln /p:Configuration=Release /p:Platform=x64 /m /v:m /t:centrifuge_core
if errorlevel 1 exit /b 1
rem Then link the exe under a dev name so the batch runner's lock on centrifuge.exe is avoided
msbuild C:\Users\scree\kimi\workspace\centrifuge\build\centrifuge.sln /p:Configuration=Release /p:Platform=x64 /m /v:m /t:centrifuge /p:TargetName=centrifuge_dev
