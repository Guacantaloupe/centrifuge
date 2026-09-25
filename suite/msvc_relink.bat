@echo off
rem Re-link MSVC objects with a decorated-name export def.
rem %1 = output exe  %2 = object dir (trailing backslash)  %3 = map file  %4 = def file
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
link /nologo /out:%1 "%2*.obj" /def:%4 /MAP:%3 /OPT:NOICF
