@echo off
rem %1 = opt level (/Od /O2 /O3)  %2 = std (/std:c11 /std:c++17)
rem %3 = output exe  %4 = object dir (with trailing backslash)  %5 = source file
rem %6 = map file  %7 = def file (suite function exports)
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cl /nologo %1 %2 /W0 /Z7 /EHsc /Fe:%3 /Fo:%4 %5 /link /OPT:NOICF /DEF:%7 /MAP:%6
