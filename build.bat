@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" amd64 >nul 2>&1
if errorlevel 1 (
  echo vcvarsall failed
  exit /b 1
)
cd /d "%~dp0"
cl /nologo /LD /EHsc /O2 /W3 /DWIN32 /D_WINDOWS /D_USRDLL /D_CRT_SECURE_NO_WARNINGS rf2_puppeteer.cpp /link /OUT:rf2_puppeteer.dll
exit /b %errorlevel%
