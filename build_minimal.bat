@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
%MSBUILD% "%~dp0MinimalDll\MinimalDll.vcxproj" /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
