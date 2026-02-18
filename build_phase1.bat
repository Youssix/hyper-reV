@echo off
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

echo === Building hyper-reV solution (hyperv-attachment + usermode) ===
%MSBUILD% "D:\Games\HyperREV\hyper-reV\hyper-reV.sln" /p:Configuration=Release /p:Platform=x64 /t:hyperv-attachment;usermode /m /nologo /verbosity:minimal
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: build failed
    exit /b 1
)

echo.
echo === ALL BUILDS SUCCESSFUL ===
