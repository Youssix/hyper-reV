@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul 2>&1
cd /d D:\Games\HyperREV\hyper-reV
msbuild hyper-reV.sln /t:loader /p:Configuration=Release /p:Platform=x64 /v:minimal
