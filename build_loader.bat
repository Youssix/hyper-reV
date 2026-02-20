@echo off
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
%MSBUILD% "D:\Games\HyperREV\hyper-reV\hyper-reV.sln" /p:Configuration=Release /p:Platform=x64 /t:loader /m /nologo /verbosity:minimal
