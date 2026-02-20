@echo off
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
%MSBUILD% "D:\Games\HyperREV\hyper-reV\CrtTestDll\CrtTestDll.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=D:\Games\HyperREV\hyper-reV\ /m /nologo /verbosity:minimal
