@echo off
set PYTHONHOME=C:\Users\yo\AppData\Local\Programs\Python\Python311
set PYTHONPATH=
set PATH=C:\Users\yo\AppData\Local\Programs\Python\Python311;%PATH%
"C:\Program Files\IDA Professional 9.3\idat.exe" -A -S"D:\Games\HyperREV\hyper-reV\ida_mtf_analysis.py" -L"D:\Games\HyperREV\hyper-reV\ida_mtf_log.txt" "D:\Games\PhysInj\intel\ring-1.io\files\bootloader-implant-deobfuscated.i64"
echo Exit code: %ERRORLEVEL%
