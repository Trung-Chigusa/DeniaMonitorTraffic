Denia - Portable Notes
======================

Copy the whole publish folder to another Windows x64 machine. Do not copy only
Denia.exe, because WPF/Skia native runtime DLLs are beside it.

Offline PCAP/PCAPNG analysis
----------------------------
Works from this folder without installing .NET, because the app is published
self-contained.

Realtime TShark mode
--------------------
Realtime capture needs:

1. tshark.exe
   The app searches these locations:
   - Tools\Wireshark\tshark.exe beside the EXE
   - Tools\TShark\tshark.exe beside the EXE
   - tshark.exe beside the EXE
   - C:\Program Files\Wireshark\tshark.exe
   - C:\Program Files (x86)\Wireshark\tshark.exe
   - PATH

2. Npcap capture driver
   This must be installed on Windows. It cannot be made fully portable by
   copying DLL files into the app folder, because packet capture needs a kernel
   driver/service.

Quick check
-----------
Run Check-Realtime-Prereqs.ps1 in PowerShell to verify tshark and Npcap.

Optional install helper
-----------------------
Run Install-Wireshark-Npcap.ps1 as Administrator to install Wireshark through
winget when available.
