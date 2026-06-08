using System.IO;
using System.Runtime.InteropServices;
using DdosTriggerAnalyzer.Models;

namespace DdosTriggerAnalyzer.Services;

public sealed class HostResourceMonitorService
{
    private ulong _previousIdle;
    private ulong _previousKernel;
    private ulong _previousUser;
    private bool _hasPreviousCpuSample;

    public HostResourceSnapshot Sample()
    {
        var cpu = SampleCpuPercent();
        var (ramPercent, ramDisplay) = SampleMemory();
        var (diskPercent, diskName) = SampleDisk();

        return new HostResourceSnapshot
        {
            CpuPercent = Math.Round(cpu, 1),
            RamPercent = Math.Round(ramPercent, 1),
            DiskPercent = Math.Round(diskPercent, 1),
            DiskName = diskName,
            RamDisplay = ramDisplay
        };
    }

    private double SampleCpuPercent()
    {
        if (!GetSystemTimes(out var idleTime, out var kernelTime, out var userTime))
        {
            return 0;
        }

        var idle = ToUInt64(idleTime);
        var kernel = ToUInt64(kernelTime);
        var user = ToUInt64(userTime);

        if (!_hasPreviousCpuSample)
        {
            _previousIdle = idle;
            _previousKernel = kernel;
            _previousUser = user;
            _hasPreviousCpuSample = true;
            return 0;
        }

        var idleDelta = idle - _previousIdle;
        var kernelDelta = kernel - _previousKernel;
        var userDelta = user - _previousUser;
        var total = kernelDelta + userDelta;

        _previousIdle = idle;
        _previousKernel = kernel;
        _previousUser = user;

        if (total == 0)
        {
            return 0;
        }

        return Math.Clamp((total - idleDelta) * 100.0 / total, 0, 100);
    }

    private static (double Percent, string Display) SampleMemory()
    {
        var status = new MemoryStatusEx();
        status.dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>();

        if (!GlobalMemoryStatusEx(ref status))
        {
            return (0, "-");
        }

        var used = status.ullTotalPhys - status.ullAvailPhys;
        var percent = status.ullTotalPhys == 0 ? 0 : used * 100.0 / status.ullTotalPhys;
        return (percent, $"{ToGiB(used):0.0}/{ToGiB(status.ullTotalPhys):0.0} GB");
    }

    private static (double Percent, string Name) SampleDisk()
    {
        var root = Path.GetPathRoot(AppContext.BaseDirectory) ?? "C:\\";
        var drive = new DriveInfo(root);
        if (!drive.IsReady || drive.TotalSize <= 0)
        {
            return (0, root);
        }

        var used = drive.TotalSize - drive.AvailableFreeSpace;
        return (used * 100.0 / drive.TotalSize, drive.Name);
    }

    private static double ToGiB(ulong bytes) => bytes / 1024d / 1024d / 1024d;

    private static ulong ToUInt64(FileTime fileTime) =>
        ((ulong)fileTime.dwHighDateTime << 32) | fileTime.dwLowDateTime;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FileTime idleTime, out FileTime kernelTime, out FileTime userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }
}
