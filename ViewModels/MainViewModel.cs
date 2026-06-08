using System.Collections.ObjectModel;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using DdosTriggerAnalyzer.Helpers;
using DdosTriggerAnalyzer.Models;
using DdosTriggerAnalyzer.Services;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Win32;
using SkiaSharp;

namespace DdosTriggerAnalyzer.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly PcapReaderService _pcapReaderService = new();
    private readonly DdosDetectionService _detectionService = new();
    private readonly ReportExportService _reportExportService = new();
    private readonly TsharkLiveCaptureService _tsharkLiveCaptureService = new();
    private readonly HostResourceMonitorService _hostResourceMonitorService = new();
    private readonly IpGeoLookupService _ipGeoLookupService = new();
    private readonly ConcurrentQueue<PacketRecord> _livePacketQueue = new();
    private readonly List<PacketRecord> _livePackets = new();
    private readonly object _livePacketsLock = new();
    private readonly List<double> _cpuHistory = new();
    private readonly List<double> _ramHistory = new();
    private readonly List<double> _diskHistory = new();
    private IReadOnlyList<PacketRecord> _lastOfflinePackets = Array.Empty<PacketRecord>();

    private AnalysisSummary _summary = new();
    private bool _isBusy;
    private bool _isLiveCaptureActive;
    private double _progress;
    private string _statusMessage = "Ready. Open a PCAP/PCAPNG file or start a TShark live capture.";
    private string _currentFile = string.Empty;
    private string _liveCaptureStatus = "Refresh interfaces to enable realtime monitoring.";
    private HostResourceSnapshot _hostResources = new();
    private NetworkInterfaceOption? _selectedInterface;
    private CancellationTokenSource? _liveCaptureCts;
    private DispatcherTimer? _liveUiTimer;
    private DispatcherTimer? _hostMonitorTimer;
    private Task? _liveAnalysisTask;
    private int _queuedSinceLastUiTick;
    private int _parsedLivePacketCount;
    private DateTime _lastAnalysisLog = DateTime.MinValue;
    private DateTime _lastGeoUpdate = DateTime.MinValue;
    private int _geoUpdateVersion;

    public MainViewModel()
    {
        OpenPcapCommand = new RelayCommand(async _ => await OpenPcapAsync(), _ => !IsBusy && !IsLiveCaptureActive);
        ExportReportCommand = new RelayCommand(_ => ExportReport(), _ => !IsBusy && Summary.TotalPackets > 0);
        RefreshInterfacesCommand = new RelayCommand(async _ => await RefreshInterfacesAsync(), _ => !IsBusy && !IsLiveCaptureActive);
        StartLiveCaptureCommand = new RelayCommand(async _ => await StartLiveCaptureAsync(), _ => !IsBusy && !IsLiveCaptureActive && SelectedInterface is not null);
        StopLiveCaptureCommand = new RelayCommand(_ => StopLiveCapture(), _ => IsLiveCaptureActive);
        ReanalyzeCommand = new RelayCommand(async _ => await ReanalyzeAsync(), _ => !IsBusy && !IsLiveCaptureActive && _lastOfflinePackets.Count > 0);
        ResetThresholdsCommand = new RelayCommand(_ => ResetThresholds(), _ => !IsBusy);
        ResetDashboard();
        StartHostMonitor();
        AddLog("INFO", "Denia initialized.");
        _ = RefreshInterfacesAsync();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand OpenPcapCommand { get; }
    public ICommand ExportReportCommand { get; }
    public ICommand RefreshInterfacesCommand { get; }
    public ICommand StartLiveCaptureCommand { get; }
    public ICommand StopLiveCaptureCommand { get; }
    public ICommand ReanalyzeCommand { get; }
    public ICommand ResetThresholdsCommand { get; }

    public DetectionThresholds Thresholds { get; } = new();
    public ObservableCollection<NetworkInterfaceOption> NetworkInterfaces { get; } = new();
    public ObservableCollection<PacketRecord> PacketDump { get; } = new();
    public ObservableCollection<IpAnalysisResult> SuspiciousIps { get; } = new();
    public ObservableCollection<EndpointTrafficStat> TopSourceIps { get; } = new();
    public ObservableCollection<EndpointTrafficStat> TopDestinationIps { get; } = new();
    public ObservableCollection<AppLogEntry> AppLogs { get; } = new();
    public ObservableCollection<GeoTrafficFlow> GeoTrafficFlows { get; } = new();
    public ObservableCollection<SocAlert> SocAlerts { get; } = new();

    public ISeries[] TimelineSeries { get; private set; } = Array.Empty<ISeries>();
    public Axis[] TimelineXAxes { get; private set; } = Array.Empty<Axis>();
    public Axis[] TimelineYAxes { get; private set; } = Array.Empty<Axis>();
    public ISeries[] ProtocolSeries { get; private set; } = Array.Empty<ISeries>();
    public ISeries[] ResourceSeries { get; private set; } = Array.Empty<ISeries>();
    public Axis[] ResourceXAxes { get; private set; } = Array.Empty<Axis>();
    public Axis[] ResourceYAxes { get; private set; } = Array.Empty<Axis>();

    public AnalysisSummary Summary
    {
        get => _summary;
        private set
        {
            if (SetField(ref _summary, value))
            {
                OnPropertyChanged(nameof(AttackTypeDisplay));
                OnPropertyChanged(nameof(RiskScoreDisplay));
                (ExportReportCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                (OpenPcapCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (ExportReportCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (RefreshInterfacesCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (StartLiveCaptureCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (StopLiveCaptureCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (ReanalyzeCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (ResetThresholdsCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsLiveCaptureActive
    {
        get => _isLiveCaptureActive;
        private set
        {
            if (SetField(ref _isLiveCaptureActive, value))
            {
                OnPropertyChanged(nameof(LiveModeBadge));
                (OpenPcapCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (RefreshInterfacesCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (StartLiveCaptureCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (StopLiveCaptureCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (ReanalyzeCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public double Progress
    {
        get => _progress;
        private set => SetField(ref _progress, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    public string CurrentFile
    {
        get => _currentFile;
        private set => SetField(ref _currentFile, value);
    }

    public string LiveCaptureStatus
    {
        get => _liveCaptureStatus;
        private set => SetField(ref _liveCaptureStatus, value);
    }

    public HostResourceSnapshot HostResources
    {
        get => _hostResources;
        private set => SetField(ref _hostResources, value);
    }

    public NetworkInterfaceOption? SelectedInterface
    {
        get => _selectedInterface;
        set
        {
            if (SetField(ref _selectedInterface, value))
            {
                (StartLiveCaptureCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public string LiveModeBadge => IsLiveCaptureActive ? "LIVE MONITORING" : "DENIA READY";

    public string AttackTypeDisplay => Summary.AttackType switch
    {
        AttackType.TcpSynFlood => "TCP SYN Flood",
        AttackType.UdpFlood => "UDP Flood",
        AttackType.IcmpFlood => "ICMP Flood",
        AttackType.PortScan => "Port Scan",
        AttackType.RequestBurst => "Request Burst",
        AttackType.MixedDdos => "Mixed DDoS",
        _ => "None"
    };

    public string RiskScoreDisplay => $"{Summary.RiskScore}/100";

    private async Task OpenPcapAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open PCAP/PCAPNG",
            Filter = "Capture files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            IsBusy = true;
            Progress = 0;
            CurrentFile = dialog.FileName;
            StatusMessage = "Reading capture file...";
            ClearCollections();
            AddLog("INFO", $"Opening capture file: {Path.GetFileName(dialog.FileName)}");

            var progress = new Progress<double>(value => Progress = value);
            var packets = await _pcapReaderService.ReadAsync(dialog.FileName, progress);
            _lastOfflinePackets = packets;
            AddLog("INFO", $"Parsed {packets.Count:N0} packets from file.");

            StatusMessage = $"Running {Thresholds.WindowSeconds}-second sliding-window detection...";
            Summary = _detectionService.Analyze(packets, Path.GetFileName(dialog.FileName), Thresholds);

            LoadPacketDump(packets);
            LoadTablesAndCharts(packets);

            StatusMessage = Summary.TotalAlerts > 0
                ? $"Analysis complete. {Summary.TotalAlerts} suspicious source IP(s) found."
                : "Analysis complete. No strong DDoS trigger detected.";
            AddLog("INFO", $"Analysis complete: risk {Summary.RiskScore}/100, alerts {Summary.TotalAlerts}.");
        }
        catch (Exception ex)
        {
            StatusMessage = "Unable to read capture file.";
            AddLog("ERROR", $"Capture analysis failed: {ex.Message}");
            MessageBox.Show(
                $"Could not analyze this file.\n\n{ex.Message}",
                "Denia",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            Progress = IsBusy ? 100 : Progress;
            IsBusy = false;
            OnPropertyChanged(nameof(AttackTypeDisplay));
            OnPropertyChanged(nameof(RiskScoreDisplay));
        }
    }

    private async Task RefreshInterfacesAsync()
    {
        try
        {
            LiveCaptureStatus = "Checking TShark interfaces...";
            AddLog("INFO", "Refreshing TShark capture interfaces.");
            var interfaces = await _tsharkLiveCaptureService.GetInterfacesAsync();

            NetworkInterfaces.Clear();
            foreach (var item in interfaces)
            {
                NetworkInterfaces.Add(item);
            }

            SelectedInterface = NetworkInterfaces.FirstOrDefault();
            LiveCaptureStatus = NetworkInterfaces.Count == 0
                ? "TShark is available, but no capture interfaces were returned."
                : $"Found {NetworkInterfaces.Count} capture interface(s).";
            AddLog("INFO", LiveCaptureStatus);
        }
        catch (Win32Exception)
        {
            LiveCaptureStatus = "TShark not found. Install Wireshark and add tshark.exe to PATH.";
            AddLog("WARN", LiveCaptureStatus);
        }
        catch (Exception ex)
        {
            LiveCaptureStatus = $"Unable to list interfaces: {ex.Message}";
            AddLog("ERROR", LiveCaptureStatus);
        }
    }

    private async Task StartLiveCaptureAsync()
    {
        if (SelectedInterface is null)
        {
            return;
        }

        ClearCollections();
        lock (_livePacketsLock)
        {
            _livePackets.Clear();
        }
        Summary = new AnalysisSummary { SourceFile = "Live capture", AnalyzedAt = DateTime.Now };
        CurrentFile = $"Live: {SelectedInterface.DisplayName}";
        StatusMessage = "Starting realtime capture...";
        Progress = 0;
        _lastOfflinePackets = Array.Empty<PacketRecord>();
        _parsedLivePacketCount = 0;
        _queuedSinceLastUiTick = 0;
        AddLog("INFO", $"Starting live capture on {SelectedInterface.DisplayName}.");
        while (_livePacketQueue.TryDequeue(out _))
        {
        }

        _liveCaptureCts = new CancellationTokenSource();
        IsLiveCaptureActive = true;
        StartLiveUiPump();
        StartLiveAnalysisLoop(_liveCaptureCts.Token);

        try
        {
            await _tsharkLiveCaptureService.StartCaptureAsync(
                SelectedInterface,
                packet =>
                {
                    _livePacketQueue.Enqueue(packet);
                    Interlocked.Increment(ref _queuedSinceLastUiTick);
                    Interlocked.Increment(ref _parsedLivePacketCount);
                    return Task.CompletedTask;
                },
                message => Application.Current.Dispatcher.Invoke(() =>
                {
                    LiveCaptureStatus = message;
                    StatusMessage = message;
                    AddLog("INFO", message);
                }),
                _liveCaptureCts.Token);
        }
        catch (Win32Exception)
        {
            LiveCaptureStatus = "TShark not found. Install Wireshark and add tshark.exe to PATH.";
            StatusMessage = LiveCaptureStatus;
            AddLog("ERROR", LiveCaptureStatus);
        }
        catch (Exception ex)
        {
            LiveCaptureStatus = $"Live capture error: {ex.Message}";
            StatusMessage = LiveCaptureStatus;
            AddLog("ERROR", LiveCaptureStatus);
        }
        finally
        {
            IsLiveCaptureActive = false;
            StopLiveUiPump();
            _liveCaptureCts?.Dispose();
            _liveCaptureCts = null;
            AddLog("INFO", "Live capture task ended.");
            OnPropertyChanged(nameof(AttackTypeDisplay));
            OnPropertyChanged(nameof(RiskScoreDisplay));
        }
    }

    private void StopLiveCapture()
    {
        _liveCaptureCts?.Cancel();
        _tsharkLiveCaptureService.StopCapture();
        StopLiveUiPump();
        IsLiveCaptureActive = false;
        LiveCaptureStatus = "Live capture stopped.";
        StatusMessage = "Live capture stopped.";
        AddLog("INFO", "Live capture stopped.");
    }

    private void StartLiveUiPump()
    {
        _liveUiTimer?.Stop();
        _liveUiTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _liveUiTimer.Tick += (_, _) => DrainLivePacketsToUi();
        _liveUiTimer.Start();
    }

    private void StopLiveUiPump()
    {
        if (_liveUiTimer is null)
        {
            return;
        }

        _liveUiTimer.Stop();
        _liveUiTimer = null;
    }

    private void DrainLivePacketsToUi()
    {
        const int maxUiRowsPerTick = 250;
        var drained = new List<PacketRecord>(maxUiRowsPerTick);

        while (drained.Count < maxUiRowsPerTick && _livePacketQueue.TryDequeue(out var packet))
        {
            drained.Add(packet);
        }

        if (drained.Count == 0)
        {
            return;
        }

        lock (_livePacketsLock)
        {
            _livePackets.AddRange(drained);
            if (_livePackets.Count > 12000)
            {
                _livePackets.RemoveRange(0, _livePackets.Count - 12000);
            }
        }

        foreach (var packet in drained)
        {
            PacketDump.Add(packet);
        }

        while (PacketDump.Count > 1200)
        {
            PacketDump.RemoveAt(0);
        }

        var parsed = Volatile.Read(ref _parsedLivePacketCount);
        var queued = Volatile.Read(ref _queuedSinceLastUiTick);
        StatusMessage = $"Live monitoring: {parsed} packets parsed, UI batch {drained.Count}, queue {Math.Max(0, queued - drained.Count)}.";
        Interlocked.Add(ref _queuedSinceLastUiTick, -drained.Count);
    }

    private void StartLiveAnalysisLoop(CancellationToken cancellationToken)
    {
        _liveAnalysisTask = Task.Run(async () =>
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);

                    List<PacketRecord> snapshot;
                    lock (_livePacketsLock)
                    {
                        snapshot = _livePackets
                            .Where(packet => DateTime.Now - packet.Time <= TimeSpan.FromMinutes(2))
                            .ToList();
                    }

                    if (snapshot.Count == 0)
                    {
                        continue;
                    }

                    var summary = _detectionService.Analyze(snapshot, "Live capture", Thresholds);
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        Summary = summary;
                        LoadRealtimeTablesAndCharts(snapshot);
                        StatusMessage = Summary.TotalAlerts > 0
                            ? $"Live monitoring: {Summary.TotalAlerts} suspicious source IP(s), {Volatile.Read(ref _parsedLivePacketCount)} packets parsed."
                            : $"Live monitoring: {Volatile.Read(ref _parsedLivePacketCount)} packets parsed.";
                        if (DateTime.Now - _lastAnalysisLog > TimeSpan.FromSeconds(5))
                        {
                            AddLog("INFO", $"Realtime analysis: {snapshot.Count:N0} recent packets, risk {Summary.RiskScore}/100, alerts {Summary.TotalAlerts}.");
                            _lastAnalysisLog = DateTime.Now;
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        LiveCaptureStatus = $"Realtime analysis error: {ex.Message}";
                        AddLog("ERROR", LiveCaptureStatus);
                    });
                }
            }
        }, cancellationToken);
    }

    private void StartHostMonitor()
    {
        _hostMonitorTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _hostMonitorTimer.Tick += (_, _) =>
        {
            HostResources = _hostResourceMonitorService.Sample();
            AddResourceSample(HostResources);
        };
        _hostMonitorTimer.Start();
    }

    private void AddResourceSample(HostResourceSnapshot snapshot)
    {
        const int maxSamples = 90;
        _cpuHistory.Add(Math.Round(snapshot.CpuPercent, 1));
        _ramHistory.Add(Math.Round(snapshot.RamPercent, 1));
        _diskHistory.Add(Math.Round(snapshot.DiskPercent, 1));

        Trim(_cpuHistory);
        Trim(_ramHistory);
        Trim(_diskHistory);
        BuildResourceChart();

        static void Trim(List<double> values)
        {
            if (values.Count > maxSamples)
            {
                values.RemoveRange(0, values.Count - maxSamples);
            }
        }
    }

    private void LoadRealtimeTablesAndCharts(IReadOnlyList<PacketRecord> packets)
    {
        SuspiciousIps.Clear();
        foreach (var ip in Summary.SuspiciousIps.Take(20))
        {
            SuspiciousIps.Add(ip);
        }

        LoadEndpointStats(TopSourceIps, packets.GroupBy(p => p.SourceIp), packets.Count);
        LoadEndpointStats(TopDestinationIps, packets.GroupBy(p => p.DestinationIp), packets.Count);
        BuildTimelineChart(packets);
        BuildProtocolChart(packets);
        BuildSocAlerts();
        ScheduleGeoTrafficUpdate(packets);

        OnPropertyChanged(nameof(AttackTypeDisplay));
        OnPropertyChanged(nameof(RiskScoreDisplay));
    }

    private void ExportReport()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export Report",
            FileName = $"ddos-report-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text report (*.txt)|*.txt|CSV evidence (*.csv)|*.csv"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            if (Path.GetExtension(dialog.FileName).Equals(".csv", StringComparison.OrdinalIgnoreCase))
            {
                _reportExportService.ExportCsv(dialog.FileName, Summary);
            }
            else
            {
                _reportExportService.ExportText(dialog.FileName, Summary);
            }

            StatusMessage = $"Report exported: {dialog.FileName}";
            AddLog("INFO", $"Report exported: {Path.GetFileName(dialog.FileName)}");
        }
        catch (Exception ex)
        {
            AddLog("ERROR", $"Report export failed: {ex.Message}");
            MessageBox.Show(
                $"Could not export report.\n\n{ex.Message}",
                "Denia",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private async Task ReanalyzeAsync()
    {
        if (_lastOfflinePackets.Count == 0)
        {
            StatusMessage = "Open a PCAP/PCAPNG file before reanalyzing thresholds.";
            AddLog("WARN", StatusMessage);
            return;
        }

        try
        {
            IsBusy = true;
            StatusMessage = $"Reanalyzing with {Thresholds.WindowSeconds}s window and custom triggers...";
            AddLog("INFO", "Manual trigger thresholds applied. Reanalyzing current capture.");
            var packets = _lastOfflinePackets;
            var sourceFile = string.IsNullOrWhiteSpace(Summary.SourceFile) ? "Offline capture" : Summary.SourceFile;

            Summary = await Task.Run(() => _detectionService.Analyze(packets, sourceFile, Thresholds));
            LoadPacketDump(packets);
            LoadTablesAndCharts(packets);

            StatusMessage = $"Reanalysis complete. Risk {Summary.RiskScore}/100, alerts {Summary.TotalAlerts}.";
            AddLog("INFO", StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = "Reanalysis failed.";
            AddLog("ERROR", $"Reanalysis failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ResetThresholds()
    {
        Thresholds.Reset();
        AddLog("INFO", "Trigger thresholds reset to defaults.");
    }

    private void LoadPacketDump(IReadOnlyList<PacketRecord> packets)
    {
        PacketDump.Clear();
        foreach (var packet in packets.Take(5000))
        {
            PacketDump.Add(packet);
        }
    }

    private void LoadTablesAndCharts(IReadOnlyList<PacketRecord> packets)
    {
        SuspiciousIps.Clear();
        foreach (var ip in Summary.SuspiciousIps.Take(25))
        {
            SuspiciousIps.Add(ip);
        }

        LoadEndpointStats(TopSourceIps, packets.GroupBy(p => p.SourceIp), packets.Count);
        LoadEndpointStats(TopDestinationIps, packets.GroupBy(p => p.DestinationIp), packets.Count);
        BuildTimelineChart(packets);
        BuildProtocolChart(packets);
        BuildSocAlerts();
        ScheduleGeoTrafficUpdate(packets, force: true);

        OnPropertyChanged(nameof(AttackTypeDisplay));
        OnPropertyChanged(nameof(RiskScoreDisplay));
    }

    private static void LoadEndpointStats(
        ObservableCollection<EndpointTrafficStat> target,
        IEnumerable<IGrouping<string, PacketRecord>> groups,
        int totalPackets)
    {
        target.Clear();
        foreach (var item in groups
                     .Where(g => g.Key != "-")
                     .OrderByDescending(g => g.Count())
                     .Take(12)
                     .Select(g => new EndpointTrafficStat
                     {
                         IpAddress = g.Key,
                         PacketCount = g.Count(),
                         Share = totalPackets == 0 ? 0 : Math.Round(g.Count() * 100.0 / totalPackets, 1)
                     }))
        {
            target.Add(item);
        }
    }

    private void BuildTimelineChart(IReadOnlyList<PacketRecord> packets)
    {
        var buckets = packets
            .GroupBy(p => new DateTime(p.Time.Year, p.Time.Month, p.Time.Day, p.Time.Hour, p.Time.Minute, p.Time.Second))
            .OrderBy(g => g.Key)
            .Take(180)
            .ToList();

        TimelineSeries = new ISeries[]
        {
            new LineSeries<int>
            {
                Name = "Packets/s",
                Values = buckets.Select(g => g.Count()).ToArray(),
                Fill = new SolidColorPaint(new SKColor(0, 215, 255, 50)),
                Stroke = new SolidColorPaint(new SKColor(0, 215, 255), 3),
                GeometrySize = 0
            }
        };

        TimelineXAxes = new[]
        {
            new Axis
            {
                Labels = buckets.Select(g => g.Key.ToString("HH:mm:ss")).ToArray(),
                LabelsPaint = new SolidColorPaint(new SKColor(156, 172, 190)),
                SeparatorsPaint = new SolidColorPaint(new SKColor(31, 43, 61)),
                TextSize = 11
            }
        };

        TimelineYAxes = new[]
        {
            new Axis
            {
                LabelsPaint = new SolidColorPaint(new SKColor(156, 172, 190)),
                SeparatorsPaint = new SolidColorPaint(new SKColor(31, 43, 61)),
                TextSize = 11,
                MinLimit = 0
            }
        };

        OnPropertyChanged(nameof(TimelineSeries));
        OnPropertyChanged(nameof(TimelineXAxes));
        OnPropertyChanged(nameof(TimelineYAxes));
    }

    private void BuildProtocolChart(IReadOnlyList<PacketRecord> packets)
    {
        int Count(string protocol) => packets.Count(p => p.Protocol == protocol);
        var tcp = Count("TCP");
        var udp = Count("UDP");
        var icmp = Count("ICMP");
        var other = Math.Max(0, packets.Count - tcp - udp - icmp);

        ProtocolSeries = new ISeries[]
        {
            new PieSeries<int> { Name = "TCP", Values = new[] { tcp }, Fill = new SolidColorPaint(new SKColor(0, 215, 255)), InnerRadius = 36 },
            new PieSeries<int> { Name = "UDP", Values = new[] { udp }, Fill = new SolidColorPaint(new SKColor(255, 139, 45)), InnerRadius = 36 },
            new PieSeries<int> { Name = "ICMP", Values = new[] { icmp }, Fill = new SolidColorPaint(new SKColor(255, 67, 87)), InnerRadius = 36 },
            new PieSeries<int> { Name = "Other", Values = new[] { other }, Fill = new SolidColorPaint(new SKColor(128, 146, 170)), InnerRadius = 36 }
        };

        OnPropertyChanged(nameof(ProtocolSeries));
    }

    private void BuildResourceChart()
    {
        ResourceSeries = new ISeries[]
        {
            new LineSeries<double>
            {
                Name = "CPU",
                Values = _cpuHistory.ToArray(),
                Fill = null,
                Stroke = new SolidColorPaint(new SKColor(0, 215, 255), 2),
                GeometrySize = 0
            },
            new LineSeries<double>
            {
                Name = "RAM",
                Values = _ramHistory.ToArray(),
                Fill = null,
                Stroke = new SolidColorPaint(new SKColor(255, 139, 45), 2),
                GeometrySize = 0
            },
            new LineSeries<double>
            {
                Name = "DISK",
                Values = _diskHistory.ToArray(),
                Fill = null,
                Stroke = new SolidColorPaint(new SKColor(49, 220, 167), 2),
                GeometrySize = 0
            }
        };

        ResourceXAxes = new[]
        {
            new Axis
            {
                LabelsPaint = new SolidColorPaint(new SKColor(125, 145, 170)),
                SeparatorsPaint = new SolidColorPaint(new SKColor(31, 43, 61, 100)),
                TextSize = 9,
                LabelsRotation = 0
            }
        };

        ResourceYAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = 100,
                LabelsPaint = new SolidColorPaint(new SKColor(125, 145, 170)),
                SeparatorsPaint = new SolidColorPaint(new SKColor(31, 43, 61)),
                TextSize = 10
            }
        };

        OnPropertyChanged(nameof(ResourceSeries));
        OnPropertyChanged(nameof(ResourceXAxes));
        OnPropertyChanged(nameof(ResourceYAxes));
    }

    private void BuildSocAlerts()
    {
        SocAlerts.Clear();
        foreach (var result in Summary.SuspiciousIps
                     .Where(result => result.AttackType is AttackType.PortScan or AttackType.RequestBurst ||
                                      result.RiskScore >= 70 ||
                                      result.UniqueDestinationPorts >= Thresholds.PortScanUniqueDestinationPortsThreshold)
                     .Take(12))
        {
            SocAlerts.Add(new SocAlert
            {
                Severity = result.Severity,
                Title = result.AttackType switch
                {
                    AttackType.PortScan => "Inbound scan / reconnaissance",
                    AttackType.RequestBurst => "High request burst",
                    AttackType.TcpSynFlood => "TCP SYN flood signal",
                    AttackType.UdpFlood => "UDP flood signal",
                    AttackType.IcmpFlood => "ICMP flood signal",
                    _ => "Elevated SOC signal"
                },
                SourceIp = result.SourceIp,
                Detail = $"{result.PacketsPerSecond:0.0} pps, {result.UniqueDestinationPorts} dst ports, {result.UniqueDestinationIps} dst IPs",
                RiskScore = result.RiskScore
            });
        }
    }

    private void ScheduleGeoTrafficUpdate(IReadOnlyList<PacketRecord> packets, bool force = false)
    {
        if (!force && DateTime.Now - _lastGeoUpdate < TimeSpan.FromSeconds(10))
        {
            return;
        }

        _lastGeoUpdate = DateTime.Now;
        var version = Interlocked.Increment(ref _geoUpdateVersion);
        var flows = packets
            .Where(p => p.SourceIp != "-" && p.DestinationIp != "-")
            .GroupBy(p => new { p.SourceIp, p.DestinationIp })
            .OrderByDescending(g => g.Count())
            .Take(8)
            .Select(g => new
            {
                g.Key.SourceIp,
                g.Key.DestinationIp,
                Count = g.Count(),
                Protocol = g.GroupBy(p => p.Protocol).OrderByDescending(pg => pg.Count()).Select(pg => pg.Key).FirstOrDefault() ?? "Mixed",
                Severity = g.Max(p => p.Severity)
            })
            .ToList();
        var endpointIps = TopSourceIps
            .Concat(TopDestinationIps)
            .Select(stat => stat.IpAddress)
            .Where(ip => ip != "-")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(24)
            .ToList();

        _ = Task.Run(async () =>
        {
            var geoFlows = new List<GeoTrafficFlow>();
            var geoAlerts = new Dictionary<string, GeoLocationInfo>(StringComparer.OrdinalIgnoreCase);
            var endpointGeo = new Dictionary<string, GeoLocationInfo>(StringComparer.OrdinalIgnoreCase);

            foreach (var flow in flows)
            {
                var source = await _ipGeoLookupService.LookupAsync(flow.SourceIp);
                var destination = await _ipGeoLookupService.LookupAsync(flow.DestinationIp);
                geoAlerts[flow.SourceIp] = source;
                geoFlows.Add(new GeoTrafficFlow
                {
                    SourceIp = flow.SourceIp,
                    DestinationIp = flow.DestinationIp,
                    SourceLocation = source.DisplayName,
                    DestinationLocation = destination.DisplayName,
                    SourceLatitude = source.Latitude,
                    SourceLongitude = source.Longitude,
                    DestinationLatitude = destination.Latitude,
                    DestinationLongitude = destination.Longitude,
                    PacketCount = flow.Count,
                    Protocol = flow.Protocol,
                    Severity = flow.Severity
                });
            }

            foreach (var ip in endpointIps)
            {
                endpointGeo[ip] = await _ipGeoLookupService.LookupAsync(ip);
            }

            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                if (version != Volatile.Read(ref _geoUpdateVersion))
                {
                    return;
                }

                GeoTrafficFlows.Clear();
                foreach (var flow in geoFlows)
                {
                    GeoTrafficFlows.Add(flow);
                }

                ApplyEndpointLocations(TopSourceIps, endpointGeo);
                ApplyEndpointLocations(TopDestinationIps, endpointGeo);

                for (var i = 0; i < SocAlerts.Count; i++)
                {
                    var alert = SocAlerts[i];
                    if (!geoAlerts.TryGetValue(alert.SourceIp, out var geo))
                    {
                        continue;
                    }

                    SocAlerts[i] = new SocAlert
                    {
                        Time = alert.Time,
                        Severity = alert.Severity,
                        Title = alert.Title,
                        SourceIp = alert.SourceIp,
                        Location = geo.DisplayName,
                        Detail = alert.Detail,
                        RiskScore = alert.RiskScore
                    };
                }
            });
        });
    }

    private static void ApplyEndpointLocations(
        ObservableCollection<EndpointTrafficStat> target,
        IReadOnlyDictionary<string, GeoLocationInfo> locations)
    {
        for (var i = 0; i < target.Count; i++)
        {
            var item = target[i];
            if (!locations.TryGetValue(item.IpAddress, out var location))
            {
                continue;
            }

            target[i] = new EndpointTrafficStat
            {
                IpAddress = item.IpAddress,
                PacketCount = item.PacketCount,
                Share = item.Share,
                Location = location.DisplayName
            };
        }
    }

    private void ClearCollections()
    {
        PacketDump.Clear();
        SuspiciousIps.Clear();
        TopSourceIps.Clear();
        TopDestinationIps.Clear();
        GeoTrafficFlows.Clear();
        SocAlerts.Clear();
    }

    private void ResetDashboard()
    {
        Summary = new AnalysisSummary();
        BuildTimelineChart(Array.Empty<PacketRecord>());
        BuildProtocolChart(Array.Empty<PacketRecord>());
        BuildResourceChart();
    }

    private void AddLog(string level, string message)
    {
        void Add()
        {
            AppLogs.Insert(0, new AppLogEntry
            {
                Level = level,
                Message = message,
                Time = DateTime.Now
            });

            while (AppLogs.Count > 300)
            {
                AppLogs.RemoveAt(AppLogs.Count - 1);
            }
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            Add();
        }
        else
        {
            dispatcher.Invoke(Add);
        }
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public void Dispose()
    {
        StopLiveCapture();
        _hostMonitorTimer?.Stop();
        _liveCaptureCts?.Dispose();
    }
}
