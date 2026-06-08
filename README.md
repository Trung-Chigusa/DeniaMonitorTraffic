# Denia Monitor Traffic

Denia Monitor Traffic là ứng dụng WPF chạy trên Windows dùng để phân tích file
`PCAP/PCAPNG`, theo dõi lưu lượng mạng nội bộ ở chế độ thụ động bằng TShark, và
hiển thị các dấu hiệu bất thường liên quan đến SYN flood, UDP flood, ICMP flood
hoặc mixed DDoS. Ứng dụng chỉ phục vụ phân tích/phòng thủ, không tạo traffic tấn
công.

## Chức năng chính

- Mở và phân tích file `.pcap` hoặc `.pcapng`.
- Theo dõi realtime interface mạng cục bộ thông qua `tshark`.
- Dashboard tổng quan: tổng packet, IP nghi vấn, victim IP, loại cảnh báo và risk score.
- Bảng packet chi tiết gồm thời gian, IP nguồn/đích, protocol, port, TCP flags, độ dài và lý do cảnh báo.
- Biểu đồ timeline và phân bố protocol bằng LiveChartsCore.
- SOC watchlist cho port scan, request burst và flood signal rủi ro cao.
- Theo dõi tài nguyên máy: CPU, RAM, disk.
- Tra cứu vị trí IP ở mức nhãn hiển thị khi có kết nối internet.
- Cho phép chỉnh threshold phát hiện trong UI.
- Xuất báo cáo dạng `.txt` hoặc `.csv`.

## Yêu cầu

- Windows 10/11.
- .NET 8 SDK nếu chạy từ source.
- Wireshark/Npcap nếu muốn dùng realtime capture.

Realtime mode là chế độ nghe thụ động trên card mạng local. App không gửi packet
và không tạo lưu lượng tấn công.

## Chạy từ source

```powershell
dotnet restore
dotnet run --project .\DdosTriggerAnalyzer.csproj
```

Hoặc build trước:

```powershell
dotnet build .\DdosTriggerAnalyzer.csproj
```

## Đóng gói EXE

```powershell
dotnet publish .\DdosTriggerAnalyzer.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

File chạy được tạo tại:

```text
bin\Release\net8.0-windows\win-x64\publish\Denia.exe
```

## Cách dùng nhanh

1. Mở app Denia.
2. Chọn **Open PCAP** để nạp file capture.
3. Có thể dùng file mẫu `Samples\sample-syn-flood.pcap` để kiểm tra chức năng phát hiện.
4. Điều chỉnh threshold nếu cần, rồi chọn **Apply**.
5. Xem dashboard, biểu đồ, packet dump, bảng top IP và log runtime.
6. Chọn **Export Report** để xuất báo cáo.

## Realtime Capture

1. Cài Wireshark và bật TShark.
2. Mở app bằng quyền Administrator nếu máy không liệt kê được interface.
3. Chọn **Refresh NICs**.
4. Chọn interface cần theo dõi.
5. Chọn **Live** để bắt đầu, **Stop** để dừng.

Nếu cần đặt `tshark.exe` thủ công, xem thư mục `Tools\Wireshark`.

## Cấu trúc thư mục

- `Models/`: model dữ liệu, threshold, kết quả phân tích và cảnh báo.
- `Services/`: đọc PCAP, capture realtime, phát hiện bất thường, export report.
- `ViewModels/`: logic điều khiển màn hình chính.
- `Views/`: giao diện WPF.
- `Assets/`: hình ảnh và icon dùng trong ứng dụng.
- `Samples/`: file PCAP mẫu để kiểm tra offline.
- `Portable/`: script hỗ trợ chạy bản publish.

## Ghi chú

Repo này chỉ chứa source và file cần thiết để build/chạy app. Các file build
tạm, `bin/`, `obj/`, ảnh minh chứng, tài liệu điểm/chấm bài và file zip đóng gói
sẵn không được đưa vào Git.
