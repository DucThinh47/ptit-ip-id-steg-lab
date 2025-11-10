# Lab: Giấu tin trong mạng sử dụng sử dụng trường IP Identification
## Lý thuyết
**1. Lý thuyết "Kênh ẩn" (Covert Channel)**
Lý thuyết cốt lõi là tạo ra `một kênh ẩn (covert channel)`.
- `Kênh hợp lệ`: Là luồng gói tin `IP/TCP` thông thường.
- `Kênh ẩn`: Được tạo ra bằng cách cố ý thao túng giá trị của trường `Identification (ID)` trong `IP Header`.
- `Đồng bộ`: Bên gửi `(send_stego.py)` và bên nhận `(detect_stego.py)` phải thống nhất trước về quy tắc mã hóa bí mật này.

**2. Nguyên tắc "Tạo Bất thường có chủ đích" (Deliberate Anomaly)**

Đây là một cách tiếp cận khác biệt so với `kỹ thuật LSB`. Thay vì cố gắng trông bình thường, kỹ thuật này tạo ra một sự bất thường rõ ràng nhưng nhất quán.
- `Hành vi thông thường`: Bài lab chỉ ra rằng trường `IP ID` thường có giá trị "ngẫu nhiên hoặc tăng dần". Đây là hành vi chuẩn của hệ điều hành để định danh các gói tin (hoặc các phân mảnh của gói tin).
- `Hành vi Bất thường (Kênh ẩn)`: Kỹ thuật này phá vỡ quy tắc đó. Nó cố định giá trị của trường `IP ID` vào một tập rất cụ thể: `{20000, 20001}`.
- Lý do chọn giá trị:
    - `Tránh xung đột`: Các giá trị này `(20000, 20001)` được chọn vì chúng "không phổ biến" và "ít bị trùng" với các giá trị ID thực tế do hệ thống tạo ra (thường bắt đầu từ 0 và tăng dần).
    - `Dễ lọc`: Giúp bên nhận (và cả người phân tích) dễ dàng lọc ra các gói tin thuộc kênh ẩn bằng bộ lọc Wireshark (`ip.id == 20000` || `ip.id == 20001`).

**3. Kỹ thuật "Mã hóa Chẵn-Lẻ" (Even-Odd Parity Encoding)**

Thay vì dùng `bit LSB`, kỹ thuật này sử dụng một quy tắc mã hóa đơn giản dựa trên tính chẵn/lẻ của các giá trị đã chọn:
- `Bit 0`: Được đại diện bởi một `giá trị chẵn` -> `20000`.
- `Bit 1`: Được đại diện bởi một `giá trị lẻ` -> `20001`.

Đây là một quy tắc mã hóa nhị phân rất rõ ràng và dễ dàng cho việc giải mã.

**4. Nguyên tắc "Phát hiện dựa trên Độ lệch" (Deviation-Based Detection)**

Bài lab này minh họa rõ ràng cách phát hiện kênh ẩn bằng cách so sánh với một `đường cơ sở (baseline)`.
- `Tạo Baseline`: `send_normal.py` được chạy để tạo ra file `normal_packets.pcap`. Đây là mẫu lưu lượng mạng "sạch", cho thấy trường `IP ID` tăng dần hoặc ngẫu nhiên.
- `Phân tích độ lệch`: `send_stego.py` tạo ra file `stego_packets.pcap`. Khi phân tích file này, người ta sẽ thấy ngay sự "bất thường": trường `IP ID` không còn tăng dần/ngẫu nhiên nữa, mà bị "kẹt" cứng ở hai giá trị `20000` và `20001`.
- `Công cụ phát hiện`: Script `detect_stego.py` chính là một công cụ phân tích tự động, được lập trình để tìm kiếm chính xác sự độ lệch này (sự xuất hiện của các giá trị `20000/20001`) để báo hiệu có kênh ẩn.

**5. Lý thuyết "Toàn vẹn Thông điệp Lớp Ẩn" (Covert Layer Integrity)**

Chuỗi bits của thông điệp sẽ dài hơn bình thường do việc thêm `checksum 16-bit` để xác thực tính toàn vẹn của tin nhắn.
- `Ý nghĩa`: Bản thân kênh ẩn (thao túng `IP ID`) chỉ là phương tiện "vận chuyển" các bit `0` và `1`. Nó không đảm bảo rằng các bit này đến đúng thứ tự hoặc không bị mất (do packet loss).
- `Giải pháp`: Bên gửi và bên nhận tự xây dựng một "giao thức" cấp cao hơn (ẩn bên trong kênh ẩn). Việc thêm checksum cho phép bên nhận (`decode_bits.py`) kiểm tra xem chuỗi bit mà nó nhận được có bị lỗi hay không, đảm bảo thông điệp được giải mã là chính xác.
## Thực hành
Trên máy `receiver`, thực hiện mở `Wireshark`:

    wireshark &

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image0.png?raw=true)

Trên máy `sender`, thực thi file `send_normal.py` để thực hiện gửi gói tin:

    sudo python3 send_normal.py

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image1.png?raw=true)

Sau khi gửi xong, bấm dừng bắt gói tin trên `Wireshark`. Quan sát, đánh giá giá trị của trường `Identification` trên `Wireshark`:

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image2.png?raw=true)

(Có thể sử dụng bộ lọc `tcp && ip.src == 175.30.0.10` để quan sát dễ hơn) Tiếp theo, trên `Wireshark`, lưu thành file `normal_packets.pcap`:

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image3.png?raw=true)

Trên máy `receiver`, thực thi file `detect_stego.py` để xác nhận file `normal_packets` không có các gói tin chứa thông điệp ẩn:

    sudo python3 detect_stego.py normal_packets.pcapng

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image4.png?raw=true)

Thực hiện bắt gói tin mới trên `Wireshark`. Trên máy `sender`, thực thi file `send_stego.py` để gửi các gói chứa thông điệp ẩn:

    sudo python3 send_stego.py <ip_máy_receiver> <message>

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image5.png?raw=true)

Quan sát trên `Wireshark`:

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image6.png?raw=true)

Dừng bắt gói tin trên `Wireshark`, lưu file `stego_packets.pcap`:

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image7.png?raw=true)

Trên máy `receiver`, thực thi file `detect_stego.py`, xác nhận file pcap có gói tin chứa thông điệp ẩn:

    sudo python3 detect_stego.py stego_packets.pcapng

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image8.png?raw=true)

Thực hiện bắt lưu lượng mới trên `Wireshark`. Trên máy sender, thực thi file `send_hidden_mess.py`:

    sudo python3 send_hidden_mess.py <ip_máy_receiver>

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image9.png?raw=true)

Sau khi gửi xong, dừng bắt gói tin trên `Wireshark`:

![img](https://github.com/DucThinh47/ptit-ip-id-steg-lab/blob/main/images/image10.png?raw=true)

Thực hiện phân tích các gói tin, tìm ra giá trị bits của thông điệp ẩn. Sau khi có được giá trị bits của thông điệp ẩn, trên máy `receiver`, thực thi file `decode_bits.py` để tìm ra thông điệp:

    python3 decode_bits.py






