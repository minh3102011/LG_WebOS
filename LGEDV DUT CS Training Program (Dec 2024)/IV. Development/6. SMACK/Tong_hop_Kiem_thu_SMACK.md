
# Tổng hợp Nội dung Trao đổi và Kế hoạch Kiểm thử SMACK

Tài liệu này tổng hợp lại toàn bộ quá trình thảo luận và vạch ra một kế hoạch chi tiết để thực hiện kiểm thử SMACK dựa trên các tài liệu được cung cấp.

---

## 1. Tổng hợp kiến thức về SMACK (Từ file LGEDV-SMACK.pdf)

**Yêu cầu:**
> Dựa vào tài liệu LGEDV-SMACK.pdf cho tôi tổng hợp những kiến thức.

**Phản hồi:**
Dựa vào tài liệu, kiến thức chính về SMACK (Simplified Mandatory Access Control Kernel) được tổng hợp như sau:

*   **Tổng quan:** SMACK là một module bảo mật của Linux (LSM) triển khai Kiểm soát Truy cập Bắt buộc (MAC) dựa trên nhãn (label), phù hợp cho hệ thống nhúng vì tính đơn giản và hiệu quả.
*   **Thuật ngữ cốt lõi:**
    *   **Subject:** Tiến trình muốn truy cập.
    *   **Object:** Tài nguyên bị truy cập.
    *   **Label:** Nhãn định danh quyền (Access Label cho object, Execute Label cho subject).
    *   **Rule:** Luật truy cập theo định dạng: `Subject_Label Object_Label Access_Type`.
    *   **Access:** Các quyền truy cập (`r, w, x, a, l, t, b`).
*   **Các chế độ hoạt động:**
    *   **Enforce Mode (Mặc định):** Thực thi luật, từ chối và ghi log các truy cập trái phép.
    *   **Permissive Mode:** Cho phép mọi hành động nhưng vẫn ghi log, dùng để gỡ lỗi.
    *   **Bring-up Mode:** Ghi log cả hành động được phép và bị từ chối nếu luật có quyền `b`.
*   **Tính năng khác:**
    *   **Denial Log:** Ghi lại chi tiết các truy cập bị từ chối vào `audit.log`.
    *   **Onlycap Mode:** Hạn chế quyền của `root`, không cho phép sửa đổi nhãn/luật trừ các nhãn đặc quyền.
    *   **Transmute Option:** Cho phép file/thư mục con kế thừa nhãn của thư mục cha.

---

## 2. Phân tích hướng đi và lập Checklist

**Yêu cầu:**
> Kết hợp 3 file `LGEDV-SMACK.pdf`, `12.1/ Smack/ Test/ Specification_v1.pdf` và `12.2/ Task/ and/ Test/ case/ Example_v1.pdf` để đưa ra hướng cần đi và lập checklist.

**Phản hồi:**
Hướng đi được xác định bằng cách phân vai trò cho từng tài liệu:
1.  **`Specification.pdf` ("CÁI GÌ?"):** Định nghĩa phạm vi, mục tiêu, các hạng mục cần kiểm thử.
2.  **`Example.pdf` ("NHƯ THẾ NÀO?"):** Cung cấp ví dụ thực tế, phương pháp luận để chuyển yêu cầu thành test case.
3.  **`LGEDV-SMACK.pdf` ("BẰNG CÁI GÌ?"):** Cung cấp kiến thức kỹ thuật sâu về công cụ, lệnh và cơ chế hoạt động.

**Checklist thực hiện:**

#### **Giai đoạn 1: Phân tích & Lập kế hoạch**
*   [ ] **1.1. Phân tích Đặc tả:** Đọc `Specification.pdf` và lập "Master Checklist" các hạng mục cần test.
*   [ ] **1.2. Nghiên cứu Ví dụ:** Đọc `Example.pdf` để học phương pháp luận (đặt tên nhãn, viết luật, cách xác minh kết quả).
*   [ ] **1.3. Đối chiếu Kỹ thuật:** Dùng `LGEDV-SMACK.pdf` để hiểu sâu các lệnh/khái niệm trong file ví dụ.

#### **Giai đoạn 2: Chuẩn bị Môi trường**
*   [ ] **2.1. Thiết lập Hệ thống:** Chuẩn bị môi trường Linux có kích hoạt SMACK.
*   [ ] **2.2. Tạo Tài nguyên:** Tạo file, thư mục, user giả lập và script dọn dẹp (`cleanup.sh`).

#### **Giai đoạn 3: Thiết kế & Thực thi Test Case**
*   [ ] **3.1. Thực thi lại Test Case Mẫu:** Chạy lại các ví dụ để xác nhận môi trường và cách hiểu đã đúng.
*   [ ] **3.2. Thiết kế Test Case còn lại:** Dựa vào "Master Checklist", thiết kế các test case mới cho những hạng mục chưa được kiểm thử.
*   [ ] **3.3. Thực thi Test Case mới:** Chạy và ghi nhận kết quả (Pass/Fail).

#### **Giai đoạn 4: Báo cáo & Hoàn tất**
*   [ ] **4.1. Tổng hợp Kết quả:** Cập nhật trạng thái Pass/Fail vào "Master Checklist".
*   [ ] **4.2. Viết Báo cáo Lỗi:** Tạo bug report chi tiết cho các trường hợp thất bại.
*   [ ] **4.3. Dọn dẹp Môi trường:** Chạy script `cleanup.sh`.

---

## 3. Tính năng, Hạng mục và Kịch bản Kiểm thử (Dựa trên Tài liệu)

Đây là cấu trúc mẫu để bạn xây dựng các kịch bản kiểm thử chi tiết sau khi phân tích các tài liệu.

### **Tính năng 1: Phân quyền Truy cập Cơ bản (Basic Access Control)**
*Dựa trên các yêu cầu trong `Specification.pdf` liên quan đến các quyền r, w, x, a.*

| Hạng mục | ID | Kịch bản Kiểm thử | Các bước thực hiện (Ví dụ) | Kết quả mong đợi |
| :--- | :--- | :--- | :--- | :--- |
| **Kiểm tra Luật Đọc/Ghi (rw)** | STC-01 | Tiến trình được cấp quyền `rw` có thể đọc và ghi file. | 1. Gán nhãn: `chsmack -a Data file.txt`, `chsmack -e App proc` <br> 2. Áp dụng luật: `smackctl apply "App Data rw"` <br> 3. Thực thi: Chạy tiến trình `proc` đọc/ghi `file.txt` | Lệnh đọc và ghi thành công. |
| | STC-02 | Tiến trình không được cấp quyền `w` bị từ chối khi cố gắng ghi file. | 1. Gán nhãn như trên. <br> 2. Áp dụng luật: `smackctl apply "App Data r"` <br> 3. Thực thi: Chạy tiến trình `proc` ghi vào `file.txt` | Lệnh ghi thất bại, trả về "Permission denied". `audit.log` ghi nhận `action=denied`. |
| **Kiểm tra Luật Thực thi (x)** | STC-03 | Tiến trình được cấp quyền `rx` có thể thực thi một script. | 1. Gán nhãn: `chsmack -a Script run.sh`, `chsmack -e User shell` <br> 2. Áp dụng luật: `smackctl apply "User Script rx"` <br> 3. Thực thi: Chạy `shell` để thực thi `./run.sh` | Script được thực thi thành công. |

### **Tính năng 2: Các Tính năng Nâng cao (Advanced Features)**
*Dựa trên các yêu cầu trong `Specification.pdf` liên quan đến Transmute, Onlycap.*

| Hạng mục | ID | Kịch bản Kiểm thử | Các bước thực hiện (Ví dụ) | Kết quả mong đợi |
| :--- | :--- | :--- | :--- | :--- |
| **Kiểm tra Kế thừa Nhãn (Transmute)** | STC-04 | File tạo mới trong thư mục được bật `t` sẽ kế thừa nhãn của thư mục cha. | 1. Gán nhãn: `chsmack -a Secret /secret_dir` <br> 2. Áp dụng luật: `smackctl apply "_ Secret rwxat"` <br> 3. Bật transmute: `chsmack -t /secret_dir` <br> 4. Thực thi: `touch /secret_dir/new_file.txt` | `chsmack /secret_dir/new_file.txt` cho thấy nhãn của file mới là `Secret`. |
| **Kiểm tra Chế độ Onlycap** | STC-05 | Tiến trình `root` không thể sửa đổi luật của SMACK khi Onlycap được bật cho nhãn đó. | 1. Bật Onlycap cho nhãn `App::Secure`. <br> 2. Thực thi (với quyền root): `smackctl apply "App::Secure _ r"` | Lệnh `smackctl` thất bại. |

### **Tính năng 3: Ghi Log và Giám sát (Logging & Monitoring)**
*Dựa trên các yêu cầu trong `Specification.pdf` liên quan đến việc giám sát hệ thống.*

| Hạng mục | ID | Kịch bản Kiểm thử | Các bước thực hiện (Ví dụ) | Kết quả mong đợi |
| :--- | :--- | :--- | :--- | :--- |
| **Kiểm tra Nhật ký Từ chối (Denial Log)** | STC-06 | Mọi truy cập bị từ chối bởi SMACK đều phải được ghi lại trong `audit.log`. | 1. Tạo một kịch bản truy cập bị từ chối (như STC-02). <br> 2. Thực thi: `cat /var/log/audit/audit.log` | Một entry mới xuất hiện trong `audit.log` với `lsm=SMACK`, `action=denied`, và các chi tiết về `subject`, `object`. |

