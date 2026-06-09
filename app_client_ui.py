import io

import time
import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st


# 1. CẤU HÌNH TRANG GIAO DIỆN
st.set_page_config(
    page_title="Hệ thống Giám sát IoT - AI", layout="wide", page_icon="🛡️"
)

st.title("🛡️ HỆ THỐNG PHÁT HIỆN TẤN CÔNG MẠNG IoT BẰNG TRÍ TUỆ NHÂN TẠO")
st.markdown("---")

# Đường dẫn API Server Render thật của bạn
SERVER_URL = "https://test-iot-attack.onrender.com/predict"

# Tên 6 cột đặc trưng số của bộ dữ liệu BoT-IoT để hiển thị lên bảng cho pro
FEATURE_NAMES = [
    "Độ lệch chuẩn thời gian (stddev)",
    "Số kết nối đến từ IP nguồn (N_IN_Conn_P_SrcIP)",
    "Thời gian kết nối nhỏ nhất (min)",
    "Thời gian kết nối trung bình (mean)",
    "Số kết nối đến IP đích (N_IN_Conn_P_DstIP)",
    "Thời gian kết nối lớn nhất (max)",
]

# 2. KHỞI TẠO BỘ NHỚ TẠM (SESSION STATE)
if "latency_history" not in st.session_state:
    st.session_state.latency_history = []
if "attack_count" not in st.session_state:
    st.session_state.attack_count = {
        "Normal": 0,
        "DoS": 0,
        "DDoS": 0,
        "Reconnaissance": 0,
        "Theft": 0,
    }
if "scanned_traffic_log" not in st.session_state:
    st.session_state.scanned_traffic_log = []  # Lưu lịch sử các gói tin để hiện bảng

# 3. THIẾT KẾ GIAO DIỆN THÀNH 2 CỘT
col_left, col_right = st.columns([1, 2])

with col_left:
    st.header("⚙️ Cấu hình Nguồn Dữ Liệu")

    mode = st.radio(
        "Chọn phương thức kiểm thử mạng:", ["Mẫu Giả Lập", "Tải file CSV Dataset"]
    )

    # Khởi tạo danh sách chứa data sẽ chạy
    active_cases = []

    if mode == "Mẫu Giả Lập":
        st.info("💡 Hệ thống sẽ sử dụng 3 mẫu traffic trích xuất từ tập Test gốc.")
        active_cases = [
            {
                "name": "Mẫu traffic số 1 (Gốc: DoS)",
                "data": [
                    0.0,
                    0.99999994,
                    0.03413914,
                    0.03412947,
                    0.99999994,
                    0.034005806,
                ],
            },
            {
                "name": "Mẫu traffic số 2 (Gốc: DDoS)",
                "data": [
                    0.66500145,
                    0.67676765,
                    0.0,
                    0.47067052,
                    0.99999994,
                    0.72488976,
                ],
            },
            {
                "name": "Mẫu traffic số 3 (Gốc: DDoS)",
                "data": [
                    0.75306267,
                    0.7373737,
                    0.19715324,
                    0.7308344,
                    0.99999994,
                    0.995662,
                ],
            },
        ]
    else:
        uploaded_file = st.file_uploader(
            "Kéo thả file CSV trích từ tập Test của BoT-IoT tại đây:",
            type=["csv"],
        )
        num_rows = st.number_input(
            "Số lượng dòng muốn quét mô phỏng:",
            min_value=1,
            max_value=100,
            value=5,
        )

        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            # Lọc bỏ các cột nhãn chữ nếu có
            features_df = df.drop(
                columns=["category", "subcategory", "label"], errors="ignore"
            )

            if features_df.shape[1] != 6:
                st.error(
                    f"❌ File CSV đang có {features_df.shape[1]} cột. Yêu cầu đúng 6 cột đặc trưng số!"
                )
            else:
                # Chuyển đổi dữ liệu từ CSV thành định dạng cấu trúc để chạy vòng lặp
                for index, row in features_df.head(int(num_rows)).iterrows():
                    active_cases.append(
                        {
                            "name": f"Dòng dữ liệu CSV số {index + 1}",
                            "data": [float(val) for val in row.values.tolist()],
                        }
                    )

    btn_start = st.button("🚀 BẮT ĐẦU QUÉT TRAFFIC", type="primary")

    if st.button("🔄 Xóa lịch sử phiên làm việc"):
        st.session_state.latency_history = []
        st.session_state.scanned_traffic_log = []
        st.session_state.attack_count = {
            "Normal": 0,
            "DoS": 0,
            "DDoS": 0,
            "Reconnaissance": 0,
            "Theft": 0,
        }
        st.rerun()

with col_right:
    st.header("📊 Nhật ký Giám sát Thời gian thực")
    status_box = st.empty()
    metrics_box = st.empty()
    chart_box = st.empty()

    # Tạo thêm một phân vùng không gian riêng để show BẢNG THÔNG TIN CHI TIẾT TRAFFIC
    st.markdown("### 🔍 Chi Tiết Thuộc Tính Các Gói Tin Đang Quét (Real-time Features)")
    table_box = st.empty()

# 4. XỬ LÝ KHI BẤM NÚT QUÉT
if btn_start:
    if len(active_cases) == 0:
        st.warning("⚠️ Vui lòng tải file dữ liệu lên trước khi bấm quét!")
    else:
        st.toast("Đang kết nối tới Server Cloud Render...", icon="🌐")

        for i, case in enumerate(active_cases):
            payload = {"features": case["data"]}
            start_time = time.time()

            try:
                # Bắn dữ liệu lên Cloud
                response = requests.post(SERVER_URL, json=payload)
                res_data = response.json()

                end_time = time.time()
                latency_ms = (end_time - start_time) * 1000

                prediction = res_data.get("prediction", "Unknown")
                confidence = res_data.get("confidence", "0%")

                # Cập nhật bộ nhớ đếm số lượng nhãn mạng
                st.session_state.latency_history.append(latency_ms)
                if prediction in st.session_state.attack_count:
                    st.session_state.attack_count[prediction] += 1

                # CẬP NHẬT DỮ LIỆU VÀO BẢNG HIỂN THỊ CHI TIẾT TRAFFIC
                # Tạo một dictionary chứa kết quả phân tích kèm 6 đặc trưng toán học gốc
                traffic_info = {
                    "Nguồn quét": case["name"],
                    "AI Phân Loại": prediction,
                    "Độ Tự Tin": confidence,
                    "Độ Trễ (ms)": f"{latency_ms:.2f} ms",
                }
                # Khớp 6 con số trong mảng tương ứng với 6 tên cột vật lý
                for idx, feat_name in enumerate(FEATURE_NAMES):
                    traffic_info[feat_name] = case["data"][idx]

                # Đẩy lên đầu danh sách để dòng mới nhất luôn xuất hiện trên cùng bảng
                st.session_state.scanned_traffic_log.insert(0, traffic_info)

                # --- HIỂN THỊ GIAO DIỆN ---

                # 1. Đèn còi cảnh báo trạng thái an toàn/nguy hiểm
                with status_box.container():
                    if prediction in ["DoS", "DDoS"]:
                        st.error(
                            f"🚨 **NGUY HIỂM:** Phát hiện tấn công độc hại **{prediction}**! (Độ tự tin: {confidence})"
                        )
                    elif prediction == "Normal":
                        st.success(
                            f"✅ **AN TOÀN:** Lưu lượng mạng bình thường. (Độ tự tin: {confidence})"
                        )
                    else:
                        st.warning(
                            f"⚠️ **CẢNH BÁO:** Phát hiện hành vi bất thường: **{prediction}**"
                        )

                # 2. Thẻ chỉ số hiển thị nhanh (Metrics)
                with metrics_box.container():
                    c1, c2 = st.columns(2)
                    c2.metric(
                        "Tổng số cuộc tấn công phát hiện",
                        sum(st.session_state.attack_count.values())
                        - st.session_state.attack_count["Normal"],
                    )
                    c1.metric("Độ trễ xử lý (Latency)", f"{latency_ms:.2f} ms")

                # 3. Vẽ đồ thị Matplotlib biến thiên Latency
                with chart_box.container():
                    fig, ax = plt.subplots(figsize=(6, 2))
                    ax.plot(
                        st.session_state.latency_history,
                        marker="o",
                        color=(
                            "#FF4B4B"
                            if prediction in ["DoS", "DDoS"]
                            else "#1E88E5"
                        ),
                    )
                    ax.set_ylabel("ms")
                    ax.set_xlabel("Thứ tự gói tin")
                    st.pyplot(fig)

                # 4. ĐỔ DỮ LIỆU ĐỘNG VÀO BẢNG DATA ĐỂ THẦY CÔ NHÌN
                with table_box.container():
                    output_df = pd.DataFrame(
                        st.session_state.scanned_traffic_log
                    )
                    st.dataframe(
                        output_df, use_container_width=True, hide_index=True
                    )

            except Exception as e:
                st.error(f"Lỗi kết nối Cloud Server ở lượt quét thứ {i+1}: {e}")

            time.sleep(1.2)  # Nghỉ một chút tạo cảm giác đang quét thực tế mạng