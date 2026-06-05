import io
import sys

# Ép Terminal xuất UTF-8 tránh lỗi font chữ tiếng Việt trên Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import numpy as np
import tensorflow as tf
from fastapi import FastAPI
from pydantic import BaseModel
from tensorflow.keras import layers, models

# =====================================================================
# 1. ĐỊNH NGHĨA KHỐI TRANSFORMER CHUẨN 3 CHIỀU (Bê nguyên từ code của bạn)
# =====================================================================
class TabularTransformerBlock(layers.Layer):

    def __init__(self, embed_dim, num_heads, ff_dim, rate=0.1, **kwargs):
        super().__init__(**kwargs)
        self.att = layers.MultiHeadAttention(
            num_heads=num_heads, key_dim=embed_dim
        )
        self.ffn = tf.keras.Sequential([
            layers.Dense(ff_dim, activation="relu"),
            layers.Dense(embed_dim),
        ])
        self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)
        self.dropout1 = layers.Dropout(rate)
        self.dropout2 = layers.Dropout(rate)

    def call(self, inputs, training=False):
        attn_output = self.att(inputs, inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)

        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        return self.layernorm2(out1 + ffn_output)


# =====================================================================
# 2. KHỞI TẠO SERVER VÀ DỰNG LẠI KHUNG XƯƠNG MÔ HÌNH
# =====================================================================
app = FastAPI(title="IoT Transformer Attack Detection Server")

num_features = 6  # Khớp với 6 features trong dataset BoT-IoT bạn dùng
embed_dim = 64
num_heads = 4
ff_dim = 64
num_classes = 5

# Dựng lại graph mô hình
inputs = layers.Input(shape=(num_features,))
x = layers.Dense(embed_dim, activation="relu")(inputs)
x_reshaped = layers.Reshape((1, embed_dim))(x)
x_transformer = TabularTransformerBlock(embed_dim, num_heads, ff_dim)(
    x_reshaped
)
x_flatten = layers.Flatten()(x_transformer)
x_dropout = layers.Dropout(0.1)(x_flatten)
outputs = layers.Dense(num_classes, activation="softmax")(x_dropout)

model = models.Model(inputs=inputs, outputs=outputs)

# Nạp trọng số từ file weights của bạn
try:
    model.load_weights("transformer_weights.weights.h5")
    print(
        "[Hệ thống Cloud] Nạp trọng số Transformer thành công! AI trực tuyến."
    )
except Exception as e:
    print(f"[Cảnh báo] Chưa tìm thấy file trọng số: {e}")

# Thứ tự nhãn chuẩn từ kết quả chạy của bạn
labels = ["DDoS", "DoS", "Normal", "Reconnaissance", "Theft"]


# =====================================================================
# 3. ĐỊNH NGHĨA ĐẦU VÀO VÀ ENDPOINT API ĐỂ NHẬN DỮ LIỆU QUA MẠNG
# =====================================================================
class TrafficData(BaseModel):
    features: list  # Nhận mảng 6 số thực gửi từ Client tới


@app.get("/")
def index():
    return {"message": "Server Transformer IoT đang chạy"}


@app.post("/predict")
def predict_traffic(data: TrafficData):
    try:
        # 1. Chuyển cục dữ liệu nhận từ Internet thành mảng numpy phù hợp với mô hình (shape: 1, 6)
        input_data = np.array([data.features], dtype=np.float32)

        # 2. Đưa qua mô hình Transformer để dự đoán
        prediction = model(input_data, training=False)
        class_id = np.argmax(prediction.numpy())
        confidence = float(prediction.numpy()[0][class_id] * 100)

        # 3. Trả về kết quả trực tiếp qua mạng cho Client
        return {
            "status": "Success",
            "prediction": labels[class_id],
            "confidence": f"{confidence:.2f}%",
        }
    except Exception as e:
        return {"status": "Error", "message": str(e)}