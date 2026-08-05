import glob
import gzip
import os
import re
from datetime import datetime
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

MODEL_FILE = "ueba_isolation_forest.pkl"

# Auth.log shakliga mos Regex pattern
log_pattern = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?: (.*)$"
)

data = []

# Tizimdagi barcha eski va yangi auth loglarni topamiz
log_files = glob.glob("/var/log/auth.log*")

for file_path in log_files:
    if file_path.endswith(".gz"):
        f = gzip.open(file_path, "rt", encoding="utf-8", errors="ignore")
    else:
        f = open(file_path, "r", encoding="utf-8", errors="ignore")

    with f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                time_str, hostname, process, message = match.groups()

                # Faqat xavfsizlikka aloqador muhim voqealarni saralaymiz
                if any(
                    k in message
                    for k in ["session", "Accepted", "Failed", "polkitd", "sudo"]
                ):
                    user_match = re.search(r"for (?:user )?(\w+)", message)
                    if user_match:
                        user = user_match.group(1)
                    elif "by " in message:
                        user = message.split("by ")[-1].split()[0]
                    else:
                        user = "system"

                    dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")
                    status = 0 if "Failed" in message else 1

                    data.append({
                        "datetime": dt,
                        "user": user,
                        "hour": dt.hour,
                        "day_of_week": dt.weekday(),
                        "status": status,
                    })

if not data:
    print("[!] Loglarda ma'lumot topilmadi.")
    exit()

# DataFrame yaratamiz
df = pd.DataFrame(data)

# Feature Engineering: 1 soat ichidagi harakatlar sonini hisoblash
df["login_count_1h"] = df.groupby(
    ["user", pd.Grouper(key="datetime", freq="1h")]
)["status"].transform("count")

# Model o'rganishi uchun belgilar (Features)
features = ["hour", "day_of_week", "status", "login_count_1h"]
X = df[features]

print("[INFO] Model yangi ma'lumotlar bo'yicha o'qitilmoqda...")

# Modelni har safar yangi loglar mezoniga ko'ra o'qitamiz
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(X)

# Yangilangan bilimlarni keyingi ishlatish uchun saqlab qo'yamiz
joblib.dump(model, MODEL_FILE)
print(f"[INFO] Yangi xotira '{MODEL_FILE}' fayliga saqlandi.")

# Anomaliya va Risk Score hisoblash
df["anomaly_raw"] = model.predict(X)
df["score"] = model.decision_function(X)

min_score, max_score = df["score"].min(), df["score"].max()

if max_score != min_score:
    df["risk_score"] = (
        (max_score - df["score"]) / (max_score - min_score) * 100
    ).round(1)
else:
    df["risk_score"] = 0

# Hisobotni ekranga chiqarish
print("\n=== UEBA ANOMALIYALARNI ANIQLASH HISOBOTI ===")
anomalies = df[df["anomaly_raw"] == -1].sort_values(
    by="risk_score", ascending=False
)

if not anomalies.empty:
    print(
        anomalies[[
            "datetime",
            "user",
            "hour",
            "day_of_week",
            "status",
            "login_count_1h",
            "risk_score",
        ]].head(15)
    )
else:
    print("Tizimda hech qanday anomaliya topilmadi.")