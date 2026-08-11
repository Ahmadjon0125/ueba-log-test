# 🔍 UEBA - User Behavior Analytics

**Log fayllardan foydalanib, foydalanuvchi xatti-harakatlarini tahlil qilish va anomaliyalarni aniqlash tizimi.**

---

## 📋 Mazmuni

- [Xususiyatlar](#-xususiyatlar)
- [O'rnatish](#-o'rnatish)
- [Ishlatish](#-ishlatish)
- [Arxitektura](#-arxitektura)
- [Feature'lar](#-featurelar)
- [Anomaliya aniqlash](#-anomaliya-aniqlash)
- [Misollar](#-misollar)
- [Real tizimda](#-real-tizimda)

---

## 🎯 Xususiyatlar

- ✅ **Log Parsing** — auth.log fayllarini avtomatik parse qilish
- ✅ **Feature Engineering** — 10+ ta feature yaratish (session duration, risk omillari)
- ✅ **Baseline Hisoblash** — Sliding Window usuli bilan normal xatti-harakatlar bazasi
- ✅ **Z-Score Anomaly Detection** — Statistik anomaliya aniqlash
- ✅ **Risk Scoring** — Ko'p omilli risk ball hisoblash
- ✅ **Report Generation** — Chiroyli hisobotlar CSV formatda

---

## 📦 O'rnatish

### 1. Python kutubxonalarini o'rnatish

```bash
pip install -r requirements.txt
```

**Talab qilinadigan paketlar:**
```
pandas>=2.0.0
numpy>=1.24.0
```

### 2. Virtual environment yaratish (tavsiya etiladi)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Ishlatish

### Auth.log tahlili

```bash
python auth_ueba.py
```

**Natija:**
```
📖 Auth.log o'qilmoqda...
✅ O'qildi: 576 ta log

🔧 Feature engineering...

📊 Baseline hisoblanmoqda...
   mean_session_duration: 0.00 daqiqa
   mean_logins_per_session: 144.0
   failure_rate: 0.35%
   off_hours_ratio: 1.74%

🔍 Anomaliya aniqlanmoqda...

================================================================================
🔍 UEBA AUTH.LOG ANOMALY REPORT
================================================================================

📊 Jami loglar: 576
🚨 Topilgan anomaliyalar: 4 (0.7%)

🔴 TOP 4 ENG xavfli loglar:
...
```

### Anomaliyalar CSV faylga saqlanadi:

```bash
cat auth_anomalies.csv
```

---

## 🏗 Arxitektura

```
┌─────────────────────────────────────────────────────────────┐
│                    UEBA Tizim Arxitekturasi                  │
└─────────────────────────────────────────────────────────────┘

1. LOG PARSING
   /var/log/auth.log
      ↓
   parse_auth_log() → Pandas DataFrame

2. FEATURE ENGINEERING
   → create_features()
   → calculate_session_durations()

3. BASELINE (30 kunlik sliding window)
   → compute_baseline()
   ✓ Bugungi loglar kirmaydi!

4. ANOMALY DETECTION
   → calculate_anomaly_score()
   → detect_anomalies()

5. REPORT
   → generate_report()
   → auth_anomalies.csv
```

---

## 📊 Feature'lar

### Auth.log dan ajratib olinadigan feature'lar:

| Feature | Tavsif | Misol |
|---------|--------|-------|
| `timestamp` | Log vaqti | 2026-08-08T10:27:24+05:00 |
| `hour` | Soat (0-23) | 10 |
| `process_name` | Process nomi | sshd, sudo, cron, sddm-helper |
| `username` | Foydalanuvchi ismi | ahmadjon, root |
| `auth_action` | Harakat turi | session_opened, failed_password |
| `is_failure` | Xatolik belgisi | 0 yoki 1 |
| `source_ip` | Kirish IP manbasi | 192.168.1.1 |
| `is_off_hours` | Tungi vaqt (0-6) | 0 yoki 1 |
| `is_ssh` | SSH orqali kirish | 0 yoki 1 |
| `is_sudo` | Sudo foydalanish | 0 yoki 1 |
| `session_duration` | Sessiya davomiyligi (daq) | 15.5 |

---

## 🔍 Anomaliya Aniqlash

### Z-Score formulasi:

```python
z = (qiymat - o'rtacha) / standart_og'ish
```

### Risk Scoring:

```python
anomaly_score = sqrt(z_duration² + failure²) + off_hours_risk + sudo_risk + failed_pw_risk

# Risk omillari:
off_hours_risk = 1.5  # Tungi soatlar (00:00 - 06:00)
sudo_risk = 2.0       # Sudo buyrug'i
failed_pw_risk = 3.0  # Noto'g'ri parol
```

### Anomaliya qanday belgilanadi:

```python
is_anomaly = anomaly_score > 3.0
```

---

## 💡 Misollar

### Misol 1: Normal login
```
User: ahmadjon
Action: session_opened
Hour: 10 (kunduzi)
Sudo: yo'q
Risk Score: 0.5 → ✅ Normal
```

### Misol 2: Shubhali tungi sudo
```
User: unknown
Action: failed_password
Hour: 03 (tungi)
Sudo: ha
Risk Score: 7.5 → 🚨 Anomaliya!
```

### Misol 3: Brute-force hujum
```
User: root
Action: failed_password (5 marta)
Hour: 02 (tungi)
Risk Score: 15.0 → 🚨 JUDA XAVFLI!
```

---

## 🌐 Real tizimda

### Haqiqiy UEBA tizimida:

| Komponent | Test | Production |
|-----------|------|------------|
| **Log manbasi** | auth.log fayl | Kafka / Elasticsearch |
| **Storage** | CSV fayl | PostgreSQL / MongoDB |
| **Processing** | Python pandas | Apache Flink / Spark |
| **Baseline** | 7 kunlik sliding window | 30 kunlik EMA (Exponential Moving Average) |
| **ML Model** | Z-Score | XGBoost / Neural Network |
| **Alerts** | CSV fayl | Slack / Email / PagerDuty |
| **Dashboard** | Console | Grafana / Kibana |

### Haqiqiy arxitektura:

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  App Server │  │  Web Server │  │  Database   │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        ↓
                  ┌─────────────┐
                  │   Kafka     │
                  └──────┬──────┘
                         ↓
                  ┌─────────────┐
                  │  UEBA       │
                  │  Engine     │
                  └──────┬──────┘
                         ↓
              ┌──────────┼──────────┐
              ↓          ↓          ↓
         ┌────────┐ ┌────────┐ ┌────────┐
         │  SQL   │ │ Cache  │ │  Alert │
         │  DB    │ │ Redis  │ │ System │
         └────────┘ └────────┘ └────────┘
```

---

## 📁 Fayl tuzilmasi

```
ueba/
├── auth_ueba.py              # Asosiy UEBA skript
├── z-score.ipynb             # Z-score tahlili (Jupyter Notebook)
├── test_logs.jsonl           # Test log fayli
├── requirements.txt          # Python paketlar
├── auth_anomalies.csv        # Topilgan anomaliyalar
├── found_anomalies.csv       # Eski natijalar
├── main.py                   # Boshqa tahlil skripti
├── cvss.py                   # CVSS hisoblash
└── README.md                 # Ushbu fayl
```

---

## 🔧 Sozlamalar

### Baseline davri:

```python
# auth_ueba.py ichida:
baseline_period = 7  # kun  → 30 ga o'zgartiring
```

### Anomaliya threshold:

```python
# auth_ueba.py ichida:
is_anomaly = anomaly_score > 3.0  # 2.0 yoki 4.0 qilish mumkin
```

### Risk omillari:

```python
off_hours_risk = 1.5    # 2.0 ga oshirish mumkin
sudo_risk = 2.0         # 3.0 ga oshirish mumkin
failed_pw_risk = 3.0    # 5.0 ga oshirish mumkin
```

---

## 📈 Kelgusi rejalalar

- [ ] ML modeli (XGBoost) qo'shish
- [ ] Real-time streaming (Kafka) qo'llab-quvvatlash
- [ ] Grafana dashboard integratsiyasi
- [ ] Email/Slack alert tizimi
- [ ] Ko'p log formatlarni qo'llab-quvvatlash (syslog, JSON, Apache)
- [ ] IP geolocation integratsiyasi

---

## 📝 Litsenziya

MIT License

---

## 👤 Muallif

Developed by **Ahmadjon** — [ueba-log-test](https://github.com/Ahmadjon0125/ueba-log-test)