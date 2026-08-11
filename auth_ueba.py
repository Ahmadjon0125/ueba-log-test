import pandas as pd
import numpy as np
import re
from datetime import datetime
from collections import defaultdict

# =============================================================================
# 1. AUTH.LOG PARSING
# =============================================================================

def parse_auth_log(file_path: str) -> pd.DataFrame:
    """
    auth.log faylini o'qib, pandas DataFrame ga aylantiradi.
    
    Har bir log qatoridan kerakli feature'larni ajratib oladi:
    - timestamp, hour, service, process_name, pid, username, 
      auth_action, source_ip, message
    """
    records = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            record = parse_auth_line(line)
            if record:
                records.append(record)
    
    df = pd.DataFrame(records)
    return df


def parse_auth_line(line: str) -> dict:
    """Bitta auth.log qatorini parse qilib, dict ga aylantiradi."""
    
    # Timestamp ni o'qish
    timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})', line)
    if not timestamp_match:
        return None
    
    timestamp_str = timestamp_match.group(1)
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
    except:
        return None
    
    record = {
        'timestamp': timestamp,
        'hour': timestamp.hour,
        'message': line
    }
    
    # Service va process name o'qish
    service_match = re.search(r'\s(\S+?)(?:\[(\d+)\])?:\s', line)
    if service_match:
        record['process_name'] = service_match.group(1)
        record['pid'] = int(service_match.group(2)) if service_match.group(2) else None
    else:
        record['process_name'] = 'unknown'
        record['pid'] = None
    
    # Username o'qish - bir nechta format
    user_match = re.search(r'for (?:user )?(\S+?)(?:\(|$)', line)
    if user_match:
        username = user_match.group(1)
        # uid=... qismini olib tashlash
        if '(' in username:
            username = username.split('(')[0]
        record['username'] = username
    else:
        # sddm-greeter uchun: pam_unix(sddm-greeter:session)
        greeter_match = re.search(r'pam_unix\((\S+?):session\)', line)
        if greeter_match:
            record['username'] = greeter_match.group(1)
        else:
            record['username'] = 'unknown'
    
    # Auth action aniqlash
    if 'failed password' in line.lower():
        record['auth_action'] = 'failed_password'
        record['auth_type'] = 'password'
        record['is_failure'] = 1
    elif 'accepted password' in line.lower():
        record['auth_action'] = 'accepted_password'
        record['auth_type'] = 'password'
        record['is_failure'] = 0
    elif 'accepted publickey' in line.lower():
        record['auth_action'] = 'accepted_publickey'
        record['auth_type'] = 'publickey'
        record['is_failure'] = 0
    elif 'session opened' in line.lower():
        record['auth_action'] = 'session_opened'
        record['auth_type'] = 'pam'
        record['is_failure'] = 0
    elif 'session closed' in line.lower():
        record['auth_action'] = 'session_closed'
        record['auth_type'] = 'pam'
        record['is_failure'] = 0
    elif 'failure' in line.lower():
        record['auth_action'] = 'failure'
        record['auth_type'] = 'unknown'
        record['is_failure'] = 1
    else:
        record['auth_action'] = 'other'
        record['auth_type'] = 'unknown'
        record['is_failure'] = 0
    
    # Source IP o'qish (sshd uchun)
    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        record['source_ip'] = ip_match.group(1)
    else:
        record['source_ip'] = None
    
    return record


# =============================================================================
# 2. FEATURE ENGINEERING
# =============================================================================

def create_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    DataFrame dan qo'shimcha feature'lar yaratadi.
    
    Yangi feature'lar:
    - session_duration: session opened va session closed orasidagi vaqt
    - login_count_per_hour: soatiga loginlar soni
    - is_sudo: sudo buyrug'i ishlatilganmi
    - is_ssh: SSH orqali kirish
    - is_off_hours: tungi vaqtda (00:00 - 06:00)
    - unique_users: har bir IP dan qancha foydalanuvchi kirgan
    """
    
    df = df.copy()
    
    # Tungi vaqt belgisi
    df['is_off_hours'] = df['hour'].apply(lambda h: 1 if 0 <= h < 6 else 0)
    
    # SSH orqali kirish
    df['is_ssh'] = df['process_name'].apply(lambda x: 1 if x == 'sshd' else 0)
    
    # Sudo foydalanish
    df['is_sudo'] = df['message'].apply(lambda x: 1 if 'sudo' in x.lower() else 0)
    
    # Auth type numerik
    auth_type_map = {'password': 0, 'publickey': 1, 'pam': 2, 'unknown': 3}
    df['auth_type_num'] = df['auth_type'].map(auth_type_map).fillna(3).astype(int)
    
    # Service numerik
    service_map = {'sshd': 0, 'sudo': 1, 'cron': 2, 'login': 3, 'other': 4}
    df['service_num'] = df['process_name'].map(service_map).fillna(4).astype(int)
    
    return df


# =============================================================================
# 3. SESSION DURATION HISOBLASH
# =============================================================================

def calculate_session_durations(df: pd.DataFrame) -> pd.DataFrame:
    """
    session opened va session closed juftliklarini topib,
    ularning davomiylik vaqtini hisoblaydi.
    """
    df = df.copy()
    df['session_duration_minutes'] = 0.0
    
    # Har bir user va process bo'yicha guruhlash
    groups = df.groupby(['username', 'process_name'])
    
    for (user, process), group in groups:
        # session opened va session closed larni topish
        opened = group[group['auth_action'] == 'session_opened'].sort_values('timestamp')
        closed = group[group['auth_action'] == 'session_closed'].sort_values('timestamp')
        
        for idx_open in opened.index:
            ts_open = df.loc[idx_open, 'timestamp']
            # Eng yaqin closed ni topish
            nearby_closed = closed[closed['timestamp'] > ts_open]
            if not nearby_closed.empty:
                ts_close = nearby_closed.iloc[0]['timestamp']
                duration = (ts_close - ts_open).total_seconds() / 60  # daqiqada
                df.loc[idx_open, 'session_duration_minutes'] = duration
    
    return df


# =============================================================================
# 4. BASELINE HISOBLASH
# =============================================================================

def compute_baseline(df: pd.DataFrame) -> dict:
    """
    Normal loglardan baseline statistikalarni hisoblaydi.
    
    Feature'lar:
    - session_duration: o'rtacha va std
    - login_count: foydalanuvchi bo'yicha loginlar soni
    - failure_rate: xatoliklar foizi
    """
    
    baseline = {
        # Session duration
        'mean_session_duration': df['session_duration_minutes'].mean(),
        'std_session_duration': df['session_duration_minutes'].std() or 1.0,
        
        # Login frequency (har bir foydalanuvchi uchun)
        'mean_logins_per_session': df.groupby('username')['timestamp'].count().mean(),
        'std_logins_per_session': df.groupby('username')['timestamp'].count().std() or 1.0,
        
        # Failure rate
        'failure_rate': df['is_failure'].mean(),
        'std_failure_rate': df['is_failure'].std() or 1.0,
        
        # Service distribution
        'ssh_ratio': df['is_ssh'].mean(),
        
        # Off-hours ratio
        'off_hours_ratio': df['is_off_hours'].mean(),
    }
    
    return baseline


# =============================================================================
# 5. ANOMALY DETECTION
# =============================================================================

def calculate_anomaly_score(row: pd.Series, baseline: dict) -> dict:
    """
    Bitta log uchun anomaly score hisoblaydi.
    
    Z-scores:
    - session_duration: normaldan uzun session
    - failure: xatolik holati
    - off_hours: tungi vaqtda faoliyat
    - sudo_risk: sudo foydalanish
    
    Qo'shimcha:
    - service_risk: sshd dan boshqa service riski
    """
    
    # Session duration z-score
    z_duration = (row['session_duration_minutes'] - baseline['mean_session_duration']) / baseline['std_session_duration']
    
    # Failure z-score
    is_failure_norm = row['is_failure'] / (baseline['std_failure_rate'] + 1e-6)
    
    # Off-hours risk
    off_hours_risk = 1.5 if row['is_off_hours'] == 1 else 0.0
    
    # Sudo risk
    sudo_risk = 2.0 if row['is_sudo'] == 1 else 0.0
    
    # Failed password risk
    failed_pw_risk = 3.0 if row['auth_action'] == 'failed_password' else 0.0
    
    # General anomaly score
    anomaly_score = np.sqrt(z_duration**2 + is_failure_norm**2) + off_hours_risk + sudo_risk + failed_pw_risk
    
    # Threshold
    is_anomaly = anomaly_score > 3.0
    
    return {
        'anomaly_score': round(float(anomaly_score), 2),
        'is_anomaly': bool(is_anomaly),
        'z_duration': round(float(z_duration), 2),
        'off_hours_risk': off_hours_risk,
        'sudo_risk': sudo_risk,
        'failed_pw_risk': failed_pw_risk,
    }


def detect_anomalies(df: pd.DataFrame, baseline: dict) -> pd.DataFrame:
    """
    Butun DataFrame uchun anomaly detection bajaradi.
    """
    results = df.apply(lambda row: calculate_anomaly_score(row, baseline), axis=1)
    results_df = pd.DataFrame(results.tolist())
    
    df = pd.concat([df, results_df], axis=1)
    
    return df


# =============================================================================
# 6. REPORT GENERATION
# =============================================================================

def generate_report(df: pd.DataFrame, top_n: int = 10) -> None:
    """
    Anomaliya hisobotini ekranga chiqaradi.
    """
    anomalies = df[df['is_anomaly']].sort_values('anomaly_score', ascending=False)
    
    print("=" * 80)
    print("🔍 UEBA AUTH.LOG ANOMALY REPORT")
    print("=" * 80)
    print(f"\n📊 Jami loglar: {len(df)}")
    print(f"🚨 Topilgan anomaliyalar: {len(anomalies)} ({len(anomalies)/len(df)*100:.1f}%)")
    
    if len(anomalies) > 0:
        print(f"\n🔴 TOP {min(top_n, len(anomalies))} ENG xavfli loglar:")
        print("-" * 80)
        
        for idx, row in anomalies.head(top_n).iterrows():
            print(f"\n  User: {row['username']}")
            print(f"  Service: {row['process_name']}")
            print(f"  Action: {row['auth_action']}")
            print(f"  Time: {row['timestamp']} (hour: {row['hour']})")
            print(f"  Anomaly Score: {row['anomaly_score']}")
            print(f"  Z-Duration: {row['z_duration']}")
            print(f"  Off Hours: {row['off_hours_risk']}")
            print(f"  Sudo Risk: {row['sudo_risk']}")
            print(f"  Failed PW Risk: {row['failed_pw_risk']}")
            print(f"  Message: {row['message'][:100]}...")
            print("-" * 40)


# =============================================================================
# ASOSIY ISHLATISH
# =============================================================================

def main():
    # 1. Auth.log ni o'qish
    print("📖 Auth.log o'qilmoqda...")
    df = parse_auth_log('/var/log/auth.log')
    
    if df.empty:
        print("❌ Log fayl bo'sh yoki o'qib bo'lmadi!")
        return
    
    print(f"✅ O'qildi: {len(df)} ta log")
    
    # 2. Feature engineering
    print("\n🔧 Feature engineering...")
    df = create_features(df)
    df = calculate_session_durations(df)
    
    # 3. Baseline hisoblash (oxirgi 7 kun, lekin bugungi kun o'chirilgan)
    print("\n📊 Baseline hisoblanmoqda...")
    # Bugungi kunning o'zini baseline dan olib tashlaymiz
    today = df['timestamp'].dt.date.max()
    baseline_period = 7  # kun
    cutoff_date = today - pd.Timedelta(days=baseline_period)
    # Faqat bugundan oldingi kunlarni olamiz (bugungi loglar kirmaydi)
    baseline_data = df[(df['timestamp'].dt.date >= cutoff_date) & (df['timestamp'].dt.date < today)]
    
    baseline = compute_baseline(baseline_data)
    print(f"   mean_session_duration: {baseline['mean_session_duration']:.2f} daqiqa")
    print(f"   mean_logins_per_session: {baseline['mean_logins_per_session']:.1f}")
    print(f"   failure_rate: {baseline['failure_rate']:.2%}")
    print(f"   off_hours_ratio: {baseline['off_hours_ratio']:.2%}")
    
    # 4. Anomaly detection (barcha ma'lumot bo'yicha)
    print("\n🔍 Anomaliya aniqlanmoqda...")
    df = detect_anomalies(df, baseline)
    
    # 5. Hisobot
    generate_report(df)
    
    # 6. Natijalarni faylga yozish
    anomalies = df[df['is_anomaly']]
    if len(anomalies) > 0:
        anomalies.to_csv('auth_anomalies.csv', index=False)
        print(f"\n💾 Anomaliyalar 'auth_anomalies.csv' ga saqlandi!")


if __name__ == '__main__':
    main()