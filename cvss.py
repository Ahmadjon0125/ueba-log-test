import math

def cvss_round_up(value):
    """CVSS standartidagi maxsus yuqoriga yaxlitlash funksiyasi.
    Raqamni har doim eng yaqin birinchi o'ndan bir xonagacha yuqoriga yaxlitlaydi.
    Masalan: 8.6466 -> 8.7
    """
    input_int = int(round(value * 100000))
    if input_int % 10000 == 0:
        return input_int / 100000.0
    else:
        return (int(input_int / 10000) + 1) / 10.0

def calculate_cvss_high_severity_example():
    print("=== CVSS v3.1 MATEMATIK HISOB-KITOB MODELI ===\n")
    
    # 0-QADAM: Boshlang'ich koeffitsiyentlar (Xalqaro standart vaznlari)
    AV = 0.85  # Attack Vector (Tarmoq orqali hujum)
    AC = 0.77  # Attack Complexity (Past qiyinchilik)
    PR = 0.85  # Privileges Required (Hech qanday huquq shart emas)
    UI = 0.85  # User Interaction (Inson aralashuvi shart emas)
    
    C = 0.56   # Confidentiality Impact (Maxfiylik to'liq buziladi)
    I = 0.56   # Integrity Impact (Tizim butunligi to'liq buziladi)
    A = 0.22   # Availability Impact (Tizim ochiqligi qisman buziladi)
    
    print(f"[0-Qadam] Berilgan koeffitsiyentlar:")
    print(f" - Hujum osonligi: AV={AV}, AC={AC}, PR={PR}, UI={UI}")
    print(f" - Zarar ko'lami:   C={C}, I={I}, A={A}\n")

    # 1-QADAM: Exploitability (Hujum osonligi) sub-balini hisoblash
    # Formula: 8.22 * AV * AC * PR * UI
    exploitability = 8.22 * AV * AC * PR * UI
    print(f"[1-Qadam] Exploitability Sub-bali hisoblanmoqda:")
    print(f" - Formula: 8.22 * {AV} * {AC} * {PR} * {UI}")
    print(f" - Natija: {exploitability:.4f}\n")

    # 2-QADAM: ISS (Boshlang'ich zarar) va Yakuniy Impact balini hisoblash
    # Formula: 1 - [ (1 - C) * (1 - I) * (1 - A) ]
    iss = 1 - ((1 - C) * (1 - I) * (1 - A))
    print(f"[2-Qadam] ISS (Boshlang'ich zarar) hisoblanmoqda:")
    print(f" - Formula: 1 - [ (1 - {C}) * (1 - {I}) * (1 - {A}) ]")
    print(f" - ISS Natija: {iss:.6f}")
    
    # Scope o'zgarmagan holat uchun Impact formulasi: 6.42 * ISS
    impact = 6.42 * iss
    print(f" - Yakuniy Impact Bali (6.42 * {iss:.6f}): {impact:.4f}\n")

    # 3-QADAM: Base Score (Asosiy Ball)ni birlashtirish
    # Formula: Minimum( (Impact + Exploitability), 10 )
    raw_sum = impact + exploitability
    print(f"[3-Qadam] Ballar birlashtirilmoqda:")
    print(f" - Jami yig'indi (Impact + Exploitability): {impact:.4f} + {exploitability:.4f} = {raw_sum:.4f}")
    
    base_score_raw = min(raw_sum, 10.0)
    print(f" - Maksimal 10 dan oshmaslik chegarasi (min): {base_score_raw:.4f}")
    
    # 4-QADAM: CVSS standartida yuqoriga yaxlitlash
    final_cvss_score = cvss_round_up(base_score_raw)
    print(f" - RoundUp qoidasi bo'yicha yakuniy yaxlitlash: {final_cvss_score}\n")

    # 5-QADAM: UEBA uchun 100 ballik tizimga o'tkazish
    ueba_risk_weight = final_cvss_score * 10
    print(f"✅ YAKUNIY NATIJA:")
    print(f" - Xalqaro CVSS Bali: {final_cvss_score} (HIGH SEVERITY)")
    print(f" - Sizning UEBA dasturingiz uchun standart vazn (Ball): {ueba_risk_weight:.0f} ball")

# Kodni ishga tushiramiz
if __name__ == "__main__":
    calculate_cvss_high_severity_example()
