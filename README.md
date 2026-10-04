# Abbas_Wifi v4.0 🔥

> أداة متكاملة لفحص أمن الشبكات اللاسلكية واكتشاف نقاط الضعف في كلمات المرور
> **المبرمج: جنرال عباس 🇮🇶 | @s.nfu**

---

## 📌 نظرة عامة

`Abbas_Wifi` هي أداة بلغة **Python 3** مخصصة لاختبار اختراق الشبكات اللاسلكية (WiFi) في بيئة قانونية وتعليمية. تجمع الأداة بين سكان الشبكات، هجوم Deauth، التقاط الـ Handshake، كسره باستخدام Wordlist، وتخمين كلمة مرور الشبكة مباشرة.

⚠️ **تنبيه مهم:** هذه الأداة مخصصة **للاختبار الأخلاقي فقط** على الشبكات التي تملك تصريحاً رسمياً باختبارها.

---

## ✨ المميزات

| # | الميزة | الوصف |
|---|--------|-------|
| 1 | 📡 **سكان الشبكات** | عرض الشبكات القريبة مع BSSID / Channel / Encryption / Power |
| 2 | 🎯 **اختيار شبكة** | اختيار هدفك بسهولة |
| 3 | ⚡ **هجوم Deauth** | إرسال حزم Deauth لتعطيل الأجهزة |
| 4 | 🤝 **التقاط Handshake** | التقاط EAPOL 4-way تلقائياً |
| 5 | 🔓 **كسر Handshake** | كسر باستخدام Wordlist (Multi-Processing) |
| 6 | 🎲 **تخمين مباشر** | التقاط + كسر بدون خطوات إضافية |
| 7 | ♻️ **إعادة استخدام Handshake** | استخدام handshake محفوظ |
| 8 | 📊 **تقرير JSON** | حفظ النتائج في `cracked.json` |
| 9 | 🩺 **تشخيص تلقائي** | فحص الأدوات + إصلاح تلقائي |
| 10 | 🚀 **Multiprocessing** | تسريع الكسر بعدة أنوية |

---

## 🖥️ المتطلبات

### 1) النظام
- **Linux** (Kali / Parrot / Ubuntu / Debian)
- صلاحيات **root**

### 2) 🔌 الأدابتر (كرت WiFi) — أهم شي

الأداة **لن تعمل** بدون كرت يدعم **Monitor Mode** + **Packet Injection**.

#### ✅ أدابترات مدعومة:
| الكرت | Monitor | Injection |
|-------|:---:|:---:|
| Alfa AWUS036NHA | ✅ | ✅ |
| Alfa AWUS036ACH | ✅ | ✅ |
| Alfa AWUS036NEH | ✅ | ✅ |
| TP-Link TL-WN722N **v1** | ✅ | ✅ |
| Panda PAU09 | ✅ | ✅ |
| Ralink RT3070 | ✅ | ✅ |
| Realtek RTL8812AU | ✅ | ✅ |

#### ❌ ما تشتغل:
- كروت **Built-in** في اللابتوبات الحديثة
- كروت **Broadcom** الحديثة
- **TL-WN722N v2/v3** (Monitor فقط بدون Injection)
- كروت **RTL8188** الرخيصة

#### 🔍 كيف أتأكد من كرتي؟
```bash
iw dev                        # عرض الكروت
sudo airmon-ng                # تفاصيل الكروت
sudo airmon-ng start wlan0    # جرب Monitor
# إذا ظهر wlan0mon ✅ وإلا ❌
```

#### 💡 نصيحة VM:
إذا تستخدم **VMware / VirtualBox** → فعّل **USB Passthrough** للأدابتر، وإلا ما راح تشتغل الأداة.

---

## 📦 التثبيت الكامل (أمر واحد)

### الخطوة 1: تثبيت كل الأدوات المطلوبة

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    aircrack-ng \
    wireless-tools \
    iw \
    net-tools \
    python3 \
    python3-pip \
    python3-dev \
    git \
    build-essential \
    libssl-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    pkg-config \
    macchanger \
    rfkill \
    wpasupplicant \
    ethtool
```

### الخطوة 2: التحقق من التثبيت

```bash
which aircrack-ng aireplay-ng airodump-ng airmon-ng iw macchanger
```

### الخطوة 3: نسخ المشروع

```bash
git clone https://github.com/pq4p/Abbas_Wifi.git
cd Abbas_Wifi
chmod +x Abbas_Wifi.py
```

### الخطوة 4: تحضير Wordlist

```bash
mkdir -p ~/netkiller

# استخدم rockyou (جاهز في Kali)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
cp /usr/share/wordlists/rockyou.txt ~/netkiller/wordlist.txt

# أو أنشئ wordlist خاص بك
nano ~/netkiller/wordlist.txt
```

### الخطوة 5: التشغيل

```bash
sudo python3 Abbas_Wifi.py
```

---

## 🚀 التشغيل السريع (نسخ/لصق كامل)

```bash
sudo apt update && \
sudo apt install -y aircrack-ng wireless-tools iw python3 python3-pip git macchanger rfkill && \
git clone https://github.com/pq4p/Abbas_Wifi.git && \
cd Abbas_Wifi && \
chmod +x Abbas_Wifi.py && \
mkdir -p ~/netkiller && \
sudo python3 Abbas_Wifi.py
```

---

## 📖 طريقة الاستخدام

```
═══ القائمة الرئيسية ═══
  1) سكان الشبكات
  2) عرض القائمة
  3) هجوم Deauth (تعطيل)
  4) التقاط Handshake
  5) كسر Handshake (بكلمة مرور)
  6) تخمين الشبكة (اختر شبكة + wordlist)
  7) إيقاف العمليات النشطة
  8) إعادة التشخيص
  9) عرض النتائج المحفوظة
  0) خروج
```

### سير العمل:

**التقليدية:** `1 → 4 → 5` (سكان → التقاط → كسر)

**السريعة:** `1 → 6` (سكان → تخمين تلقائي)

---

## 🔧 تشغيل Monitor Mode يدوياً

```bash
sudo airmon-ng check kill              # قتل الخدمات المتعارضة
sudo airmon-ng start wlan0             # تشغيل Monitor
iw dev                                  # تحقق: يظهر wlan0mon

# بعد الانتهاء
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

---

## 📂 هيكل الملفات

```
~/netkiller/
├── hs/                  # ملفات Handshake (.cap)
├── dumps/               # نتائج السكان
├── netkiller.log        # سجل العمليات
├── cracked.json         # كلمات المرور المكتشفة
└── wordlist.txt         # قائمة الكلمات
```

---

## 🧠 كيف تعمل الأداة؟

1. **Monitor Mode** → تحوّل الواجهة تلقائياً عبر `airmon-ng`
2. **سكان** → `airodump-ng` + تحليل CSV
3. **Deauth** → `aireplay-ng --deauth` لفصل الأجهزة
4. **التقاط Handshake** → فحص EAPOL 4-way
5. **الكسر** → PMK (PBKDF2-HMAC-SHA1) → PTK → MIC → مقارنة

---

## 📊 مثال المخرجات

```
╔══════════════════════════════════════════════════════════════╗
║  Abbas_Wifi v4.0                                              ║
║  المبرمج: جنرال عباس | @s.nfu                                ║
╚══════════════════════════════════════════════════════════════╝

[+] عدد الكلمات: 14,344,391
[+] عدد المعالجات: 7

[████████████████████░░░░░░░░░░░░░░░░░░░░] 52.3% | 7,500,000/14,344,391 | 12,450 H/s | 550s

✅ كلمة السر: MySecurePass123
⏱  612.4s | 📊 7,500,000 محاولة
```

---

## ⚙️ الإعدادات القابلة للتعديل

في ملف **`Abbas_Wifi.py`** يمكنك تعديل:

```python
SCAN_TIME        = 20       # مدة السكان
DEAUTH_BURST     = 64       # عدد الحزم
BURST_INTERVAL   = 0.3      # الفاصل بين الدفعات
CAPTURE_TIMEOUT  = 180      # مهلة الالتقاط
CAPTURE_MIN_SIZE = 10000    # أقل حجم لملف .cap
```

---

## 🐛 حل المشاكل الشائعة

| المشكلة | الحل |
|---------|------|
| `✗ ليس root` | شغّل بـ `sudo` |
| `✗ missing: aircrack-ng` | `sudo apt install -y aircrack-ng` |
| `✗ لا واجهة WiFi` | `iw dev` — تأكد من الكرت |
| `✗ لا يوجد Monitor Mode` | كرتك غير مدعوم — استخدم أدابتر |
| `✗ فشل السكان` | `sudo airmon-ng check kill` |
| `multiprocessing فشل` | يتحول تلقائياً لوضع Single |
| Handshake لا يُلتقط | اقترب من الراوتر + وجود عميل متصل |
| الكرت ما يشتغل في VM | فعّل **USB Passthrough** |
| `Operation not permitted` | شغّل بـ `sudo` |

---

## 🔍 أوامر فحص سريعة

```bash
iw dev                              # كروت WiFi
lsusb                               # أدابترات USB
ip link show                        # حالة الواجهات
sudo airmon-ng check kill           # قتل الخدمات المعطلة
sudo systemctl restart NetworkManager wpa_supplicant
```

---

## ⚠️ إخلاء المسؤولية

```
هذه الأداة مخصصة للأغراض التعليمية واختبار الاختراق الأخلاقي فقط.
- استخدام الأداة على شبكات لا تملكها = جريمة
- المبرمج غير مسؤول عن أي استخدام غير قانوني
- استخدم الأداة بمسؤولية تامة
```

---

## 👨‍💻 المبرمج

**جنرال عباس** 🇮🇶
- 📱 Instagram: [@s.nfu](https://www.instagram.com/s.nfu?stkn=a3c4ODJ1cGxlcDZh)
- 🔗 GitHub: [pq4p/Abbas_Wifi](https://github.com/pq4p/Abbas_Wifi)

---

## 📜 الرخصة

MIT License — راجع ملف `LICENSE`.

---

<div align="center">

**⭐ لا تنسَ النجمة ⭐**

**صُنع بـ ❤️ في العراق 🇮🇶**

</div>
