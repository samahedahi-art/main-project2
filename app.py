from flask import Flask, render_template, request, send_from_directory
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sqlite3
import datetime
import os
import socket
import ssl
import json

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, Image, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import arabic_reshaper
from bidi.algorithm import get_display

# ===============================
# App Config
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security_scanner.db")

app = Flask(__name__)

# ===============================
# Database
# ===============================
def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            status TEXT,
            score INTEGER,
            report TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ===============================
# Security Checks
# ===============================
def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip.startswith(("127.", "10.", "192.168."))
    except:
        return True

def check_https(url):
    return url.startswith("https://")

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
        return True
    except:
        return False

def check_headers(response):
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    return [h for h in required if h not in response.headers]

def check_sql_pattern(url):
    patterns = ["'", "\"", " OR ", " AND ", "--", ";"]
    return any(p.lower() in url.lower() for p in patterns)

def check_xss_forms(soup):
    forms = soup.find_all("form")
    for form in forms:
        if not form.get("method") or form.get("method").lower() == "get":
            return True
    return False

def analyze_site(url):
    try:
        r = requests.get(url, timeout=15, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        return {
            "status_code": r.status_code,
            "scripts": soup.find_all("script"),
            "iframes": soup.find_all("iframe"),
            "redirects": len(r.history),
            "missing_headers": check_headers(r),
            "soup": soup
        }
    except:
        return None

# ===============================
# Build Report
# ===============================
def build_report(url, analysis):
    if not analysis:
        return "🔴 غير متاح", 0, [{"title": "فشل الاتصال", "description": "تعذر الوصول للموقع", "score": 0}]
    score = 100
    report = []
    parsed = urlparse(url)
    if is_private_ip(parsed.hostname):
        return "🔴 مرفوض", 0, [{"title": "عنوان محلي غير مسموح", "description": "", "score": 0}]

    if not check_https(url):
        score -= 20
        report.append({"title": "لا يستخدم HTTPS", "description": "الاتصال غير مشفر", "score": 30})
    else:
        if not check_ssl(parsed.hostname):
            score -= 15
            report.append({"title": "SSL غير صالح", "description": "مشكلة في الشهادة", "score": 60})

    if analysis["status_code"] != 200:
        score -= 15
        report.append({"title": "استجابة غير طبيعية", "description": f"Status {analysis['status_code']}", "score": 50})

    score -= len(analysis["missing_headers"]) * 5

    if analysis["redirects"] > 3:
        score -= 10
        report.append({"title": "إعادة توجيه كثيرة", "description": "عدد تحويلات مرتفع", "score": 40})

    if len(analysis["scripts"]) > 8:
        score -= 10
        report.append({"title": "سكريبتات كثيرة", "description": "قد تحتوي على إعلانات مفرطة", "score": 60})

    if analysis["iframes"]:
        score -= 10
        report.append({"title": "iframe خارجي", "description": "قد يكون بث من مصدر غير معروف", "score": 40})

    if check_sql_pattern(url):
        score -= 10
        report.append({"title": "مؤشر SQL Injection", "description": "الرابط يحتوي رموز مشبوهة", "score": 40})

    if check_xss_forms(analysis["soup"]):
        score -= 5
        report.append({"title": "نموذج GET غير محمي", "description": "قد يكون عرضة XSS", "score": 60})

    score = max(score, 0)
    status = "🟢 آمن غالباً" if score >= 80 else "🟡 متوسط الخطورة" if score >= 50 else "🔴 عالي الخطورة"
    return status, score, report

# ===============================
# Save Scan
# ===============================
def save_scan(url, status, score, report):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO scan_results (url, status, score, report, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (url, status, score, json.dumps(report, ensure_ascii=False),
          datetime.datetime.now().isoformat()))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id

# ===============================
# PDF Generator (Updated)
# ===============================
import os
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Image, ListFlowable, ListItem
)
from reportlab.lib.pagesizes import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_RIGHT, TA_CENTER
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.platypus import Table, TableStyle
from reportlab.lib.colors import HexColor

# ألوان مستوحاة من تصميم الموقع
CYBER_DARK = HexColor("#0f172a")   
CYBER_BLUE = HexColor("#0ea5e9")   
CYBER_LIGHT = HexColor("#e0f2fe")  
CYBER_GLOW = HexColor("#38bdf8")   

# =======================
# Font
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
pdfmetrics.registerFont(
    TTFont('Amiri', os.path.join(BASE_DIR, 'static/fonts/Amiri-Regular.ttf'))
)

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from PIL import Image as PILImage
import os
import arabic_reshaper
from bidi.algorithm import get_display

def generate_pdf(scan_id, url, status, score, report, advice):
    # مسار التقرير
    filename = f"report_{scan_id}.pdf"
    path = os.path.join(BASE_DIR, filename)

    doc = SimpleDocTemplate(
        path,
        pagesize=(8.5 * inch, 11 * inch),
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=50
    )

    elements = []

    TEXT_DARK = colors.HexColor("#0B3D91")

    # ======================
    # الأنماط
    # ======================
    heading_style = ParagraphStyle(
        name='HeadingStyle',
        fontName='Amiri',
        fontSize=22,
        alignment=TA_CENTER,
        textColor=TEXT_DARK,
        spaceAfter=25
    )

    section_style = ParagraphStyle(
        name='SectionStyle',
        fontName='Amiri',
        fontSize=15,
        alignment=TA_RIGHT,
        textColor=TEXT_DARK,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        name='NormalStyle',
        fontName='Amiri',
        fontSize=13,
        alignment=TA_RIGHT,
        textColor=colors.black,
        spaceAfter=6
    )

    # ======================
    # الشعار
    # ======================
    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        elements.append(Image(logo_path, width=80, height=80, hAlign='CENTER'))
    elements.append(Spacer(1, 15))

    # ======================
    # العنوان الرئيسي مع خط
    # ======================
    title_text = "تقرير فحص أمان الموقع"
    reshaped_title = arabic_reshaper.reshape(title_text)
    bidi_title = get_display(reshaped_title)
    elements.append(Paragraph(f"<u>{bidi_title}</u>", heading_style))
    elements.append(Spacer(1, 20))

    # ======================
    # معلومات الفحص مع خط تحت القسم
    # ======================
    section_text = "معلومات الفحص"
    reshaped_section = arabic_reshaper.reshape(section_text)
    bidi_section = get_display(reshaped_section)
    elements.append(Paragraph(f"<u>{bidi_section}</u>", section_style))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(get_display(arabic_reshaper.reshape(f"الرابط: {url}")), normal_style))
    elements.append(Paragraph(get_display(arabic_reshaper.reshape(f"الحالة: {status}")), normal_style))
    elements.append(Spacer(1, 20))

    # ======================
    # مستوى الأمان بالأرقام مع خط تحت القسم
    # ======================
    section_text = "مستوى الأمان"
    reshaped_section = arabic_reshaper.reshape(section_text)
    bidi_section = get_display(reshaped_section)
    elements.append(Paragraph(f"<u>{bidi_section}</u>", section_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(get_display(arabic_reshaper.reshape(f"{score}%")), heading_style))
    elements.append(Spacer(1, 25))

    # ======================
    # التحليل التفصيلي مع خط تحت القسم
    # ======================
    section_text = "التحليل التفصيلي"
    reshaped_section = arabic_reshaper.reshape(section_text)
    bidi_section = get_display(reshaped_section)
    elements.append(Paragraph(f"<u>{bidi_section}</u>", section_style))
    elements.append(Spacer(1, 10))

    for item in report:
        title_text = get_display(arabic_reshaper.reshape(item.get('title', '')))
        desc_text = get_display(arabic_reshaper.reshape(item.get('description', '')))
        val = item.get('score', 0)
        elements.append(Paragraph(title_text, normal_style))
        elements.append(Paragraph(desc_text, normal_style))
        elements.append(Paragraph(get_display(arabic_reshaper.reshape(f"الدرجة: {val}%")), normal_style))
        elements.append(Spacer(1, 15))

    # ======================
    # نصيحة المشاهدة مع خط تحت القسم
    # ======================
    section_text = "نصيحة المشاهدة"
    reshaped_section = arabic_reshaper.reshape(section_text)
    bidi_section = get_display(reshaped_section)
    elements.append(Paragraph(f"<u>{bidi_section}</u>", section_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(get_display(arabic_reshaper.reshape(advice)), normal_style))

    # ======================
    # الخلفية صورة back.jpg بدون أي إطار وخفيفة
    # ======================
    def add_background(canvas, doc):
        canvas.saveState()
        back_path = os.path.join("static", "back.jpg")
        if os.path.exists(back_path):
            pil_img = PILImage.open(back_path).convert("RGBA")
            alpha = 0.9  # أخف خلفية لتوضيح النصوص
            overlay = PILImage.new('RGBA', pil_img.size, (255, 255, 255, int(255 * alpha)))
            pil_img = PILImage.alpha_composite(pil_img, overlay)
            img = ImageReader(pil_img)
            canvas.drawImage(img, 0, 0, width=612, height=792, mask='auto')



        # إطار خفيف حول الصفحة
        canvas.setStrokeColor(colors.HexColor("#82E0F5"))
        canvas.setLineWidth(1)

         # dash = [طول الخط, طول الفراغ] بالبوينت
        canvas.setDash(6, 3)  # 6 بوينت خط، 3 بوينت فراغ
        
        canvas.rect(30, 30, 552, 732, fill=0)

        canvas.restoreState()

    # ======================
    # بناء التقرير
    # ======================
    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)

    return filename
# ===============================
# Routes
# ===============================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")
    if not url:
        return "أدخل رابط صحيح"
    if not url.startswith("http"):
        url = "http://" + url

    analysis = analyze_site(url)

    if not analysis:
        status = "🔴 غير متاح"
        final_score = 0
        report = [{"title": "فشل الاتصال", "description": "تعذر الوصول للموقع", "score": 0}]
        advice = "🔴 لا يمكن تحليل الموقع"
    else:
        status, base_score, report = build_report(url, analysis)
        https_score = 100 if url.startswith("https://") else 30
        headers_score = max(0, 100 - (len(analysis["missing_headers"]) * 20))
        behavior_score = 100
        behavior_score -= len(analysis["scripts"])*5
        behavior_score -= len(analysis["iframes"])*10
        behavior_score = max(0, behavior_score)
        piracy_score = 100
        if analysis["iframes"]:
            piracy_score -= 30
        sql_score = 100 if not check_sql_pattern(url) else 40
        xss_score = 100 if not check_xss_forms(analysis["soup"]) else 60
        final_score = round((https_score + headers_score + behavior_score + piracy_score + sql_score + xss_score)/6)
        status = "🟢 آمن غالباً" if final_score >= 80 else "🟡 متوسط الخطورة" if final_score >=50 else "🔴 عالي الخطورة"

        # نصيحة المشاهدة مع مواقع موثوقة
        trusted_sites = ["netflix.com", "youtube.com", "disneyplus.com"]
        hostname = urlparse(url).hostname or ""
        if any(site in hostname for site in trusted_sites):
            advice = "🟢 الموقع موثوق ويمكن المشاهدة بأمان."
        else:
            critical_risk = any(item["title"] in ["مؤشر SQL Injection", "SSL غير صالح", "لا يستخدم HTTPS"] for item in report)
            warning_risk = any(item["title"] in ["iframe خارجي", "سكريبتات كثيرة", "إعادة توجيه كثيرة"] for item in report)
            if critical_risk:
                advice = "🔴 لا يُنصح بالمشاهدة لوجود ثغرات خطيرة."
            elif warning_risk:
                advice = "🟡 يمكن المشاهدة لكن بحذر لوجود مؤشرات غير مطمئنة."
            elif final_score >= 85:
                advice = "🟢 الموقع آمن ويمكنك المشاهدة بأمان."
            else:
                advice = "🟡 مستوى الأمان متوسط، يفضل الحذر."

    scan_id = save_scan(url, status, final_score, report)
    pdf_file = generate_pdf(scan_id, url, status, final_score, report, advice)

    return render_template("result.html",
        url=url,
        status=status,
        score=final_score,
        report=report,
        pdf_file=pdf_file,
        advice=advice,
        https_score=https_score if analysis else 0,
        headers_score=headers_score if analysis else 0,
        behavior_score=behavior_score if analysis else 0,
        piracy={"score": piracy_score if analysis else 0},
        sql_score=sql_score if analysis else 0,
        xss_score=xss_score if analysis else 0
    )

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(BASE_DIR, filename, as_attachment=True)

# ===============================
if __name__ == "__main__":
    app.run(debug=True)