import asyncio
import requests
import socket
import ssl
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import dns.resolver
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# ========== قم بتغيير هذا إلى توكن البوت الخاص بك ==========
BOT_TOKEN = "1933471238:AAHCB_GMbIZanMExNEHn9YFaz5RlzIXLcF0"
# ========================================================

# --- دوال الفحص الأمني ---

def get_headers_info(url):
    """فحص الهيدرات الأمنية"""
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        headers = r.headers
        security_headers = {
            "Strict-Transport-Security": "HSTS مفعل ✅" if "Strict-Transport-Security" in headers else "HSTS غير مفعل ❌",
            "X-Frame-Options": "حماية من Clickjacking مفعلة ✅" if "X-Frame-Options" in headers else "Clickjacking protection غير مفعلة ❌",
            "X-Content-Type-Options": "حماية MIME مفعلة ✅" if "X-Content-Type-Options" in headers else "MIME protection غير مفعلة ❌",
            "Content-Security-Policy": "CSP موجود ✅" if "Content-Security-Policy" in headers else "CSP غير موجود ❌",
            "X-XSS-Protection": "XSS Protection مفعل ✅" if "X-XSS-Protection" in headers else "XSS Protection غير مفعل ❌"
        }
        return security_headers, r.status_code, r.elapsed.total_seconds()
    except Exception as e:
        return {"خطأ": str(e)}, None, None

def get_ip_info(domain):
    """الحصول على IP والسيرفر"""
    try:
        ip = socket.gethostbyname(domain)
        # محاولة الحصول على اسم السيرفر
        try:
            r = requests.get(f"https://{domain}", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            server = r.headers.get("Server", "غير معروف")
        except:
            server = "غير معروف (قد لا يدعم HTTPS)"
        return ip, server
    except Exception as e:
        return str(e), "غير معروف"

def check_ssl(domain):
    """فحص شهادة SSL"""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(cert.get("issuer", []))
            subject = dict(cert.get("subject", []))
            expires = cert.get("notAfter", "غير معروف")
            issuer_name = issuer.get("organizationName", "غير معروف")
            return issuer_name, expires
    except:
        return "لا يدعم HTTPS", "N/A"

def get_dns_records(domain):
    """فحص سجلات DNS"""
    records = {}
    for record_type in ["A", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers[:3]]  # أقصى 3 نتائج
        except:
            records[record_type] = []
    return records

def scan_for_common_paths(url):
    """فحص مسارات شائعة"""
    common_paths = [
        "/admin", "/login", "/wp-admin", "/administrator",
        "/robots.txt", "/sitemap.xml", "/.env", "/backup",
        "/config", "/.git/config", "/phpinfo.php", "/info.php",
        "/api", "/swagger.json", "/.htaccess", "/crossdomain.xml"
    ]
    found = []
    for path in common_paths:
        try:
            full_url = f"{url.rstrip('/')}{path}"
            r = requests.get(full_url, timeout=3, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                found.append(f"{path} (200 OK) - موجود ✅")
            elif r.status_code == 403:
                found.append(f"{path} (403 Forbidden) - موجود لكن ممنوع ⚠️")
            elif r.status_code == 301 or r.status_code == 302:
                found.append(f"{path} ({r.status_code} Redirect) 🔄")
        except:
            pass
    return found

def check_technologies(url):
    """كشف التقنيات المستخدمة"""
    techs = []
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        
        # فحص من الصفحة
        if soup.find("meta", attrs={"name": "generator"}):
            gen = soup.find("meta", attrs={"name": "generator"})
            techs.append(f"CMS: {gen.get('content', 'غير معروف')}")
        
        # فحص من الهيدرات
        server = r.headers.get("Server", "")
        if server:
            techs.append(f"سيرفر: {server}")
        
        # فحص X-Powered-By
        powered = r.headers.get("X-Powered-By", "")
        if powered:
            techs.append(f"Powered by: {powered}")
        
        # فحص Set-Cookie
        set_cookie = r.headers.get("Set-Cookie", "")
        if "PHPSESSID" in set_cookie:
            techs.append("لغة: PHP ✅")
        elif "ASP.NET" in set_cookie or "ASPSESSIONID" in set_cookie:
            techs.append("لغة: ASP.NET ✅")
        elif "JSESSIONID" in set_cookie:
            techs.append("لغة: Java (JSP) ✅")
        
        if not techs:
            techs.append("لم يتم كشف تقنيات محددة")
    except:
        techs.append("فشل الاتصال")
    return techs

def check_open_ports(domain):
    """فحص البورتات المفتوحة (أساسية)"""
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port <= 1024 else "custom"
                open_ports.append(f"{port}/{service}")
            sock.close()
        except:
            pass
    return open_ports

def check_form_handling(url):
    """فحص وجود فورم"""
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        form_count = len(forms)
        inputs_count = len(soup.find_all("input"))
        return form_count, inputs_count
    except:
        return 0, 0

async def scan_website(url):
    """الفحص الكامل"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    
    result = []
    result.append("=" * 50)
    result.append(f"🔍 تقرير الفحص الأمني للموقع")
    result.append(f"🎯 الرابط: {url}")
    result.append(f"⏰ الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    result.append("=" * 50)
    
    # 1. معلومات IP والسيرفر
    result.append("\n📡 **معلومات الخادم**")
    ip, server = get_ip_info(domain)
    result.append(f"📍 الـ IP: {ip}")
    result.append(f"🖥️ السيرفر: {server}")
    
    # 2. SSL
    result.append("\n🔐 **شهادة SSL**")
    ssl_issuer, ssl_expiry = check_ssl(domain)
    result.append(f"🏢 المُصدر: {ssl_issuer}")
    result.append(f"📅 تنتهي: {ssl_expiry}")
    
    # 3. الهيدرات الأمنية
    result.append("\n🛡️ **الهيدرات الأمنية**")
    sec_headers, status_code, response_time = get_headers_info(url)
    for header, value in sec_headers.items():
        result.append(f"  {value}")
    result.append(f"📊 حالة الاتصال: {status_code}")
    result.append(f"⏱ زمن الاستجابة: {response_time} ثانية")
    
    # 4. التقنيات
    result.append("\n⚙️ **التقنيات المكتشفة**")
    techs = check_technologies(url)
    for t in techs:
        result.append(f"  • {t}")
    
    # 5. DNS
    result.append("\n🌐 **سجلات DNS**")
    dns_records = get_dns_records(domain)
    for rtype, rlist in dns_records.items():
        if rlist:
            for r in rlist:
                result.append(f"  {rtype}: {r}")
        else:
            result.append(f"  {rtype}: لا يوجد")
    
    # 6. البورتات المفتوحة
    result.append("\n🚪 **البورتات المفتوحة (الأساسية)**")
    ports = check_open_ports(domain)
    if ports:
        for p in ports:
            result.append(f"  • بورت {p} مفتوح ⚠️")
    else:
        result.append("  لا توجد بورتات أساسية مكشوفة ✅")
    
    # 7. المسارات الحساسة
    result.append("\n📁 **المسارات المكتشفة**")
    paths = scan_for_common_paths(url)
    if paths:
        for p in paths:
            result.append(f"  {p}")
    else:
        result.append("  لم يتم العثور على مسارات حساسة ✅")
    
    # 8. الفورم
    result.append("\n📝 **النماذج (Forms)**")
    form_count, input_count = check_form_handling(url)
    result.append(f"  عدد النماذج: {form_count}")
    result.append(f"  عدد الحقول: {input_count}")
    if form_count > 0:
        result.append("  ⚠️ يوجد نماذج - قد تكون نقطة دخول للهجمات (SQLi, XSS)")
    
    result.append("\n" + "=" * 50)
    result.append("✅ انتهى الفحص. يرجى مراجعة النتائج بعناية.")
    result.append("⚠️ تذكير: هذا الفحص مخصص للأغراض الأمنية المصرح بها فقط.")
    result.append("=" * 50)
    
    return "\n".join(result)

# --- دوال البوت ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **مرحباً بك في بوت فحص المواقع الأمني!**\n\n"
        "أرسل لي رابط الموقع الذي تريد فحصه وسأقوم بـ:\n"
        "✅ فحص الهيدرات الأمنية\n"
        "✅ كشف IP والتقنيات\n"
        "✅ فحص SSL\n"
        "✅ سجلات DNS\n"
        "✅ فحص البورتات المفتوحة\n"
        "✅ البحث عن مسارات حساسة\n"
        "✅ وأكثر...\n\n"
        "📌 مثال: `https://example.com`\n\n"
        "⚠️ **ملاحظة:** استخدم هذا البوت فقط على المواقع التي تملك تصريحاً باختبارها.",
        parse_mode="Markdown"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔍 **كيفية الاستخدام:**\n\n"
        "1. أرسل رابط الموقع كاملاً (مثال: https://example.com)\n"
        "2. انتظر حتى ينتهي الفحص (قد يستغرق 30-60 ثانية)\n"
        "3. ستحصل على تقرير كامل بالنتائج\n\n"
        "الأوامر:\n"
        "/start - بدء المحادثة\n"
        "/help - تعليمات المساعدة\n"
        "/scan [الرابط] - فحص موقع معين",
        parse_mode="Markdown"
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ الرجاء إرسال رابط الموقع. مثال: /scan https://example.com")
        return
    
    url = " ".join(context.args)
    await update.message.reply_text(f"🔍 جاري فحص {url}، الرجاء الانتظار... (قد يستغرق 30-60 ثانية)")
    
    try:
        report = await scan_website(url)
        # تقسيم التقرير الطويل
        if len(report) > 4000:
            parts = [report[i:i+4000] for i in range(0, len(report), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="Markdown")
        else:
            await update.message.reply_text(report, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ أثناء الفحص: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    
    # التحقق من أن النص قد يكون رابط
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # فحص بسيط إن كان رابط صحيح
    if "." not in url:
        await update.message.reply_text("❌ الرجاء إرسال رابط صحيح. مثال: https://example.com")
        return
    
    await update.message.reply_text(f"🔍 جاري فحص {url}...")
    
    try:
        report = await scan_website(url)
        if len(report) > 4000:
            parts = [report[i:i+4000] for i in range(0, len(report), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="Markdown")
        else:
            await update.message.reply_text(report, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

def main():
    """تشغيل البوت"""
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 البوت يعمل... أرسل /start في تيليجرام")
    app.run_polling()

if __name__ == "__main__":
    main()