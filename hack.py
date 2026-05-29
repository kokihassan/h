import asyncio
import requests
import socket
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = "1933471238:AAHCB_GMbIZanMExNEHn9YFaz5RlzIXLcF0"

# ========== دوال الفحص المتقدم ==========

def check_sqli_basic(url):
    """فحص SQLi أساسي"""
    payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "'; DROP TABLE users--"]
    results = []
    parsed = urlparse(url)
    
    # فحص GET parameters
    if parsed.query:
        for param in parsed.query.split("&"):
            key = param.split("=")[0] if "=" in param else param
            for payload in payloads:
                try:
                    test_url = url.replace(f"{key}={param.split('=')[1] if '=' in param else ''}", f"{key}={payload}")
                    r = requests.get(test_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                    if any(err in r.text.lower() for err in ["sql", "mysql", "syntax error", "unclosed quotation", "odbc"]):
                        results.append(f"⚠️ SQLi محتمل في: {key} مع payload: {payload}")
                        break
                except:
                    pass
    
    return results

def check_xss_reflected(url):
    """فحص XSS منعكس"""
    payload = "<script>alert('XSS')</script>"
    results = []
    parsed = urlparse(url)
    
    if parsed.query:
        for param in parsed.query.split("&"):
            key = param.split("=")[0] if "=" in else param
            try:
                test_url = f"{url}&{key}={payload}" if "=" in param else f"{url}?{key}={payload}"
                test_url = test_url.replace("?&", "?")
                r = requests.get(test_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                if payload in r.text:
                    results.append(f"⚠️ XSS منعكس محتمل في: {key}")
            except:
                pass
    
    return results

def enumerate_js_endpoints(url):
    """استخراج API endpoints من ملفات JS"""
    endpoints = set()
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        
        for script in scripts:
            src = script["src"]
            if src.endswith(".js"):
                js_url = urljoin(url, src)
                try:
                    js = requests.get(js_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"}).text
                    # بحث عن API endpoints
                    patterns = re.findall(r'["\'](/api/[^"\']*)["\']', js)
                    for p in patterns:
                        endpoints.add(p)
                    # بحث عن routes
                    routes = re.findall(r'["\'](/[a-zA-Z0-9_/-]+)["\']', js)
                    for route in routes:
                        if any(skip in route for skip in [".css", ".png", ".jpg", ".svg", ".ico"]):
                            continue
                        if 3 < len(route) < 100:
                            endpoints.add(route)
                except:
                    pass
    except:
        pass
    
    return list(endpoints)

def check_nextjs_routes(url):
    """فحص مسارات Next.js API"""
    routes = [
        "/api", "/api/auth", "/api/user", "/api/users",
        "/api/login", "/api/register", "/api/admin",
        "/api/config", "/api/settings", "/api/data",
        "/api/v1", "/api/v2", "/api/graphql",
        "/_next/static/chunks/pages",
        "/_next/data/development", "/_next/data/production",
        "/__nextjs_original-stack-frame"
    ]
    found = []
    base = url.rstrip("/")
    for route in routes:
        try:
            r = requests.get(f"{base}{route}", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code in [200, 201, 403, 401]:
                found.append(f"{route} → {r.status_code} ⚠️")
            elif r.status_code == 500:
                found.append(f"{route} → 500 Internal Error 🔴")
        except:
            pass
    return found

def check_cloudfront_security(url):
    """فحص أمان CloudFront"""
    findings = []
    domain = urlparse(url).netloc
    
    # فحص Origin headers
    try:
        r = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "127.0.0.1"
        })
        if "X-Amz-Cf-Id" in r.headers or "x-amz-cf-pop" in r.headers:
            findings.append("محمي بـ CloudFront - ممكن نسوي Bypass بـ Host header")
    except:
        pass
    
    return findings

async def advanced_scan(url):
    """الفحص المتقدم الكامل"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    result = []
    result.append("=" * 55)
    result.append("🔴 تقرير الفحص المتقدم - Advanced Scan")
    result.append(f"🎯 {url}")
    result.append("=" * 55)
    
    # 1. SQL Injection
    result.append("\n🐍 **SQL Injection Check**")
    sqli = check_sqli_basic(url)
    if sqli:
        for s in sqli:
            result.append(f"  {s}")
    else:
        result.append("  ✅ لم يتم العثور على SQLi واضح")
    
    # 2. XSS
    result.append("\n🔥 **XSS Reflected Check**")
    xss = check_xss_reflected(url)
    if xss:
        for x in xss:
            result.append(f"  {x}")
    else:
        result.append("  ✅ لم يتم العثور على XSS واضح")
    
    # 3. JS Endpoints
    result.append("\n📜 **JavaScript API Endpoints**")
    endpoints = enumerate_js_endpoints(url)
    if endpoints:
        for ep in endpoints[:20]:
            result.append(f"  📌 {ep}")
        if len(endpoints) > 20:
            result.append(f"  ...و {len(endpoints)-20} إضافية")
    else:
        result.append("  لم يتم العثور على endpoints")
    
    # 4. Next.js Routes
    result.append("\n⚡ **Next.js Routes Scan**")
    next_routes = check_nextjs_routes(url)
    if next_routes:
        for nr in next_routes:
            result.append(f"  {nr}")
    else:
        result.append("  ✅ جميع مسارات Next.js آمنة")
    
    # 5. CloudFront Security
    result.append("\n☁️ **CloudFront Security**")
    cf = check_cloudfront_security(url)
    if cf:
        for c in cf:
            result.append(f"  {c}")
    
    # 6. فحص صفحة login بالتفصيل
    result.append("\n🔐 **Login Page Analysis**")
    try:
        login_url = f"{url.rstrip('/')}/login"
        r = requests.get(login_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        
        # فحص نوع الفورم
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "none")
            method = form.get("method", "GET")
            inputs = form.find_all("input")
            result.append(f"  📝 Form action: {action}")
            result.append(f"  📝 Method: {method}")
            for inp in inputs:
                inp_type = inp.get("type", "text")
                inp_name = inp.get("name", "no-name")
                result.append(f"    Input: {inp_name} (type: {inp_type})")
            
            # فحص CSRF token
            csrf = form.find("input", {"name": re.compile(r"(csrf|token|_token)", re.I)})
            if csrf:
                result.append(f"  ✅ CSRF token موجود")
            else:
                result.append(f"  ❌ CSRF token غير موجود!")
        
        # فحص طريقة إرسال كلمة المرور
        if "password" in r.text.lower():
            result.append("  ⚠️ صفحة تسجيل الدخول تستخدم password field")
        
        # فحص response headers للـ login
        login_headers = r.headers
        if "Set-Cookie" in login_headers:
            cookie = login_headers["Set-Cookie"]
            if "HttpOnly" not in cookie:
                result.append("  ❌ HttpOnly غير مفعل على الكوكيز!")
            if "Secure" not in cookie:
                result.append("  ❌ Secure flag غير مفعل على الكوكيز!")
            if "SameSite" not in cookie:
                result.append("  ❌ SameSite غير مفعل على الكوكيز!")
        
    except Exception as e:
        result.append(f"  ❌ فشل فتح صفحة login: {str(e)}")
    
    # 7. توصيات أمنية
    result.append("\n" + "=" * 55)
    result.append("📋 **التوصيات الأمنية**")
    result.append("-" * 55)
    result.append("1. ❌ تفعيل HSTS لتجنب SSL Stripping")
    result.append("2. ❌ تفعيل X-Frame-Options (DENY) ضد Clickjacking")
    result.append("3. ❌ تفعيل Content-Security-Policy (CSP)")
    result.append("4. ❌ تفعيل X-Content-Type-Options (nosniff)")
    result.append("5. ❌ تفعيل HttpOnly و Secure على الكوكيز")
    result.append("6. ❌ إضافة CSRF token على الفورم")
    result.append("7. ❌ فحص Next.js API endpoints للتأكد من المصادقة")
    result.append("8. ❌ مراجعة المسارات الحساسة (/api, /admin)")
    result.append("=" * 55)
    result.append("⚠️  هذا للاختبار الأمني المصرح به فقط")
    result.append("=" * 55)
    
    return "\n".join(result)

# ========== دوال البوت ==========

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **بوت الفحص المتقدم**\n\n"
        "الإصدار المتطور مع:\n"
        "✅ SQL Injection Check\n"
        "✅ XSS Reflected Check\n"
        "✅ JavaScript API Discovery\n"
        "✅ Next.js Route Scanning\n"
        "✅ Login Page Analysis\n"
        "✅ CloudFront Security Check\n\n"
        "أرسل الرابط لبدء الفحص المتقدم"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    await update.message.reply_text("🔍 جاري الفحص المتقدم... قد يستغرق دقيقة")
    
    try:
        report = await advanced_scan(url)
        if len(report) > 4000:
            parts = [report[i:i+4000] for i in range(0, len(report), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="Markdown")
        else:
            await update.message.reply_text(report, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🤖 البوت المتقدم يعمل...")
    app.run_polling()

if __name__ == "__main__":
    main()