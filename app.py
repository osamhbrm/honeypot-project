from flask import Flask, render_template, request, jsonify, redirect, url_for,abort
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import geocoder
import random
import os
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///honeypot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# المسار الافتراضي لملف لوقات كاوري (تأكد من صلاحيات القراءة لهذا الملف)
COWRIE_LOG_PATH = "/app/cowrie_logs/cowrie.json"

class AttackLog(db.Model):
    __tablename__ = 'attack_log'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50))
    country = db.Column(db.String(100), default="Unknown")
    city = db.Column(db.String(100), default="Unknown")
    user_agent = db.Column(db.String(500))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    attack_type = db.Column(db.String(100))
    request_path = db.Column(db.String(500))
    request_method = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self):
        """تحويل السجل إلى قاموس مع إضافة حقل المصدر لتمييز الهجمات"""
        return {
            'id': f"web_{self.id}", # إضافة بادئة لتمييز المعرف عن SSH
            'source': 'web',
            'ip_address': self.ip_address,
            'country': self.country,
            'city': self.city,
            'user_agent': self.user_agent,
            'username': self.username or "-",
            'password': self.password or "-",
            'attack_type': self.attack_type,
            'request_path': self.request_path,
            'request_method': self.request_method,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None
        }


def init_database():
    """إنشاء الجداول إذا لم تكن موجودة"""
    with app.app_context():
        try:
            test = AttackLog.query.first()
            print("[+] Database exists and is ready")
        except Exception as e:
            print("[-] Table not found, creating...")
            db.create_all()
            print("[+] Tables created successfully!")


def get_location_from_ip(ip):
    """جلب الموقع الجغرافي للمخترق"""
    if ip == '127.0.0.1':
        fake_locations = [
            ("Russia", "Moscow"),
            ("China", "Beijing"),
            ("North Korea", "Pyongyang"),
            ("Iran", "Tehran"),
            ("Unknown", "Unknown")
        ]
        return random.choice(fake_locations)
    
    try:
        g = geocoder.ipinfo(ip)
        if g.ok:
            return g.country, g.city
    except Exception as e:
        print(f"Error fetching location: {e}")
    
    return "Unknown", "Unknown"

init_database()


# دالة مساعدة لقراءة وتحليل لوقات كاوري (SSH) وتوحيدها مع قالب المشروع
def parse_cowrie_logs():
    cowrie_attacks = []
    if not os.path.exists(COWRIE_LOG_PATH):
        return cowrie_attacks

    try:
        with open(COWRIE_LOG_PATH, "r") as f:
            for line in f:
                try:
                    log = json.loads(line)
                    event_id = log.get("eventid")
                    
                    # نفلتر الأحداث المهمة فقط: محاولات الدخول، أو الأوامر المنفذة
                    if event_id in ["cowrie.login.success", "cowrie.login.failed", "cowrie.command.input"]:
                        
                        # معالجة الوقت وتوحيده ليطابق الـ Format الخاص بـ Flask
                        raw_time = log.get("timestamp", "")
                        try:
                            clean_time = raw_time.split(".")[0].replace("T", " ")
                        except:
                            clean_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        # تحديد نوع التهديد والـ Payload المستهدف
                        if "login" in event_id:
                            attack_type = "SSH Bruteforce Attempt"
                            req_path = "SSH Port 22"
                        else:
                            attack_type = "SSH Command Execution"
                            req_path = f"Cmd: {log.get('input', '-')}"

                        # الاستفادة من دالة تحديد الموقع الخاصة بمشروعك لعناوين الـ IP القادمة من SSH
                        ip = log.get("src_ip", "0.0.0.0")
                        country, city = get_location_from_ip(ip)

                        attack_data = {
                            'id': f"ssh_{log.get('session', '0')[:5]}_{log.get('messageid', '0')[:3]}",
                            'source': 'ssh',
                            'ip_address': ip,
                            'country': country,
                            'city': city,
                            'user_agent': "SSH Client",
                            'username': log.get("username", "-"),
                            'password': log.get("password", "-"),
                            'attack_type': attack_type,
                            'request_path': req_path,
                            'request_method': "SSH",
                            'timestamp': clean_time
                        }
                        cowrie_attacks.append(attack_data)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading Cowrie logs: {e}")
        
    return cowrie_attacks


def is_directory_traversal(input_data):
    patterns = ["../", "..\\", "%2e%2e", "%2f", "/etc/passwd", "windows/system32"]
    input_data = input_data.lower()
    for p in patterns:
        if p in input_data:
            return True
    return False


def detect_attack(username, password):
    payload = f"{username}{password}".lower()

    sql_patterns = ["'", "--", ";", "or 1=1", "union select", "insert into", "drop table", "update", "delete"]
    for pattern in sql_patterns:
        if pattern in payload:
            return "SQL Injection Attempt"

    xss_patterns = ["<script>", "javascript:", "onload=", "onerror=", "onclick=", "alert("]
    for pattern in xss_patterns:
        if pattern in payload:
            return "XSS Attempt"

    if is_directory_traversal(payload):
        return "Directory Traversal"

    ssrf_patterns = ["http://", "https://", "169.254.169.254", "127.0.0.1", "localhost", "file://"]
    for pattern in ssrf_patterns:
        if pattern in payload:
            return "SSRF Attempt"

    crlf_patterns = ["%0d%0a", "%0d", "%0a", "\r", "\n"]
    for pattern in crlf_patterns:
        if pattern in payload:
            return "CRLF Injection Attempt"

    default_users = ["admin", "root", "administrator", "guest"]
    default_passwords = ["admin", "root", "password", "123456", "12345678", "toor"]
    if username.lower() in default_users and password.lower() in default_passwords:
        return "Default Credentials Attempt"

    return "Normal Attempt"


@app.route('/')
def hello_world():
    # توجيه المستخدم مباشرة إلى دالة صفحة الـ login
    return redirect(url_for('login'))


@app.before_request
def detect_traversal_globally():
    if request.path.startswith('/api/') or request.path == '/dashboard':
        return # تجنب فحص مسارات لوحة التحكم حتى لا تمنع نفسك من الدخول لقراءة اللوقات

    full_request = request.full_path.lower()
    if is_directory_traversal(full_request):
        try:
            country, city = get_location_from_ip(request.remote_addr)
            attack_log = AttackLog(
                ip_address=request.remote_addr,
                country=country,
                city=city,
                user_agent=request.headers.get("User-Agent", "Unknown"),
                username=request.form.get("username", ""),
                password=request.form.get("password", ""),
                attack_type="Directory Traversal",
                request_path=request.path,
                request_method=request.method
            )
            db.session.add(attack_log)
            db.session.commit()
            print(f"[+] Saved Directory Traversal attack from {request.remote_addr}")
        except Exception as e:
            print(f"[-] Error saving data: {e}")
            db.session.rollback()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        attack_type = detect_attack(username, password)
        country, city = get_location_from_ip(request.remote_addr)

        attack_log = AttackLog(
            ip_address=request.remote_addr,
            country=country,
            city=city,
            user_agent=request.headers.get("User-Agent"),
            username=username,
            password=password,
            attack_type=attack_type,
            request_path=request.path,
            request_method=request.method
        )

        db.session.add(attack_log)
        db.session.commit()
        print(f"[+] Saved {attack_type} from {request.remote_addr}")

        return render_template("login.html", error="اسم المستخدم أو كلمة المرور غير صحيحة")

    return render_template("login.html")


@app.route('/admin')
def admin():
    return 'Admin Page!'


@app.route('/upload')
def upload():
    return 'Uploaded File!'


# ========== Dashboard Routes ==========

@app.route('/dashboard')
def dashboard():
    # جلب الـ Host الخارجي الذي جاء منه الطلب الفعلي (مثال: your-aws-ip:5000)
    host_header = request.headers.get('Host', '')
    
    # إذا لم يكن بورت 5000 جزءاً من الرابط الخارجي، يتم الحظر الفوري
    if ':5000' not in host_header:
        abort(403)
        
    return render_template('dashboard.html')


# ========== API Routes للداشبورد بعد الدمج والتحديث ==========

@app.route('/api/attacks')
def get_attacks():
    """جلب جميع الهجمات (Web + SSH) مع دعم التصفية والترتيب الزمني والتصفح الذكي"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    attack_type = request.args.get('type', None)

    # 1. جلب بيانات الويب بالكامل
    web_query = AttackLog.query
    if attack_type and attack_type != 'all' and not attack_type.startswith('SSH'):
        web_query = web_query.filter(AttackLog.attack_type == attack_type)
    web_attacks = [a.to_dict() for a in web_query.all()]

    # 2. جلب بيانات الـ SSH
    ssh_attacks = parse_cowrie_logs()
    if attack_type and attack_type != 'all':
        ssh_attacks = [a for a in ssh_attacks if attack_type.lower() in a['attack_type'].lower()]

    # إذا تم اختيار نوع هجوم ويب مخصص، نقوم بتصفير مصفوفة الـ SSH
    if attack_type and attack_type != 'all' and not attack_type.startswith('SSH') and attack_type in ["SQL Injection Attempt", "XSS Attempt", "Directory Traversal", "SSRF Attempt"]:
        ssh_attacks = []

    # 3. الدمج والترتيب تنازلياً (الأحدث أولاً)
    combined_attacks = web_attacks + ssh_attacks
    combined_attacks.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '', reverse=True)

    # 4. تطبيق نظام الـ Pagination يدوياً على البيانات المدمجة لتفادي مشاكل قاعدة البيانات
    total = len(combined_attacks)
    pages = (total + per_page - 1) // per_page
    offset = (page - 1) * per_page
    paginated_attacks = combined_attacks[offset:offset + per_page]

    return jsonify({
        'attacks': paginated_attacks,
        'total': total,
        'pages': pages,
        'current_page': page
    })


@app.route('/api/attacks/count')
def get_attacks_count():
    """عدد الهجمات الكلي للمصيدتين"""
    web_count = AttackLog.query.count()
    ssh_count = len(parse_cowrie_logs())
    return jsonify({'total_attacks': web_count + ssh_count})


@app.route('/api/attacks/today')
def get_today_attacks():
    """الهجمات التي حدثت اليوم من المصدرين"""
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    # الويب
    web_today = AttackLog.query.filter(func.date(AttackLog.timestamp) == datetime.now().date()).all()
    web_list = [a.to_dict() for a in web_today]
    
    # SSH
    ssh_list = [a for a in parse_cowrie_logs() if a['timestamp'].startswith(today_str)]
    
    combined = web_list + ssh_list
    combined.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(combined)


@app.route('/api/attacks/recent')
def get_recent_attacks():
    """أحدث الهجمات المدمجة"""
    limit = request.args.get('limit', 5, type=int)
    web_list = [a.to_dict() for a in AttackLog.query.all()]
    ssh_list = parse_cowrie_logs()
    
    combined = web_list + ssh_list
    combined.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(combined[:limit])


@app.route('/api/attacks/stats')
def get_attacks_stats():
    """الإحصائيات الشاملة للبطاقات العلوية في الواجهة"""
    web_total = AttackLog.query.count()
    ssh_attacks = parse_cowrie_logs()
    ssh_total = len(ssh_attacks)

    today_str = datetime.now().strftime('%Y-%m-%d')
    web_today = AttackLog.query.filter(func.date(AttackLog.timestamp) == datetime.now().date()).count()
    ssh_today = sum(1 for a in ssh_attacks if a['timestamp'].startswith(today_str))

    sql_count = AttackLog.query.filter(AttackLog.attack_type.contains('SQL')).count()
    xss_count = AttackLog.query.filter(AttackLog.attack_type.contains('XSS')).count()
    traversal_count = AttackLog.query.filter(AttackLog.attack_type.contains('Traversal')).count()
    
    # حساب عدد هجمات كاوري المخصصة
    ssh_brute = sum(1 for a in ssh_attacks if "Bruteforce" in a['attack_type'])

    return jsonify({
        'total': web_total + ssh_total,
        'today': web_today + ssh_today,
        'sql_injection': sql_count,
        'xss': xss_count,
        'directory_traversal': traversal_count,
        'ssh_bruteforce': ssh_brute
    })


@app.route('/api/attacks/by-type')
def get_attacks_by_type():
    """توزيع الهجمات حسب النوع لرسوم الـ Chart الرسم البياني"""
    # الويب
    web_result = db.session.query(
        AttackLog.attack_type, func.count(AttackLog.id)
    ).group_by(AttackLog.attack_type).all()
    
    stats_dict = {r[0]: r[1] for r in web_result}
    
    # SSH
    ssh_attacks = parse_cowrie_logs()
    for a in ssh_attacks:
        stats_dict[a['attack_type']] = stats_dict.get(a['attack_type'], 0) + 1

    return jsonify([{'type': k, 'count': v} for k, v in stats_dict.items()])


@app.route('/api/attacks/top-ips')
def get_top_ips():
    """أعلى العناوين المهاجمة من كلا النظامين"""
    ip_map = {}
    
    # حساب الويب
    web_logs = AttackLog.query.all()
    for l in web_logs:
        ip_map[l.ip_address] = ip_map.get(l.ip_address, 0) + 1
        
    # حساب SSH
    ssh_logs = parse_cowrie_logs()
    for l in ssh_logs:
        ip_map[l['ip_address']] = ip_map.get(l['ip_address'], 0) + 1

    sorted_ips = sorted(ip_map.items(), key=lambda x: x[1], reverse=True)[:5]
    return jsonify([{'ip': item[0], 'count': item[1]} for item in sorted_ips])


@app.route('/api/attacks/hourly')
def get_hourly_stats():
    """إحصائيات آخر 24 ساعة المدمجة"""
    hours_ago = datetime.now() - timedelta(hours=24)
    hours_data = {f"{i:02d}": 0 for i in range(24)}

    # الويب
    web_result = db.session.query(
        func.strftime('%H', AttackLog.timestamp), func.count(AttackLog.id)
    ).filter(AttackLog.timestamp >= hours_ago).group_by(func.strftime('%H', AttackLog.timestamp)).all()
    
    for r in web_result:
        if r[0]: hours_data[r[0]] += r[1]

    # SSH
    ssh_logs = parse_cowrie_logs()
    for l in ssh_logs:
        log_time = datetime.strptime(l['timestamp'], '%Y-%m-%d %H:%M:%S')
        if log_time >= hours_ago:
            hour_str = log_time.strftime('%H')
            hours_data[hour_str] += 1

    return jsonify([{'hour': h, 'count': c} for h, c in hours_data.items()])


@app.route('/api/attacks/daily')
def get_daily_stats():
    """إحصائيات آخر 7 أيام مدمجة"""
    days_ago = datetime.now() - timedelta(days=7)
    daily_map = {}

    # الويب
    web_result = db.session.query(
        func.date(AttackLog.timestamp), func.count(AttackLog.id)
    ).filter(AttackLog.timestamp >= days_ago).group_by(func.date(AttackLog.timestamp)).all()
    
    for r in web_result:
        daily_map[str(r[0])] = r[1]

    # SSH
    ssh_logs = parse_cowrie_logs()
    for l in ssh_logs:
        log_date = l['timestamp'].split(" ")[0]
        log_time = datetime.strptime(l['timestamp'], '%Y-%m-%d %H:%M:%S')
        if log_time >= days_ago:
            daily_map[log_date] = daily_map.get(log_date, 0) + 1

    return jsonify([{'date': k, 'count': v} for k, v in sorted(daily_map.items())])


@app.route('/api/attacks/search')
def search_attacks():
    """البحث الذكي المدمج في الـ IP أو اسم المستخدم أو نوع الهجوم"""
    query = request.args.get('q', '').lower()

    if not query:
        return jsonify({'attacks': [], 'count': 0})

    # بحث الويب
    web_results = AttackLog.query.filter(
        or_(
            AttackLog.ip_address.contains(query),
            AttackLog.username.contains(query),
            AttackLog.attack_type.contains(query)
        )
    ).order_by(AttackLog.timestamp.desc()).limit(10).all()
    web_list = [a.to_dict() for a in web_results]

    # بحث SSH
    ssh_logs = parse_cowrie_logs()
    ssh_list = [a for a in ssh_logs if (query in a['ip_address'].lower() or query in a['username'].lower() or query in a['attack_type'].lower())]

    combined = web_list + ssh_list
    combined.sort(key=lambda x: x['timestamp'], reverse=True)
    final_results = combined[:10]

    return jsonify({
        'attacks': final_results,
        'count': len(final_results)
    })


@app.route('/api/attacks/<string:attack_id>', methods=['DELETE'])
def delete_attack(attack_id):
    """حذف هجوم ويب (ملاحظة: كاوري ملف نصي لا يحذف من هنا مباشرة لدواعي أمنية وحماية السجلات)"""
    try:
        if attack_id.startswith('web_'):
            real_id = int(attack_id.split('_')[1])
            attack = AttackLog.query.get(real_id)
            if attack:
                db.session.delete(attack)
                db.session.commit()
                return jsonify({'success': True, 'message': 'تم حذف سجل الويب بنجاح'})
        elif attack_id.startswith('ssh_'):
            return jsonify({'success': False, 'message': 'سجلات SSH محمية (قراءة فقط) لتأمين الأدلة الجنائية الرقمية'}), 403
        
        return jsonify({'success': False, 'message': 'الهجوم غير موجود'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/attacks/clear', methods=['POST'])
def clear_all_attacks():
    """تفريغ سجلات قاعدة البيانات للويب"""
    try:
        num_deleted = db.session.query(AttackLog).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': f'تم مسح {num_deleted} سجل من الويب بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/export/csv')
def export_csv():
    """تصدير السجل الكامل والمدمج (Web + SSH) إلى ملف CSV للتحليل الخارجي"""
    web_attacks = AttackLog.query.order_by(AttackLog.timestamp.desc()).all()
    ssh_attacks = parse_cowrie_logs()

    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['ID', 'Source', 'Time', 'IP Address', 'Country', 'City', 'Attack Type', 'Username', 'Password', 'Path/Payload', 'Method/Protocol', 'User Agent'])

    # كتابة الـ Web
    for a in web_attacks:
        writer.writerow([f"web_{a.id}", "Web", a.timestamp.strftime('%Y-%m-%d %H:%M:%S'), a.ip_address, a.country, a.city, a.attack_type, a.username, a.password, a.request_path, a.request_method, a.user_agent])

    # كتابة الـ SSH
    for a in ssh_attacks:
        writer.writerow([a['id'], "SSH (Cowrie)", a['timestamp'], a['ip_address'], a['country'], a['city'], a['attack_type'], a['username'], a['password'], a['request_path'], a['request_method'], a['user_agent']])

    output.seek(0)

    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=combined_honeypot_attacks.csv'
    }


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)