from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import geocoder
import random

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///honeypot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


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

    # تعريف to_dict هنا (قبل init_database)
    def to_dict(self):
        """تحويل السجل إلى قاموس"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'country': self.country,
            'city': self.city,
            'user_agent': self.user_agent,
            'username': self.username,
            'password': self.password,
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


def is_directory_traversal(input_data):
    patterns = ["../", "..\\", "%2e%2e", "%2f", "/etc/passwd", "windows/system32"]
    input_data = input_data.lower()
    for p in patterns:
        if p in input_data:
            return True
    return False


def detect_attack(username, password):
    payload = f"{username}{password}".lower()

    # اكتشاف SQL Injection بشكل أدق
    sql_patterns = ["'", "--", ";", "or 1=1", "union select", "insert into", "drop table", "update", "delete"]
    for pattern in sql_patterns:
        if pattern in payload:
            return "SQL Injection Attempt"

    # اكتشاف XSS
    xss_patterns = ["<script>", "javascript:", "onload=", "onerror=", "onclick=", "alert("]
    for pattern in xss_patterns:
        if pattern in payload:
            return "XSS Attempt"

    # اكتشاف Directory Traversal
    if is_directory_traversal(payload):
        return "Directory Traversal"

    # اكتشاف SSRF
    ssrf_patterns = ["http://", "https://", "169.254.169.254", "127.0.0.1", "localhost", "file://"]
    for pattern in ssrf_patterns:
        if pattern in payload:
            return "SSRF Attempt"

    # اكتشاف CRLF Injection
    crlf_patterns = ["%0d%0a", "%0d", "%0a", "\r", "\n"]
    for pattern in crlf_patterns:
        if pattern in payload:
            return "CRLF Injection Attempt"

    # اكتشاف Default Credentials
    default_users = ["admin", "root", "administrator", "guest"]
    default_passwords = ["admin", "root", "password", "123456", "12345678", "toor"]
    if username.lower() in default_users and password.lower() in default_passwords:
        return "Default Credentials Attempt"

    return "Normal Attempt"


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.before_request
def detect_traversal_globally():
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
    """الصفحة الرئيسية للداشبورد"""
    return render_template('dashboard.html')


# ========== API Routes للداشبورد ==========

@app.route('/api/attacks')
def get_attacks():
    """جلب جميع الهجمات مع إمكانية التصفية"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)  # تغيير إلى 10 للمزيد من التحكم
    attack_type = request.args.get('type', None)

    query = AttackLog.query

    if attack_type and attack_type != 'all':
        query = query.filter(AttackLog.attack_type == attack_type)

    # الحصول على البيانات بدون paginate (إذا كان هناك مشكلة مع paginate)
    if hasattr(query, 'paginate'):
        attacks = query.order_by(AttackLog.timestamp.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)
        attacks_list = attacks.items
        total = attacks.total
        pages = attacks.pages
    else:
        # حل بديل بدون paginate
        offset = (page - 1) * per_page
        attacks_list = query.order_by(AttackLog.timestamp.desc()) \
            .offset(offset).limit(per_page).all()
        total = query.count()
        pages = (total + per_page - 1) // per_page

    return jsonify({
        'attacks': [attack.to_dict() for attack in attacks_list],
        'total': total,
        'pages': pages,
        'current_page': page
    })


@app.route('/api/attacks/count')
def get_attacks_count():
    """عدد الهجمات الكلي"""
    count = AttackLog.query.count()
    return jsonify({'total_attacks': count})


@app.route('/api/attacks/today')
def get_today_attacks():
    """الهجمات اليوم"""
    today = datetime.now().date()
    attacks = AttackLog.query.filter(
        func.date(AttackLog.timestamp) == today
    ).order_by(AttackLog.timestamp.desc()).all()

    return jsonify([attack.to_dict() for attack in attacks])


@app.route('/api/attacks/recent')
def get_recent_attacks():
    """أحدث الهجمات"""
    limit = request.args.get('limit', 5, type=int)
    attacks = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(limit).all()
    return jsonify([attack.to_dict() for attack in attacks])


@app.route('/api/attacks/stats')
def get_attacks_stats():
    """إحصائيات الهجمات"""
    total = AttackLog.query.count()

    today = datetime.now().date()
    today_count = AttackLog.query.filter(
        func.date(AttackLog.timestamp) == today
    ).count()

    sql_count = AttackLog.query.filter(
        AttackLog.attack_type.contains('SQL')
    ).count()

    xss_count = AttackLog.query.filter(
        AttackLog.attack_type.contains('XSS')
    ).count()

    traversal_count = AttackLog.query.filter(
        AttackLog.attack_type.contains('Traversal')
    ).count()

    return jsonify({
        'total': total,
        'today': today_count,
        'sql_injection': sql_count,
        'xss': xss_count,
        'directory_traversal': traversal_count
    })


@app.route('/api/attacks/by-type')
def get_attacks_by_type():
    """عدد الهجمات حسب النوع"""
    result = db.session.query(
        AttackLog.attack_type,
        func.count(AttackLog.id).label('count')
    ).group_by(AttackLog.attack_type).all()

    return jsonify([{'type': r[0], 'count': r[1]} for r in result])


@app.route('/api/attacks/top-ips')
def get_top_ips():
    """أكثر عناوين IP نشاطاً"""
    result = db.session.query(
        AttackLog.ip_address,
        func.count(AttackLog.id).label('count')
    ).group_by(AttackLog.ip_address).order_by(func.count(AttackLog.id).desc()).limit(5).all()

    return jsonify([{'ip': r[0], 'count': r[1]} for r in result])


@app.route('/api/attacks/hourly')
def get_hourly_stats():
    """إحصائيات الهجمات حسب الساعة (آخر 24 ساعة)"""
    hours_ago = datetime.now() - timedelta(hours=24)

    result = db.session.query(
        func.strftime('%H', AttackLog.timestamp).label('hour'),
        func.count(AttackLog.id).label('count')
    ).filter(AttackLog.timestamp >= hours_ago) \
        .group_by(func.strftime('%H', AttackLog.timestamp)) \
        .order_by('hour').all()

    # ملء الساعات الفارغة
    hours_data = {f"{i:02d}": 0 for i in range(24)}
    for r in result:
        if r[0]:
            hours_data[r[0]] = r[1]

    return jsonify([{'hour': hour, 'count': count} for hour, count in hours_data.items()])


@app.route('/api/attacks/daily')
def get_daily_stats():
    """إحصائيات الهجمات اليومية (آخر 7 أيام)"""
    days_ago = datetime.now() - timedelta(days=7)

    result = db.session.query(
        func.date(AttackLog.timestamp).label('date'),
        func.count(AttackLog.id).label('count')
    ).filter(AttackLog.timestamp >= days_ago) \
        .group_by(func.date(AttackLog.timestamp)) \
        .order_by('date').all()

    return jsonify([{'date': str(r[0]), 'count': r[1]} for r in result])


@app.route('/api/attacks/search')
def search_attacks():
    """بحث في الهجمات"""
    query = request.args.get('q', '')

    if not query:
        return jsonify({'attacks': [], 'count': 0})

    results = AttackLog.query.filter(
        or_(
            AttackLog.ip_address.contains(query),
            AttackLog.username.contains(query),
            AttackLog.attack_type.contains(query)
        )
    ).order_by(AttackLog.timestamp.desc()).limit(10).all()

    return jsonify({
        'attacks': [attack.to_dict() for attack in results],
        'count': len(results)
    })


@app.route('/api/attacks/<int:attack_id>', methods=['DELETE'])
def delete_attack(attack_id):
    """حذف هجوم معين"""
    try:
        attack = AttackLog.query.get(attack_id)
        if attack:
            db.session.delete(attack)
            db.session.commit()
            return jsonify({'success': True, 'message': 'تم الحذف بنجاح'})
        else:
            return jsonify({'success': False, 'message': 'الهجوم غير موجود'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/attacks/clear', methods=['POST'])
def clear_all_attacks():
    """مسح جميع الهجمات"""
    try:
        num_deleted = db.session.query(AttackLog).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': f'تم مسح {num_deleted} سجل'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/export/csv')
def export_csv():
    """تصدير البيانات كملف CSV"""
    attacks = AttackLog.query.order_by(AttackLog.timestamp.desc()).all()

    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # كتابة العناوين
    writer.writerow(['ID', 'Time', 'IP Address', 'Country', 'City', 'Attack Type', 'Username', 'Password', 'Path', 'Method', 'User Agent'])

    # كتابة البيانات
    for attack in attacks:
        writer.writerow([
            attack.id,
            attack.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            attack.ip_address,
            attack.country or 'Unknown',
            attack.city or 'Unknown',
            attack.attack_type,
            attack.username or '',
            attack.password or '',
            attack.request_path,
            attack.request_method,
            attack.user_agent or ''
        ])

    output.seek(0)

    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=honeypot_attacks.csv'
    }


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)