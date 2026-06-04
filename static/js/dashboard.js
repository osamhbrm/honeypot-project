// تطبيق Dashboard (النسخة الأصلية المدمجة مع Cowrie SSH والمراقبة الحية)
const dashboard = {
    // الإعدادات
    config: {
        apiBase: '/api',
        refreshInterval: 5000, // التحديث التلقائي المباشر كل 5 ثوانٍ للبيانات الحية
        itemsPerPage: 10,
        currentPage: 1,
        liveMode: true,
        charts: {}
    },

    // الحالة
    state: {
        attacks: [],
        stats: {},
        liveAttacks: [],
        isLoading: false
    },

    // التهيئة
    init: function() {
        console.log('🚀 Dashboard initialized');

        // تهيئة الأحداث
        this.initEvents();

        // تحميل البيانات الأولية
        this.loadAllData();

        // بدء التحديثات التلقائية (المراقبة المباشرة)
        this.startAutoRefresh();

        // تحديث الوقت
        this.updateTime();
        setInterval(() => this.updateTime(), 1000);
    },

    // تهيئة الأحداث
    initEvents: function() {
        // تبديل المباشر
        const liveToggle = document.getElementById('liveToggle');
        if (liveToggle) {
            liveToggle.addEventListener('change', (e) => {
                this.config.liveMode = e.target.checked;
                if (this.config.liveMode) {
                    this.startAutoRefresh();
                    this.showAlert('تم تفعيل المراقبة الحية المباشرة', 'success');
                } else {
                    this.stopAutoRefresh();
                    this.showAlert('تم إيقاف المراقبة المباشرة مؤقتاً', 'warning');
                }
            });
        }
    },

    // تحميل جميع البيانات
    async loadAllData() {
        try {
            await Promise.all([
                this.loadStats(),
                this.loadRecentAttacks(),
                this.loadCharts(),
                this.loadTopIPs()
            ]);

            this.updateLastUpdateTime();
            const footerStatus = document.getElementById('footerStatus');
            if (footerStatus) footerStatus.innerText = "الرصد مستقر ومباشر...";
        } catch (error) {
            console.error('Error loading data:', error);
            this.showAlert('خطأ في تحميل البيانات المباشرة', 'danger');
        }
    },

    // تحميل الإحصائيات الشاملة (Web + SSH)
    async loadStats() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/stats`);
            this.state.stats = response.data;

            // تحديث الواجهة
            this.updateStatsUI();

        } catch (error) {
            console.error('Error loading stats:', error);
        }
    },

    // تحميل الهجمات الأخيرة (تعرض في واجهة نظرة عامة)
    async loadRecentAttacks() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/recent?limit=5`);
            this.state.attacks = response.data;

            // تحديث جدول الهجمات الأخيرة
            this.updateRecentAttacksTable();

        } catch (error) {
            console.error('Error loading recent attacks:', error);
        }
    },

    // تحميل جميع الهجمات (للقسم الكامل مع التصفح الذكي)
    async loadAllAttacksTable(filterType = 'all') {
        try {
            let url = `${this.config.apiBase}/attacks?page=${this.config.currentPage}&per_page=${this.config.itemsPerPage}`;
            if (filterType !== 'all') {
                url += `&type=${encodeURIComponent(filterType)}`;
            }
            
            const response = await axios.get(url);
            const data = response.data;

            // تحديث جدول الهجمات الكامل
            this.updateAllAttacksTable(data.attacks);

            // تحديث الترقيم (Pagination)
            this.updatePagination(data.total, data.pages);

        } catch (error) {
            console.error('Error loading all attacks:', error);
        }
    },

    // تحميل الرسوم البيانية
    async loadCharts() {
        try {
            const [hourlyResponse, typeResponse, weeklyResponse] = await Promise.all([
                axios.get(`${this.config.apiBase}/attacks/hourly`),
                axios.get(`${this.config.apiBase}/attacks/by-type`),
                axios.get(`${this.config.apiBase}/attacks/daily`)
            ]);

            // تحديث الرسوم البيانية حياً
            this.updateHourlyChart(hourlyResponse.data);
            this.updateTypeChart(typeResponse.data);
            this.updateWeeklyChart(weeklyResponse.data);

        } catch (error) {
            console.error('Error loading charts:', error);
        }
    },

    // تحميل أكثر IPs نشاطاً من المصيدتين
    async loadTopIPs() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/top-ips`);
            this.updateTopIPsList(response.data);
        } catch (error) {
            console.error('Error loading top IPs:', error);
        }
    },

    // تحديث واجهة الإحصائيات والبطاقات العلوية
    updateStatsUI() {
        const stats = this.state.stats;

        // تحديث الأرقام الرئيسية
        this.updateElement('totalAttacks', stats.total || 0);
        this.updateElement('todayAttacks', stats.today || 0);
        this.updateElement('sqlAttacks', stats.sql_injection || 0);
        this.updateElement('xssAttacks', stats.xss || 0);

        // تحديث البادجات في الشريط الجانبي
        this.updateElement('totalAttacksBadge', stats.total || 0);
        this.updateElement('todayAttacksBadge', stats.today || 0);

        // تحديث الإحصائيات مفصلة في تبويب الإحصائيات
        this.updateDetailedStats();
    },

    // تحديث جدول الهجمات الأخيرة (نظرة عامة) - يدعم وسم الـ SSH والـ Web الملون
    updateRecentAttacksTable() {
        const tableBody = document.getElementById('recentAttacksTable');
        if (!tableBody) return;

        if (this.state.attacks.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted">
                        <i class="fas fa-inbox me-2"></i>لا توجد هجمات مسجلة حالياً
                    </td>
                </tr>`;
            return;
        }

        tableBody.innerHTML = this.state.attacks.map(attack => {
            const badgeSrc = attack.source === 'ssh' 
                ? `<span class="badge bg-danger text-white ms-1"><i class="fas fa-terminal text-sm"></i> SSH</span>` 
                : `<span class="badge bg-primary text-white ms-1"><i class="fas fa-globe text-sm"></i> Web</span>`;
            
            return `
            <tr>
                <td>${this.formatTime(attack.timestamp)}</td>
                <td><code>${attack.ip_address}</code> ${badgeSrc}</td>
                <td>
                    <span class="attack-badge ${this.getAttackClass(attack.attack_type)}">
                        ${attack.attack_type}
                    </span>
                </td>
                <td>${attack.username || 'N/A'}</td>
                <td class="text-truncate" style="max-width: 200px;" title="${attack.request_path}"><small>${attack.request_path}</small></td>
            </tr>`;
        }).join('');
    },

    // تحديث جدول الهجمات الكامل (سجل الهجمات)
    updateAllAttacksTable(attacks) {
        const tableBody = document.getElementById('allAttacksTable');
        if (!tableBody) return;

        if (attacks.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center text-muted">
                        <i class="fas fa-inbox fa-2x mb-3 d-block"></i>
                        <h5>لا توجد هجمات مطابقة للمواصفات</h5>
                    </td>
                </tr>`;
            return;
        }

        const startIndex = (this.config.currentPage - 1) * this.config.itemsPerPage;

        tableBody.innerHTML = attacks.map((attack, index) => {
            const badgeSrc = attack.source === 'ssh' 
                ? `<span class="badge bg-danger text-white"><i class="fas fa-terminal"></i> SSH</span>` 
                : `<span class="badge bg-primary text-white"><i class="fas fa-globe"></i> Web</span>`;

            return `
            <tr>
                <td>${startIndex + index + 1}</td>
                <td>${this.formatTime(attack.timestamp)}</td>
                <td>
                    <code class="ip-address" style="cursor:pointer;" onclick="dashboard.copyToClipboard('${attack.ip_address}')">
                        ${attack.ip_address} <i class="fas fa-copy ms-1 text-muted small"></i>
                    </code>
                    <div class="mt-1">${badgeSrc} <span class="text-muted small">${attack.country || ''}</span></div>
                </td>
                <td>
                    <span class="attack-badge ${this.getAttackClass(attack.attack_type)}">
                        ${attack.attack_type}
                    </span>
                </td>
                <td><strong class="text-success">${attack.username || 'N/A'}</strong></td>
                <td>
                    <span class="badge bg-light text-dark font-mono">
                        ${attack.password || 'N/A'}
                    </span>
                </td>
                <td class="text-wrap small" style="max-width: 220px;"><code>${attack.request_path}</code></td>
                <td>
                    <span class="badge bg-${attack.request_method === 'GET' ? 'info' : (attack.request_method === 'SSH' ? 'dark' : 'success')}">
                        ${attack.request_method}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="dashboard.deleteAttack('${attack.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>`;
        }).join('');
    },

    // تحديث الرسم البياني للساعات حياً
    updateHourlyChart(data) {
        const ctx = document.getElementById('hourlyChart');
        if (!ctx) return;

        if (this.config.charts.hourly) {
            this.config.charts.hourly.destroy();
        }

        const labels = data.map(item => `${item.hour}:00`);
        const counts = data.map(item => item.count);

        this.config.charts.hourly = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'عدد التهديدات المكتشفة',
                    data: counts,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { rtl: true, labels: { font: { family: 'Cairo, sans-serif' } } }
                }
            }
        });
    },

    // تحديث رسم توزيع الأنواع الدائري
    updateTypeChart(data) {
        const ctx = document.getElementById('typeChart');
        if (!ctx) return;

        if (this.config.charts.type) {
            this.config.charts.type.destroy();
        }

        const labels = data.map(item => item.type);
        const counts = data.map(item => item.count);

        this.config.charts.type = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: [
                        '#FF6B6B', '#4ECDC4', '#FFD166', '#06D6A0',
                        '#118AB2', '#6f42c1', '#073B4C'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', rtl: true } }
            }
        });
    },

    // تحديث رسم الأسبوع البياني للمصيدتين
    updateWeeklyChart(data) {
        const ctx = document.getElementById('weeklyChart');
        if (!ctx) return;

        if (this.config.charts.weekly) {
            this.config.charts.weekly.destroy();
        }

        const labels = data.map(item => item.date);
        const counts = data.map(item => item.count);

        this.config.charts.weekly = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'إجمالي المحاولات اليومية والـ SSH',
                    data: counts,
                    backgroundColor: '#0d6efd'
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { rtl: true } }
            }
        });
    },

    // تحديث قائمة أعلى 5 مهاجمين نشطين
    updateTopIPsList(data) {
        const container = document.getElementById('topIPsList');
        if (!container) return;

        if (data.length === 0) {
            container.innerHTML = '<p class="text-muted p-3 text-center">لا توجد بيانات كافية</p>';
            return;
        }

        container.innerHTML = data.map((item, index) => `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border-bottom">
                <div>
                    <span class="badge bg-secondary me-2">${index + 1}</span>
                    <code>${item.ip}</code>
                </div>
                <div>
                    <span class="badge bg-danger rounded-pill">${item.count} محاولة</span>
                </div>
            </div>
        `).join('');
    },

    // تحديث الإحصائيات المفصلة في شاشة الإحصائيات حياً
    updateDetailedStats() {
        const tableBody = document.getElementById('detailedStatsTable');
        if (!tableBody) return;

        axios.get(`${this.config.apiBase}/attacks/by-type`).then(res => {
            const data = res.data;
            const total = data.reduce((sum, item) => sum + item.count, 0);

            tableBody.innerHTML = data.map(item => `
                <tr>
                    <td><strong>${item.type}</strong></td>
                    <td><span class="badge bg-dark">${item.count}</span></td>
                    <td>${total > 0 ? ((item.count / total) * 100).toFixed(1) : 0}%</td>
                    <td><span class="text-success small">نشط حياً <i class="fas fa-circle-notch fa-spin ms-1"></i></span></td>
                </tr>
            `).join('');
        });
    },

    // تحديث الترقيم الديناميكي للجداول
    updatePagination(total, pages) {
        const container = document.getElementById('pageNumbers');
        if (!container) return;

        let html = '';
        const maxVisible = 5;
        let startPage = Math.max(1, this.config.currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(pages, startPage + maxVisible - 1);

        if (endPage - startPage + 1 < maxVisible) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }

        for (let i = startPage; i <= endPage; i++) {
            if(i > 0) {
                html += `
                    <button class="page-number ${i === this.config.currentPage ? 'active' : ''}"
                            onclick="dashboard.goToPage(${i})">
                        ${i}
                    </button>
                `;
            }
        }

        container.innerHTML = html || '<button class="page-number active">1</button>';
    },

    // البحث الفوري في الهجمات
    async searchAttacks() {
        const searchInput = document.getElementById('searchInput');
        const query = searchInput.value.trim();

        if (!query) {
            this.loadAllAttacksTable('all');
            const pag = document.querySelector('.pagination');
            if (pag) pag.style.display = 'flex';
            return;
        }

        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/search?q=${encodeURIComponent(query)}`);
            this.updateAllAttacksTable(response.data.attacks);

            const pag = document.querySelector('.pagination');
            if (pag) pag.style.display = 'none';

        } catch (error) {
            console.error('Error searching attacks:', error);
        }
    },

    // تصفية الهجمات حسب النوع من خلال الـ Dropdown الأصلي الخاص بك
    async filterAttacks() {
        const typeFilter = document.getElementById('typeFilter');
        const type = typeFilter.value;
        this.config.currentPage = 1;
        
        if (type === 'all') {
            this.loadAllAttacksTable('all');
            const pag = document.querySelector('.pagination');
            if (pag) pag.style.display = 'flex';
        } else {
            this.loadAllAttacksTable(type);
            const pag = document.querySelector('.pagination');
            if (pag) pag.style.display = 'none';
        }
    },

    goToPage(page) {
        this.config.currentPage = page;
        const typeFilter = document.getElementById('typeFilter');
        this.loadAllAttacksTable(typeFilter ? typeFilter.value : 'all');
    },

    prevPage() {
        if (this.config.currentPage > 1) {
            this.goToPage(this.config.currentPage - 1);
        }
    },

    nextPage() {
        this.goToPage(this.config.currentPage + 1);
    },

    // حذف هجوم مع مراعاة حماية أدلة كاوري الجنائية
    async deleteAttack(id) {
        if (!confirm('هل أنت متأكد من حذف هذا السجل الجنائي؟')) return;

        try {
            const response = await axios.delete(`${this.config.apiBase}/attacks/${id}`);
            this.showAlert(response.data.message, 'success');
            this.loadAllData();
            
            const typeFilter = document.getElementById('typeFilter');
            this.loadAllAttacksTable(typeFilter ? typeFilter.value : 'all');
        } catch (error) {
            if (error.response && error.response.status === 403) {
                this.showAlert('⚠️ لا يمكن حذف سجلات SSH (Cowrie) حمايةً للأدلة الجنائية للأجهزة الرقمية.', 'danger');
            } else {
                this.showAlert('خطأ في إتمام عملية الحذف للوق المختار', 'danger');
            }
        }
    },

    // مسح لوقات الويب وتصفيرها
    async clearAllAttacks() {
        if (!confirm('⚠️ تحذير أمني: سيتم تفريغ مسارات هجمات الويب بالكامل ومسحها من الـ Database. هل أنت متأكد؟')) return;

        try {
            const response = await axios.post(`${this.config.apiBase}/attacks/clear`);
            this.showAlert(response.data.message, 'success');
            this.loadAllData();
            this.loadAllAttacksTable('all');
        } catch (error) {
            console.error('Error clearing attacks:', error);
            this.showAlert('خطأ أثناء عملية مسح السجلات', 'danger');
        }
    },

    // التنقل الذكي بين الأقسام الـ 5 القديمة كما هي في شريطك الجانبي
    showSection(sectionId) {
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });

        document.querySelectorAll('.sidebar-menu .menu-btn').forEach(btn => {
            btn.classList.remove('active');
        });

        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('active');
        }

        // تفعيل الخيار المقابل هندسياً في القائمة الجانبية الأصلية
        const buttons = document.querySelectorAll('.sidebar-menu .menu-btn');
        buttons.forEach(btn => {
            if (btn.getAttribute('onclick').includes(sectionId)) {
                btn.classList.add('active');
            }
        });

        // تشغيل التحميل المخصص للقسم المختار فوراُ
        if (sectionId === 'attacks') {
            this.config.currentPage = 1;
            const typeFilter = document.getElementById('typeFilter');
            if(typeFilter) typeFilter.value = 'all';
            this.loadAllAttacksTable('all');
        } else if (sectionId === 'statistics') {
            this.loadTopIPs();
            this.updateDetailedStats();
        } else if (sectionId === 'realtime') {
            this.updateLiveData();
        }
    },

    // مسح قاعدة البيانات من التبويب الخامس (Settings)
    async clearDatabase() {
        await this.clearAllAttacks();
    },

    // حفظ إعدادات التنبيهات محلياً
    saveSettings() {
        const settings = {
            alertSQL: document.getElementById('alertSQL').checked,
            alertXSS: document.getElementById('alertXSS').checked,
            alertTraversal: document.getElementById('alertTraversal').checked
        };

        localStorage.setItem('honeypotSettings', JSON.stringify(settings));
        this.showAlert('تم حفظ الإعدادات الأمنية للتنبيهات بنجاح', 'success');
    },

    // تحميل التنبيهات المحفوظة مسبقاً للواجهة
    loadSettings() {
        const saved = localStorage.getItem('honeypotSettings');
        if (saved) {
            const settings = JSON.parse(saved);
            if (document.getElementById('alertSQL')) document.getElementById('alertSQL').checked = settings.alertSQL;
            if (document.getElementById('alertXSS')) document.getElementById('alertXSS').checked = settings.alertXSS;
            if (document.getElementById('alertTraversal')) document.getElementById('alertTraversal').checked = settings.alertTraversal;
        }
    },

    // بدء المراقبة التلقائية الحية (Live Monitoring System)
    startAutoRefresh() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);

        this.refreshInterval = setInterval(() => {
            const activeSec = document.querySelector('.dashboard-section.active');
            if (!activeSec) return;
            const activeSection = activeSec.id;

            // تحديث البطاقات والشارات العلوية دائماً في الخلفية
            this.loadStats();

            switch(activeSection) {
                case 'overview':
                    this.loadRecentAttacks();
                    break;
                case 'realtime':
                    this.updateLiveData();
                    break;
            }

            this.updateLastUpdateTime();
        }, this.config.refreshInterval);
    },

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    },

    // تحديث تبويب الـ Realtime (القسم المباشر) ليعرض اللوق التفاعلي للـ Web والـ SSH معاً
    async updateLiveData() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/recent?limit=10`);
            this.state.liveAttacks = response.data;
            this.updateLiveFeed();

            // تحديث العدادات الحية في تبويب "مباشر" الأصلي
            this.updateElement('liveAttacksNow', this.state.liveAttacks.length);
            this.updateElement('liveIPs', [...new Set(this.state.liveAttacks.map(a => a.ip_address))].length);
            this.updateElement('liveRequests', Math.floor(this.state.liveAttacks.length * 1.5));
            this.updateElement('liveThreats', this.state.liveAttacks.filter(a => a.attack_type !== 'Normal Attempt').length);

        } catch (error) {
            console.error('Error updating live data:', error);
        }
    },

    // تعبئة الـ Feed المباشر داخل واجهة الـ Realtime
    updateLiveFeed() {
        const feed = document.getElementById('liveFeed');
        if (!feed) return;

        if (this.state.liveAttacks.length === 0) {
            feed.innerHTML = `
                <div class="text-center p-4 text-muted">
                    <i class="fas fa-comment-slash fa-2x mb-3"></i>
                    <p>لا توجد هجمات ملتقطة حالياً حية في قنوات الرصد</p>
                </div>`;
            return;
        }

        feed.innerHTML = this.state.liveAttacks.map(attack => {
            const isSSH = attack.source === 'ssh';
            const badgeColor = isSSH ? 'bg-danger' : 'bg-primary';
            const icon = isSSH ? 'fa-terminal' : 'fa-globe';

            return `
            <div class="live-attack p-3 mb-2 border rounded bg-white shadow-sm" style="border-right: 4px solid ${isSSH ? '#dc3545' : '#0d6efd'} !important;">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <strong class="font-mono text-dark">${attack.ip_address}</strong>
                        <span class="badge ${badgeColor} ms-2">
                            <i class="fas ${icon} me-1"></i> ${attack.attack_type}
                        </span>
                    </div>
                    <small class="text-muted"><i class="fas fa-clock me-1"></i> ${this.formatTime(attack.timestamp)}</small>
                </div>
                <div class="mt-2 text-secondary small">
                    <span><strong>المستخدم المستهدف:</strong> ${attack.username || 'N/A'}</span> &bull; 
                    <span><strong>الحمولة / المسار:</strong> <code class="text-dark">${attack.request_path}</code></span>
                </div>
            </div>`;
        }).join('');
    },

    updateTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('ar-SA');
        this.updateElement('currentTime', timeString);
    },

    updateLastUpdateTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit' });
        this.updateElement('lastUpdateTime', timeString);
    },

    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showAlert(`تم نسخ عنوان IP [${text}] بنجاح`, 'success');
        }).catch(() => {
            this.showAlert('فشل النسخ التلقائي للحافظة', 'danger');
        });
    },

    refreshAll() {
        const footerStatus = document.getElementById('footerStatus');
        if (footerStatus) footerStatus.innerText = "جاري جلب القنوات والبيانات فورياً...";
        this.loadAllData();
        const activeSec = document.querySelector('.dashboard-section.active');
        if (activeSec) {
            this.showSection(activeSec.id);
        }
    },

    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    },

    showAlert(message, type = 'info') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show shadow-sm position-fixed top-0 start-50 translate-middle-x mt-3`;
        alert.style.zIndex = '9999';
        alert.innerHTML = `
            <i class="fas fa-info-circle me-2"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        const oldAlerts = document.querySelectorAll('.alert');
        oldAlerts.forEach(a => a.remove());

        document.body.appendChild(alert);

        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 3500);
    },

    formatTime(dateString) {
        if(!dateString) return '--:--';
        try {
            const date = new Date(dateString);
            return date.toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch {
            return dateString;
        }
    },

    getAttackClass(attackType) {
        if (attackType.includes('SQL')) return 'badge-sql';
        if (attackType.includes('XSS')) return 'badge-xss';
        if (attackType.includes('Traversal')) return 'badge-traversal';
        if (attackType.includes('SSH')) return 'bg-danger text-white';
        return 'badge-normal';
    }
};

// تهيئة Dashboard عند تحميل الصفحة الكاملة
document.addEventListener('DOMContentLoaded', function() {
    dashboard.init();
    dashboard.loadSettings();
});