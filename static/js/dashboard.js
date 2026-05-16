// تطبيق Dashboard
const dashboard = {
    // الإعدادات
    config: {
        apiBase: '/api',
        refreshInterval: 5000,
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

        // بدء التحديثات التلقائية
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
                } else {
                    this.stopAutoRefresh();
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
        } catch (error) {
            console.error('Error loading data:', error);
            this.showAlert('خطأ في تحميل البيانات', 'danger');
        }
    },

    // تحميل الإحصائيات
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

    // تحميل الهجمات الأخيرة
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

    // تحميل جميع الهجمات (للقسم الكامل)
    async loadAllAttacksTable() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks?page=${this.config.currentPage}&per_page=${this.config.itemsPerPage}`);
            const data = response.data;

            // تحديث جدول الهجمات الكامل
            this.updateAllAttacksTable(data.attacks);

            // تحديث الترقيم
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

            // تحديث الرسوم البيانية
            this.updateHourlyChart(hourlyResponse.data);
            this.updateTypeChart(typeResponse.data);
            this.updateWeeklyChart(weeklyResponse.data);

        } catch (error) {
            console.error('Error loading charts:', error);
        }
    },

    // تحميل أكثر IPs نشاطاً
    async loadTopIPs() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/top-ips`);
            this.updateTopIPsList(response.data);
        } catch (error) {
            console.error('Error loading top IPs:', error);
        }
    },

    // تحديث واجهة الإحصائيات
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

        // تحديث الإحصائيات المفصلة
        this.updateDetailedStats();
    },

    // تحديث جدول الهجمات الأخيرة
    updateRecentAttacksTable() {
        const tableBody = document.getElementById('recentAttacksTable');
        if (!tableBody) return;

        if (this.state.attacks.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted">
                        <i class="fas fa-inbox me-2"></i>
                        لا توجد هجمات مسجلة
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = this.state.attacks.map(attack => `
            <tr>
                <td>${this.formatTime(attack.timestamp)}</td>
                <td><code>${attack.ip_address}</code></td>
                <td>
                    <span class="attack-badge ${this.getAttackClass(attack.attack_type)}">
                        ${attack.attack_type}
                    </span>
                </td>
                <td>${attack.username || 'N/A'}</td>
                <td><small>${attack.request_path}</small></td>
            </tr>
        `).join('');
    },

    // تحديث جدول الهجمات الكامل
    updateAllAttacksTable(attacks) {
        const tableBody = document.getElementById('allAttacksTable');
        if (!tableBody) return;

        if (attacks.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center text-muted">
                        <i class="fas fa-inbox fa-2x mb-3 d-block"></i>
                        <h5>لا توجد هجمات مسجلة</h5>
                        <p>لم يتم تسجيل أي هجمات بعد</p>
                    </td>
                </tr>
            `;
            return;
        }

        const startIndex = (this.config.currentPage - 1) * this.config.itemsPerPage;

        tableBody.innerHTML = attacks.map((attack, index) => `
            <tr>
                <td>${startIndex + index + 1}</td>
                <td>${this.formatTime(attack.timestamp)}</td>
                <td>
                    <code class="ip-address" onclick="dashboard.copyToClipboard('${attack.ip_address}')">
                        ${attack.ip_address}
                        <i class="fas fa-copy ms-2"></i>
                    </code>
                </td>
                <td>${attack.country || 'غير معروف'}</td>
                <td>${attack.city || 'غير معروف'}</td>
                <td>
                    <span class="attack-badge ${this.getAttackClass(attack.attack_type)}">
                        ${attack.attack_type}
                    </span>
                </td>
                <td>${attack.username || 'N/A'}</td>
                <td>
                    <span class="password-field">
                        ${attack.password ? '•'.repeat(Math.min(attack.password.length, 8)) : 'N/A'}
                    </span>
                </td>
                <td><small>${attack.request_path}</small></td>
                <td>
                    <span class="badge bg-${attack.request_method === 'GET' ? 'info' : 'success'}">
                        ${attack.request_method}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="dashboard.deleteAttack(${attack.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    },

    // تحديث الرسم البياني للساعات
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
                    label: 'عدد الهجمات',
                    data: counts,
                    borderColor: '#4CAF50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        rtl: true,
                        labels: {
                            font: {
                                family: 'Cairo, sans-serif'
                            }
                        }
                    }
                }
            }
        });
    },

    // تحديث رسم توزيع الأنواع
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
                        '#118AB2', '#EF476F', '#073B4C'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        rtl: true
                    }
                }
            }
        });
    },

    // تحديث رسم الأسبوع
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
                    label: 'عدد الهجمات',
                    data: counts,
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        rtl: true
                    }
                }
            }
        });
    },

    // تحديث قائمة أكثر IPs نشاطاً
    updateTopIPsList(data) {
        const container = document.getElementById('topIPsList');
        if (!container) return;

        if (data.length === 0) {
            container.innerHTML = '<p class="text-muted">لا توجد بيانات</p>';
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border-bottom">
                <div>
                    <code>${item.ip}</code>
                </div>
                <div>
                    <span class="badge bg-primary">${item.count}</span>
                </div>
            </div>
        `).join('');
    },

    // تحديث الإحصائيات المفصلة
    updateDetailedStats() {
        const tableBody = document.getElementById('detailedStatsTable');
        if (!tableBody) return;

        // هذه بيانات تجريبية، يمكنك استبدالها ببيانات حقيقية
        const detailedData = [
            { type: 'SQL Injection Attempt', count: this.state.stats.sql_injection || 0 },
            { type: 'XSS Attempt', count: this.state.stats.xss || 0 },
            { type: 'Directory Traversal', count: this.state.stats.directory_traversal || 0 },
            { type: 'Normal Attempt', count: (this.state.stats.today || 0) -
                (this.state.stats.sql_injection || 0) -
                (this.state.stats.xss || 0) -
                (this.state.stats.directory_traversal || 0) }
        ].filter(item => item.count > 0);

        const total = detailedData.reduce((sum, item) => sum + item.count, 0);

        tableBody.innerHTML = detailedData.map(item => `
            <tr>
                <td>${item.type}</td>
                <td>${item.count}</td>
                <td>${total > 0 ? ((item.count / total) * 100).toFixed(1) : 0}%</td>
                <td>--</td>
            </tr>
        `).join('');
    },

    // تحديث الترقيم
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
            html += `
                <button class="page-number ${i === this.config.currentPage ? 'active' : ''}"
                        onclick="dashboard.goToPage(${i})">
                    ${i}
                </button>
            `;
        }

        container.innerHTML = html;
    },

    // البحث في الهجمات
    async searchAttacks() {
        const searchInput = document.getElementById('searchInput');
        const query = searchInput.value.trim();

        if (!query) {
            this.loadAllAttacksTable();
            return;
        }

        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/search?q=${query}`);
            this.updateAllAttacksTable(response.data.attacks);

            // إخفاء الترقيم عند البحث
            document.querySelector('.pagination').style.display = 'none';

        } catch (error) {
            console.error('Error searching attacks:', error);
        }
    },

    // تصفية الهجمات حسب النوع
    async filterAttacks() {
        const typeFilter = document.getElementById('typeFilter');
        const type = typeFilter.value;

        if (type === 'all') {
            this.config.currentPage = 1;
            this.loadAllAttacksTable();
            return;
        }

        try {
            const response = await axios.get(`${this.config.apiBase}/attacks?type=${type}`);
            this.updateAllAttacksTable(response.data.attacks);

            // إخفاء الترقيم عند التصفية
            document.querySelector('.pagination').style.display = 'none';

        } catch (error) {
            console.error('Error filtering attacks:', error);
        }
    },

    // الذهاب لصفحة محددة
    goToPage(page) {
        this.config.currentPage = page;
        this.loadAllAttacksTable();
    },

    // الصفحة السابقة
    prevPage() {
        if (this.config.currentPage > 1) {
            this.goToPage(this.config.currentPage - 1);
        }
    },

    // الصفحة التالية
    nextPage() {
        this.goToPage(this.config.currentPage + 1);
    },

    // حذف هجوم
    async deleteAttack(id) {
        if (!confirm('هل أنت متأكد من حذف هذا الهجوم؟')) return;

        try {
            await axios.delete(`${this.config.apiBase}/attacks/${id}`);
            this.showAlert('تم حذف الهجوم بنجاح', 'success');
            this.loadAllAttacksTable();
            this.loadStats();
        } catch (error) {
            console.error('Error deleting attack:', error);
            this.showAlert('خطأ في حذف الهجوم', 'danger');
        }
    },

    // مسح جميع الهجمات
    async clearAllAttacks() {
        if (!confirm('⚠️ تحذير: سيتم مسح جميع الهجمات المسجلة. هل أنت متأكد؟')) return;

        try {
            const response = await axios.post(`${this.config.apiBase}/attacks/clear`);
            this.showAlert(response.data.message, 'success');
            this.loadAllData();
        } catch (error) {
            console.error('Error clearing attacks:', error);
            this.showAlert('خطأ في مسح الهجمات', 'danger');
        }
    },

    // تبديل الأقسام
    showSection(sectionId) {
        // إخفاء جميع الأقسام
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });

        // إزالة النشط من جميع الأزرار
        document.querySelectorAll('.menu-btn').forEach(btn => {
            btn.classList.remove('active');
        });

        // إظهار القسم المطلوب
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('active');
        }

        // تفعيل الزر المطلوب
        const buttons = document.querySelectorAll('.menu-btn');
        buttons.forEach(btn => {
            if (btn.textContent.includes(this.getSectionName(sectionId))) {
                btn.classList.add('active');
            }
        });

        // تحميل بيانات القسم إذا لزم
        if (sectionId === 'attacks') {
            this.config.currentPage = 1;
            this.loadAllAttacksTable();
        } else if (sectionId === 'statistics') {
            this.loadTopIPs();
            this.updateDetailedStats();
        } else if (sectionId === 'realtime') {
            this.startLiveUpdates();
        }
    },

    // مسح قاعدة البيانات
    async clearDatabase() {
        if (!confirm('⚠️ تحذير: سيتم مسح قاعدة البيانات بالكامل. هل أنت متأكد؟')) return;

        try {
            await this.clearAllAttacks();
        } catch (error) {
            console.error('Error clearing database:', error);
        }
    },

    // حفظ الإعدادات
    saveSettings() {
        const settings = {
            alertSQL: document.getElementById('alertSQL').checked,
            alertXSS: document.getElementById('alertXSS').checked,
            alertTraversal: document.getElementById('alertTraversal').checked
        };

        localStorage.setItem('honeypotSettings', JSON.stringify(settings));
        this.showAlert('تم حفظ الإعدادات', 'success');
    },

    // تحميل الإعدادات
    loadSettings() {
        const saved = localStorage.getItem('honeypotSettings');
        if (saved) {
            const settings = JSON.parse(saved);
            document.getElementById('alertSQL').checked = settings.alertSQL;
            document.getElementById('alertXSS').checked = settings.alertXSS;
            document.getElementById('alertTraversal').checked = settings.alertTraversal;
        }
    },

    // بدء التحديثات التلقائية
    startAutoRefresh() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);

        this.refreshInterval = setInterval(() => {
            const activeSection = document.querySelector('.dashboard-section.active').id;

            switch(activeSection) {
                case 'overview':
                    this.loadStats();
                    this.loadRecentAttacks();
                    break;
                case 'realtime':
                    this.updateLiveData();
                    break;
            }

            this.updateLastUpdateTime();
        }, this.config.refreshInterval);
    },

    // إيقاف التحديثات التلقائية
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    },

    // تحديث البيانات الحية
    async updateLiveData() {
        try {
            const response = await axios.get(`${this.config.apiBase}/attacks/recent?limit=10`);
            this.state.liveAttacks = response.data;
            this.updateLiveFeed();

            // تحديث الإحصائيات الحية
            this.updateElement('liveAttacksNow', this.state.liveAttacks.length);

        } catch (error) {
            console.error('Error updating live data:', error);
        }
    },

    // تحديث البث المباشر
    updateLiveFeed() {
        const feed = document.getElementById('liveFeed');
        if (!feed) return;

        if (this.state.liveAttacks.length === 0) {
            feed.innerHTML = `
                <div class="text-center p-4 text-muted">
                    <i class="fas fa-comment-slash fa-2x mb-3"></i>
                    <p>لا توجد هجمات حالية</p>
                </div>
            `;
            return;
        }

        feed.innerHTML = this.state.liveAttacks.map(attack => `
            <div class="live-attack">
                <div class="d-flex justify-content-between">
                    <div>
                        <strong>${attack.ip_address}</strong>
                        <span class="badge ${this.getAttackClass(attack.attack_type)} ms-2">
                            ${attack.attack_type}
                        </span>
                    </div>
                    <small>${this.formatTime(attack.timestamp)}</small>
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        ${attack.username || 'N/A'} • ${attack.request_path}
                    </small>
                </div>
            </div>
        `).join('');

        // التمرير للأعلى لعرض أحدث الهجمات
        feed.scrollTop = 0;
    },

    // تحديث الوقت
    updateTime() {
        const now = new Date();
        const timeString = now.toLocaleString('ar-SA', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        this.updateElement('currentTime', timeString);
    },

    // تحديث وقت آخر تحديث
    updateLastUpdateTime() {
        const now = new Date();
        const timeString = now.toLocaleString('ar-SA', {
            hour: '2-digit',
            minute: '2-digit'
        });

        this.updateElement('lastUpdateTime', timeString);
    },

    // نسخ إلى الحافظة
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showAlert('تم النسخ إلى الحافظة', 'success');
        }).catch(() => {
            this.showAlert('فشل النسخ', 'danger');
        });
    },

    // تحديث جميع البيانات
    refreshAll() {
        this.loadAllData();
        this.showAlert('تم تحديث البيانات', 'info');
    },

    // تحديث عنصر في الواجهة
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    },

    // عرض تنبيه
    showAlert(message, type = 'info') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // إزالة التنبيهات القديمة
        const oldAlerts = document.querySelectorAll('.alert');
        oldAlerts.forEach(a => a.remove());

        // إضافة التنبيه الجديد
        const container = document.querySelector('.container-fluid');
        container.insertBefore(alert, container.firstChild);

        // إزالة التنبيه بعد 3 ثواني
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 3000);
    },

    // تنسيق الوقت
    formatTime(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString('ar-SA', {
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    // الحصول على كلاس الهجوم
    getAttackClass(attackType) {
        if (attackType.includes('SQL')) return 'badge-sql';
        if (attackType.includes('XSS')) return 'badge-xss';
        if (attackType.includes('Traversal')) return 'badge-traversal';
        return 'badge-normal';
    },

    // الحصول على اسم القسم
    getSectionName(sectionId) {
        const names = {
            'overview': 'نظرة عامة',
            'attacks': 'سجل الهجمات',
            'statistics': 'الإحصائيات',
            'realtime': 'مباشر',
            'settings': 'الإعدادات'
        };

        return names[sectionId] || sectionId;
    }
};

// تهيئة Dashboard عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', function() {
    dashboard.init();
    dashboard.loadSettings();
});