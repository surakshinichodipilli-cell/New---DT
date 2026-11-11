document.addEventListener('DOMContentLoaded', function () {
    const dataElement = document.getElementById('dashboard-data');
    if (!dataElement) {
        return;
    }

    const initialData = JSON.parse(dataElement.textContent);
    const riskCanvas = document.getElementById('riskChart');
    const activityCanvas = document.getElementById('activityChart');
    const chartError = document.querySelector('[data-chart-error]');
    const refreshError = document.querySelector('[data-refresh-error]');
    const apiUrl = document.body.dataset.dashboardUrl;
    let riskChart;
    let activityChart;

    function formatDate(value) {
        const parts = value.slice(0, 10).split('-').map(Number);
        if (parts.length !== 3 || parts.some(Number.isNaN)) {
            return value;
        }
        return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' })
            .format(new Date(parts[0], parts[1] - 1, parts[2]));
    }

    function formatDateTime(value) {
        const date = new Date(value.replace(' ', 'T') + 'Z');
        if (Number.isNaN(date.getTime())) {
            return value;
        }
        return new Intl.DateTimeFormat(undefined, {
            dateStyle: 'medium',
            timeStyle: 'short'
        }).format(date);
    }

    function riskClass(value) {
        return String(value || '').toLowerCase().replace(/\s+/g, '-');
    }

    function updateText(selector, value) {
        document.querySelectorAll(selector).forEach(function (element) {
            const formatted = element.dataset.format === 'score' && value !== null && value !== undefined
                ? value + '/100'
                : value === null || value === undefined ? '—' : value;
            element.textContent = formatted;
        });
    }

    function renderRiskChart(stats) {
        if (!riskChart) {
            return;
        }
        riskChart.data.datasets[0].data = [
            stats.safe_urls,
            stats.suspicious_urls,
            stats.high_risk_urls
        ];
        riskChart.update('none');
    }

    function renderActivityChart(activity) {
        if (!activityChart) {
            return;
        }
        activityChart.data.labels = activity.map(function (item) {
            return formatDate(item.date);
        });
        activityChart.data.datasets[0].data = activity.map(function (item) { return item.urls; });
        activityChart.data.datasets[1].data = activity.map(function (item) { return item.high_risk_urls; });
        activityChart.data.datasets[2].data = activity.map(function (item) { return item.device_discoveries; });
        activityChart.data.datasets[3].data = activity.map(function (item) { return item.alerts; });
        activityChart.update('none');
    }

    function renderEvents(events) {
        const tbody = document.querySelector('[data-recent-events]');
        if (!tbody) {
            return;
        }
        tbody.replaceChildren();
        if (!events.length) {
            const row = document.createElement('tr');
            row.className = 'events-empty';
            const cell = document.createElement('td');
            cell.colSpan = 5;
            const title = document.createElement('strong');
            title.textContent = 'No security events yet';
            const description = document.createElement('span');
            description.textContent = 'Completed URL analyses, network scans, and alerts will appear here.';
            cell.append(title, description);
            row.append(cell);
            tbody.append(row);
            return;
        }

        events.forEach(function (event) {
            const row = document.createElement('tr');
            const type = document.createElement('td');
            type.className = 'event-type';
            type.textContent = event.event_type;
            const description = document.createElement('td');
            description.className = 'event-description';
            description.textContent = event.description;
            const riskCell = document.createElement('td');
            const risk = document.createElement('span');
            risk.className = 'event-risk ' + riskClass(event.risk_level);
            risk.textContent = event.risk_level;
            riskCell.append(risk);
            const time = document.createElement('td');
            time.className = 'event-time';
            time.textContent = formatDateTime(event.event_time);
            const statusCell = document.createElement('td');
            const status = document.createElement('span');
            status.className = 'event-status ' + riskClass(event.status);
            status.textContent = event.status;
            statusCell.append(status);
            row.append(type, description, riskCell, time, statusCell);
            tbody.append(row);
        });
    }

    function renderNetworkStatus(stats) {
        const banner = document.querySelector('[data-network-status]');
        const scan = stats.latest_network_scan;
        if (!banner) {
            return;
        }
        banner.replaceChildren();
        const indicator = document.createElement('span');
        indicator.className = 'network-status-indicator ' + (scan ? scan.mode : 'idle');
        indicator.setAttribute('aria-hidden', 'true');
        const details = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = scan ? scan.mode === 'demo' ? 'DEMO DATA' : 'LAST LIVE SCAN' : 'NO SCANS YET';
        const timestamp = document.createElement('span');
        timestamp.textContent = scan ? formatDateTime(scan.created_at) : 'Run a scan to see network activity';
        details.append(title, timestamp);
        banner.append(indicator, details);
        updateText('[data-network-stat="detected"]', scan ? scan.total_devices : 0);
    }

    function renderDashboard(data) {
        const stats = data.stats;
        updateText('[data-stat="overall_security_score"]', stats.overall_security_score);
        updateText('[data-stat="urls_scanned"]', stats.urls_scanned);
        updateText('[data-stat="high_risk_urls"]', stats.high_risk_urls);
        updateText('[data-stat="total_devices"]', stats.total_devices);
        updateText('[data-stat="unverified_devices"]', stats.unverified_devices);
        updateText('[data-stat="active_alerts"]', stats.active_alerts);
        updateText('[data-stat="safe_urls"]', stats.safe_urls);
        updateText('[data-stat="suspicious_urls"]', stats.suspicious_urls);
        updateText('[data-stat="known_devices"]', stats.known_devices);
        updateText('[data-stat="suspicious_devices"]', stats.suspicious_devices);
        updateText('[data-stat="security_status"]', stats.security_status);

        const scoreDescription = document.querySelector('[data-stat-description="overall_security_score"]');
        if (scoreDescription) {
            scoreDescription.textContent = stats.has_scan_data
                ? 'Based on your latest saved scans'
                : 'Run a scan to establish a baseline';
        }
        const explanation = document.querySelector('[data-security-explanation]');
        if (explanation) {
            explanation.textContent = stats.security_explanation;
        }
        const statusCard = document.querySelector('[data-security-status]');
        if (statusCard) {
            statusCard.className = 'security-status-card ' + riskClass(stats.security_status);
        }

        const activeAlerts = document.querySelector('.notification-link');
        if (activeAlerts) {
            const previousCount = activeAlerts.querySelector('.notification-count');
            if (previousCount) {
                previousCount.remove();
            }
            if (stats.active_alerts) {
                const count = document.createElement('span');
                count.className = 'notification-count';
                count.textContent = stats.active_alerts;
                activeAlerts.append(count);
            }
            activeAlerts.setAttribute('aria-label', stats.active_alerts
                ? stats.active_alerts + ' active security alerts'
                : 'Security alerts');
        }

        renderNetworkStatus(stats);
        renderRiskChart(stats);
        renderActivityChart(data.activity);
        renderEvents(data.events);

        const activityEmpty = document.querySelector('[data-activity-empty]');
        if (activityEmpty) {
            const hasActivity = stats.has_activity_data;
            activityEmpty.classList.toggle('hidden', Boolean(hasActivity));
        }
    }

    function initializeCharts(data) {
        if (typeof Chart === 'undefined') {
            if (chartError) {
                chartError.classList.remove('hidden');
            }
            return;
        }
        const gridColor = 'rgba(147, 170, 197, 0.12)';
        const tickColor = '#91a5bd';
        riskChart = new Chart(riskCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Low risk', 'Medium risk', 'High risk'],
                datasets: [{
                    data: [data.stats.safe_urls, data.stats.suspicious_urls, data.stats.high_risk_urls],
                    backgroundColor: ['#38d9a9', '#ffbf69', '#ff647c'],
                    borderColor: '#111c2c',
                    borderWidth: 5,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '74%',
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: '#091322', padding: 12 }
                }
            }
        });
        activityChart = new Chart(activityCanvas, {
            type: 'line',
            data: {
                labels: data.activity.map(function (item) { return formatDate(item.date); }),
                datasets: [
                    { label: 'URL scans', data: data.activity.map(function (item) { return item.urls; }), borderColor: '#38d9ff', backgroundColor: 'rgba(56, 217, 255, .09)', fill: true },
                    { label: 'High-risk URLs', data: data.activity.map(function (item) { return item.high_risk_urls; }), borderColor: '#ff647c', backgroundColor: 'transparent' },
                    { label: 'Device discoveries', data: data.activity.map(function (item) { return item.device_discoveries; }), borderColor: '#9a8cff', backgroundColor: 'transparent' },
                    { label: 'Security alerts', data: data.activity.map(function (item) { return item.alerts; }), borderColor: '#ffbf69', backgroundColor: 'transparent' }
                ].map(function (dataset) {
                    return Object.assign({
                        borderWidth: 2,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                        tension: 0.35
                    }, dataset);
                })
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: tickColor, usePointStyle: true, pointStyle: 'circle', boxWidth: 7, padding: 18 }
                    },
                    tooltip: { backgroundColor: '#091322', padding: 12 }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: tickColor } },
                    y: { beginAtZero: true, ticks: { color: tickColor, precision: 0 }, grid: { color: gridColor } }
                }
            }
        });
    }

    initializeCharts(initialData);
    renderDashboard(initialData);

    window.setInterval(async function () {
        try {
            const response = await fetch(apiUrl, {
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json' }
            });
            if (!response.ok) {
                throw new Error('Dashboard refresh returned HTTP ' + response.status);
            }
            const data = await response.json();
            if (!data.success) {
                throw new Error('Dashboard refresh was not successful.');
            }
            renderDashboard(data);
            if (refreshError) {
                refreshError.classList.add('hidden');
            }
        } catch (error) {
            console.error('Unable to refresh dashboard data.', error);
            if (refreshError) {
                refreshError.textContent = 'Dashboard data could not refresh. Reload this page to try again.';
                refreshError.classList.remove('hidden');
            }
        }
    }, 30000);
});
