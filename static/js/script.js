document.addEventListener('DOMContentLoaded', () => {
    // 1. Persistent Theme Toggle (Dark / Light)
    const themeBtn = document.getElementById('themeToggleBtn');
    const themeIcon = document.getElementById('themeToggleIcon');
    const savedTheme = localStorage.getItem('xmonitor_theme') || 'dark';

    function applyTheme(mode) {
        if (mode === 'light') {
            document.body.classList.remove('bg-dark');
            document.body.classList.add('light-theme');
            if (themeIcon) themeIcon.className = 'fas fa-moon';
        } else {
            document.body.classList.remove('light-theme');
            document.body.classList.add('bg-dark');
            if (themeIcon) themeIcon.className = 'fas fa-sun';
        }
    }

    applyTheme(savedTheme);

    if (themeBtn) {
        themeBtn.addEventListener('click', () => {
            const isLight = document.body.classList.contains('light-theme');
            const nextTheme = isLight ? 'dark' : 'light';
            localStorage.setItem('xmonitor_theme', nextTheme);
            applyTheme(nextTheme);
        });
    }

    // 2. Mobile Sidebar Drawer Toggle
    const sidebar = document.getElementById('appSidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    const menuToggleBtn = document.getElementById('sidebarToggleBtn');

    function closeSidebar() {
        if (sidebar) sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('show');
    }

    if (menuToggleBtn && sidebar) {
        menuToggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            if (backdrop) backdrop.classList.toggle('show');
        });
    }

    if (backdrop) {
        backdrop.addEventListener('click', closeSidebar);
    }

    // 3. Chart.js Live Toggler (kept for backward compatibility)
    const charts = {};
    const chartIntervals = {};
    const networkData = { upload: [], download: [], labels: [] };

    window.toggleChart = function(chartId, chartType, serverId) {
        const canvas = document.getElementById(chartId);
        if (!canvas) return;

        if (canvas.style.display === 'none' || !charts[chartId]) {
            canvas.style.display = 'block';
            if (!charts[chartId]) {
                if (chartType === 'pie') {
                    charts[chartId] = new Chart(canvas, {
                        type: 'doughnut',
                        data: {
                            labels: ['مصرف‌شده', 'آزاد'],
                            datasets: [{
                                data: [0, 100],
                                backgroundColor: ['#3b82f6', 'rgba(148, 163, 184, 0.15)'],
                                borderWidth: 0
                            }]
                        },
                        options: { responsive: true, maintainAspectRatio: false, cutout: '72%' }
                    });
                } else if (chartType === 'line') {
                    charts[chartId] = new Chart(canvas, {
                        type: 'line',
                        data: {
                            labels: networkData.labels,
                            datasets: [
                                { label: 'Upload (Mbps)', data: networkData.upload, borderColor: '#06b6d4', tension: 0.35, fill: false },
                                { label: 'Download (Mbps)', data: networkData.download, borderColor: '#3b82f6', tension: 0.35, fill: false }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                x: { grid: { display: false } },
                                y: { grid: { color: 'rgba(148, 163, 184, 0.12)' } }
                            }
                        }
                    });
                }
            }

            if (!chartIntervals[chartId]) {
                chartIntervals[chartId] = setInterval(() => {
                    fetch(`/monitor/${serverId}`)
                        .then(res => res.json())
                        .then(data => {
                            if (chartId === 'cpu-chart' && charts[chartId]) {
                                charts[chartId].data.datasets[0].data = [data.cpu_usage, Math.max(0, 100 - data.cpu_usage)];
                                charts[chartId].update();
                            } else if (chartId === 'ram-chart' && charts[chartId]) {
                                charts[chartId].data.datasets[0].data = [data.ram_usage, Math.max(0, 100 - data.ram_usage)];
                                charts[chartId].update();
                            } else if (chartId === 'network-chart' && charts[chartId]) {
                                networkData.labels.push(new Date().toLocaleTimeString());
                                networkData.upload.push(data.upload);
                                networkData.download.push(data.download);
                                if (networkData.labels.length > 20) {
                                    networkData.labels.shift();
                                    networkData.upload.shift();
                                    networkData.download.shift();
                                }
                                charts[chartId].data.labels = networkData.labels;
                                charts[chartId].data.datasets[0].data = networkData.upload;
                                charts[chartId].data.datasets[1].data = networkData.download;
                                charts[chartId].update();
                            }
                        })
                        .catch(err => console.error('Chart monitor error:', err));
                }, 2000);
            }
        } else {
            canvas.style.display = 'none';
            if (chartIntervals[chartId]) {
                clearInterval(chartIntervals[chartId]);
                delete chartIntervals[chartId];
            }
        }
    };
});
