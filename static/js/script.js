document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'scale(1.05)';
        });
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'scale(1)';
        });
    });

    let charts = {};
    let networkData = { upload: [], download: [], labels: [] };

    window.toggleChart = function(chartId, chartType, serverId) {
        const canvas = document.getElementById(chartId);
        if (canvas.style.display === 'none' || !charts[chartId]) {
            canvas.style.display = 'block';
            if (!charts[chartId]) {
                if (chartType === 'pie') {
                    if (chartId === 'cpu-chart') {
                        charts[chartId] = new Chart(canvas, {
                            type: 'pie',
                            data: {
                                labels: ['Used', 'Free'],
                                datasets: [{ data: [0, 100], backgroundColor: ['#FF6384', '#36A2EB'] }]
                            },
                            options: { responsive: true, maintainAspectRatio: false }
                        });
                    } else if (chartId === 'ram-chart') {
                        charts[chartId] = new Chart(canvas, {
                            type: 'pie',
                            data: {
                                labels: ['Used', 'Free'],
                                datasets: [{ data: [0, 100], backgroundColor: ['#FFCE56', '#4BC0C0'] }]
                            },
                            options: { responsive: true, maintainAspectRatio: false }
                        });
                    }
                } else if (chartType === 'line') {
                    charts[chartId] = new Chart(canvas, {
                        type: 'line',
                        data: {
                            labels: networkData.labels,
                            datasets: [
                                { label: 'Upload (Mbps)', data: networkData.upload, borderColor: '#FF6384', fill: false },
                                { label: 'Download (Mbps)', data: networkData.download, borderColor: '#36A2EB', fill: false }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                x: { title: { display: true, text: 'Time' } },
                                y: { title: { display: true, text: 'Mbps' } }
                            }
                        }
                    });
                }
            }
        } else {
            canvas.style.display = 'none';
        }

        setInterval(() => {
            fetch(`/monitor/${serverId}`)
                .then(response => response.json())
                .then(data => {
                    if (chartId === 'cpu-chart') {
                        charts[chartId].data.datasets[0].data = [data.cpu_usage, 100 - data.cpu_usage];
                        charts[chartId].update();
                    } else if (chartId === 'ram-chart') {
                        charts[chartId].data.datasets[0].data = [data.ram_usage, 100 - data.ram_usage];
                        charts[chartId].update();
                    } else if (chartId === 'network-chart') {
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
                });
        }, 1000);
    };

    document.getElementById('themeSwitch').addEventListener('change', (e) => {
        if (e.target.checked) {
            document.body.classList.remove('bg-dark');
            document.body.classList.add('light-theme');
        } else {
            document.body.classList.remove('light-theme');
            document.body.classList.add('bg-dark');
        }
    });
});