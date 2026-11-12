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

    // 3. Pure-JS Fallback for Modals & Dropdowns (if Bootstrap CDN is blocked)
    if (typeof window.bootstrap === 'undefined') {
        document.querySelectorAll('[data-bs-toggle="modal"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetSel = btn.getAttribute('data-bs-target');
                const modalEl = targetSel ? document.querySelector(targetSel) : null;
                if (modalEl) modalEl.classList.add('show');
            });
        });
        document.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const modalEl = btn.closest('.modal');
                if (modalEl) modalEl.classList.remove('show');
            });
        });
        document.querySelectorAll('[data-bs-toggle="dropdown"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const menu = btn.parentElement.querySelector('.dropdown-menu');
                if (menu) menu.classList.toggle('show');
            });
        });
        document.addEventListener('click', () => {
            document.querySelectorAll('.dropdown-menu.show').forEach(m => m.classList.remove('show'));
        });
    }
});
