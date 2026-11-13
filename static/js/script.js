document.addEventListener("DOMContentLoaded", function () {
    // 1. Sidebar Toggle (Mobile)
    const toggleBtn = document.getElementById("sidebarToggleBtn");
    const sidebar = document.getElementById("appSidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener("click", function () {
            sidebar.classList.toggle("show");
            if (backdrop) backdrop.classList.toggle("show");
        });
    }
    if (backdrop && sidebar) {
        backdrop.addEventListener("click", function () {
            sidebar.classList.remove("show");
            backdrop.classList.remove("show");
        });
    }

    // 2. Theme Toggle (Deep Navy #111127 vs Light #F7F6FC)
    const themeBtn = document.getElementById("themeToggleBtn");
    const themeIcon = document.getElementById("themeToggleIcon");
    const savedTheme = localStorage.getItem("cc_theme") || "dark";
    if (savedTheme === "light") {
        document.body.classList.add("light-mode");
        if (themeIcon) themeIcon.className = "fas fa-moon";
    }
    if (themeBtn) {
        themeBtn.addEventListener("click", function () {
            document.body.classList.toggle("light-mode");
            const isLight = document.body.classList.contains("light-mode");
            localStorage.setItem("cc_theme", isLight ? "light" : "dark");
            if (themeIcon) {
                themeIcon.className = isLight ? "fas fa-moon" : "fas fa-sun";
            }
        });
    }

    // 3. Offline-Safe Dropdown Toggle
    document.querySelectorAll('[data-bs-toggle="dropdown"]').forEach(function (btn) {
        btn.addEventListener("click", function (e) {
            e.stopPropagation();
            const menu = btn.parentElement.querySelector(".dropdown-menu");
            if (menu) menu.classList.toggle("show");
        });
    });
    document.addEventListener("click", function () {
        document.querySelectorAll(".dropdown-menu.show").forEach(function (m) {
            m.classList.remove("show");
        });
    });
});

function copyText(txt) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(txt);
    }
}


// Interactive Mouse Spotlight on Cards
document.addEventListener("mousemove", function (e) {
    document.querySelectorAll(".cc-plan-card, .stat-card").forEach(function (card) {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty("--mouse-x", x + "px");
        card.style.setProperty("--mouse-y", y + "px");
    });
});
