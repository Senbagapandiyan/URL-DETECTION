// Keep the existing theme toggle behavior while preserving the current page structure.
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('themeToggle');
    if (!toggle) {
        return;
    }

    const currentTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', currentTheme);
    toggle.innerHTML = currentTheme === 'dark' ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';

    toggle.addEventListener('click', () => {
        const nextTheme = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', nextTheme);
        localStorage.setItem('theme', nextTheme);
        toggle.innerHTML = nextTheme === 'dark' ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';
    });
});
