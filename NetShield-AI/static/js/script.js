document.addEventListener('DOMContentLoaded', function () {
    const mobileButton = document.querySelector('.mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');

    if (mobileButton && sidebar) {
        mobileButton.addEventListener('click', function () {
            const isOpen = sidebar.classList.toggle('is-open');
            document.body.classList.toggle('sidebar-open', isOpen);
            mobileButton.setAttribute('aria-expanded', String(isOpen));
            mobileButton.setAttribute('aria-label', isOpen ? 'Close navigation' : 'Open navigation');
        });
    }

    if (overlay && mobileButton && sidebar) {
        overlay.addEventListener('click', function () {
            sidebar.classList.remove('is-open');
            document.body.classList.remove('sidebar-open');
            mobileButton.setAttribute('aria-expanded', 'false');
            mobileButton.setAttribute('aria-label', 'Open navigation');
        });
    }
});
