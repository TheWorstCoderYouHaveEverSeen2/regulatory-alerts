// Mobile sidebar toggle
document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('mobile-menu-btn');
    var sidebar = document.getElementById('sidebar');

    if (btn && sidebar) {
        btn.addEventListener('click', function () {
            sidebar.classList.toggle('sidebar-open');
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function (e) {
            if (window.innerWidth < 1024 &&
                !sidebar.contains(e.target) &&
                !btn.contains(e.target) &&
                sidebar.classList.contains('sidebar-open')) {
                sidebar.classList.remove('sidebar-open');
            }
        });
    }
});

// Auto-dismiss flash messages after 5 seconds
document.body.addEventListener('htmx:afterSwap', function (e) {
    dismissFlashes();
});

document.addEventListener('DOMContentLoaded', function () {
    dismissFlashes();
});

function dismissFlashes() {
    var flashes = document.querySelectorAll('.flash-msg');
    flashes.forEach(function (flash) {
        setTimeout(function () {
            flash.classList.add('fade-out');
            setTimeout(function () { flash.remove(); }, 500);
        }, 5000);
    });
}

// Channel type toggle (webhook / slack / email fields)
document.addEventListener('change', function (e) {
    if (e.target.name === 'channel_type') {
        var webhookFields = document.getElementById('webhook-fields');
        var emailFields = document.getElementById('email-fields');
        var secretGroup = document.getElementById('webhook-secret-group');
        var val = e.target.value;
        if (webhookFields && emailFields) {
            // Show URL fields for both webhook and slack; email fields only for email
            webhookFields.classList.toggle('hidden', val === 'email');
            emailFields.classList.toggle('hidden', val !== 'email');
        }
        if (secretGroup) {
            // HMAC secret only for webhook (not slack)
            secretGroup.classList.toggle('hidden', val !== 'webhook');
        }
    }
});
