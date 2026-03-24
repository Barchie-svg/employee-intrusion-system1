(function() {
    // ==========================================
    // SECURE IDS — INVISIBLE SHIELD WIDGET v2
    // ==========================================

    const idsHost = new URL(document.currentScript.src).origin;
    const apiKey = document.currentScript.getAttribute('data-api-key');

    // ─── Inject CSS ───
    const style = document.createElement('style');
    style.innerHTML = `
        /* ── Badge ── */
        .ids-badge {
            position: fixed; bottom: 22px; right: 22px;
            background: rgba(15, 19, 32, 0.95);
            color: #c4c8e0;
            padding: 9px 16px;
            border-radius: 100px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.35), 0 0 0 1px rgba(108,92,231,0.25);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 12.5px; font-weight: 600;
            display: flex; align-items: center; gap: 8px;
            z-index: 999999; cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            backdrop-filter: blur(10px);
            text-decoration: none;
        }
        .ids-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.4), 0 0 0 1px rgba(108,92,231,0.5);
        }
        .ids-badge-icon { color: #6c5ce7; font-size: 15px; animation: shieldPulse 3s ease-in-out infinite; }
        @keyframes shieldPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        /* ── Loading Overlay ── */
        .ids-loader {
            position: fixed; inset: 0;
            background: rgba(8, 11, 20, 0.7);
            z-index: 9999999;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            gap: 16px;
            backdrop-filter: blur(6px);
            font-family: 'Segoe UI', sans-serif;
        }
        .ids-loader-card {
            background: rgba(15, 19, 32, 0.95);
            border: 1px solid rgba(108,92,231,0.25);
            border-radius: 16px; padding: 32px 40px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        .ids-loader-spinner {
            width: 46px; height: 46px;
            border: 3px solid rgba(108,92,231,0.2);
            border-top-color: #6c5ce7;
            border-radius: 50%;
            animation: idsSpinner 0.8s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes idsSpinner { to { transform: rotate(360deg); } }
        .ids-loader-text { color: #a78bfa; font-weight: 600; font-size: 14px; }
        .ids-loader-sub { color: #64748b; font-size: 12px; margin-top: 4px; }

        /* ── Block Overlay ── */
        .ids-block-overlay {
            position: fixed; inset: 0;
            background: rgba(8, 11, 20, 0.92);
            z-index: 9999999;
            display: flex; justify-content: center; align-items: center;
            opacity: 0; transition: opacity 0.35s ease;
            backdrop-filter: blur(12px);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .ids-block-overlay.visible { opacity: 1; }
        .ids-block-card {
            background: #0f1320;
            border: 1px solid rgba(239,68,68,0.25);
            border-radius: 20px; padding: 44px 40px;
            max-width: 460px; width: 90%;
            text-align: center; color: white;
            box-shadow: 0 25px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(239,68,68,0.1);
            transform: scale(0.92);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        .ids-block-overlay.visible .ids-block-card { transform: scale(1); }

        .ids-block-icon-wrap {
            width: 72px; height: 72px;
            background: rgba(239,68,68,0.12);
            border: 1px solid rgba(239,68,68,0.25);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 22px;
        }
        .ids-block-icon { color: #ef4444; font-size: 32px; }
        .ids-block-title { font-size: 22px; font-weight: 700; margin-bottom: 12px; color: #f8fafc; }
        .ids-block-reason {
            font-size: 14px; color: #94a3b8; line-height: 1.65;
            margin-bottom: 28px;
            background: rgba(239,68,68,0.07);
            border: 1px solid rgba(239,68,68,0.15);
            border-radius: 10px; padding: 14px 16px;
        }
        .ids-block-footer {
            display: flex; justify-content: center; gap: 12px; flex-wrap: wrap;
        }
        .ids-dismiss-btn {
            background: rgba(239,68,68,0.15); color: #ef4444;
            border: 1px solid rgba(239,68,68,0.25);
            padding: 11px 24px; border-radius: 10px;
            font-size: 14px; font-weight: 600;
            cursor: pointer; transition: background 0.2s;
            font-family: inherit;
        }
        .ids-dismiss-btn:hover { background: rgba(239,68,68,0.25); }
        .ids-brand-link {
            color: #6c5ce7; font-size: 12px; font-weight: 600;
            text-decoration: none; display: block; margin-top: 20px;
            opacity: 0.7;
        }
        .ids-brand-link:hover { opacity: 1; }
    `;
    document.head.appendChild(style);

    // ─── Load FontAwesome if not present ───
    if (!document.querySelector('link[href*="font-awesome"]')) {
        const fa = document.createElement('link');
        fa.rel = 'stylesheet';
        fa.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css';
        document.head.appendChild(fa);
    }

    // ─── Inject "Protected by SecureIDS" badge ───
    window.addEventListener('DOMContentLoaded', () => {
        const badge = document.createElement('a');
        badge.className = 'ids-badge';
        badge.href = idsHost + '/integration';
        badge.target = '_blank';
        badge.title = 'Powered by SecureIDS Intrusion Detection';
        badge.innerHTML = `<i class="fa-solid fa-shield-halved ids-badge-icon"></i> Protected by SecureIDS`;
        document.body.appendChild(badge);

        // Find all login forms (forms with a password field)
        document.querySelectorAll('form').forEach(form => {
            if (form.querySelector('input[type="password"]')) {
                attachShield(form);
            }
        });
    });

    // ─── Attach security interceptor to a form ───
    function attachShield(form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();

            // Show scanning loader
            const loader = createLoader();
            document.body.appendChild(loader);

            // Grab identifier from the first non-password, non-hidden field
            let identifier = 'unknown_user';
            const inputs = form.querySelectorAll('input:not([type="password"]):not([type="hidden"]):not([type="submit"])');
            if (inputs.length > 0 && inputs[0].value) {
                identifier = inputs[0].value;
            }

            // Grab the password field
            let passwordValue = '';
            const passInput = form.querySelector('input[type="password"]');
            if (passInput) {
                passwordValue = passInput.value;
            }

            try {
                const resp = await fetch(idsHost + '/api/v1/auth/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + apiKey
                    },
                    body: JSON.stringify({
                        identifier: identifier,
                        password: passwordValue,
                        url: window.location.href
                    })
                });

                const data = await resp.json();
                loader.remove();

                if (data.status === 'allow') {
                    // ✅ Safe — allow form to submit normally
                    form.submit();
                } else {
                    // 🚫 Blocked — show reason overlay
                    showBlockOverlay(data.reason || 'Access was denied by the security system.');
                }
            } catch (err) {
                console.warn('[SecureIDS] Evaluation failed — failing open:', err);
                loader.remove();
                // Fail-open: if IDS is unreachable, don't block legitimate users
                form.submit();
            }
        });
    }

    function createLoader() {
        const el = document.createElement('div');
        el.className = 'ids-loader';
        el.innerHTML = `
            <div class="ids-loader-card">
                <div class="ids-loader-spinner"></div>
                <div class="ids-loader-text"><i class="fa-solid fa-shield-halved"></i> Verifying access...</div>
                <div class="ids-loader-sub">SecureIDS is screening your request</div>
            </div>
        `;
        return el;
    }

    function showBlockOverlay(reason) {
        const overlay = document.createElement('div');
        overlay.className = 'ids-block-overlay';
        overlay.innerHTML = `
            <div class="ids-block-card">
                <div class="ids-block-icon-wrap">
                    <i class="fa-solid fa-shield-halved ids-block-icon"></i>
                </div>
                <div class="ids-block-title">Access Denied</div>
                <div class="ids-block-reason">
                    <strong>Security Reason:</strong><br>${reason}
                </div>
                <div class="ids-block-footer">
                    <button class="ids-dismiss-btn" onclick="this.closest('.ids-block-overlay').remove()">
                        <i class="fa-solid fa-xmark"></i> Dismiss
                    </button>
                </div>
                <a class="ids-brand-link" href="${idsHost}/integration" target="_blank">
                    <i class="fa-solid fa-shield-halved"></i> Secured by SecureIDS
                </a>
            </div>
        `;
        document.body.appendChild(overlay);
        // Trigger animation
        requestAnimationFrame(() => overlay.classList.add('visible'));
    }
})();
