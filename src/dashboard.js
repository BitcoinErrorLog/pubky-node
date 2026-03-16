// Pubky Node Dashboard
(function () {
    'use strict';

    // ========== Auth System ==========
    // Custom login/setup forms instead of browser Basic Auth popup.
    // Password is stored in memory and sent via X-Auth-Password header with every API call.

    var _authPassword = null; // In-memory password, cleared on tab close

    // Authenticated fetch wrapper — adds auth header to all API calls
    function authFetch(url, opts) {
        opts = opts || {};
        opts.headers = opts.headers || {};
        if (_authPassword) {
            opts.headers['X-Auth-Password'] = _authPassword;
        }
        return fetch(url, opts);
    }

    async function checkAuthSetup() {
        try {
            var res = await fetch('/api/auth/check');
            var data = await res.json();
            if (!data.has_password) {
                showSetupOverlay();
                return false;
            } else {
                showLoginOverlay();
                return false;
            }
        } catch (e) {
            console.log('Auth check error:', e.message);
        }
        return true;
    }

    function showSetupOverlay() {
        var overlay = document.getElementById('unified-onboarding-overlay');
        if (overlay) overlay.style.display = 'flex';
        unifiedShowStep(1);

        var btn = document.getElementById('onboard-dash-btn');
        var passInput = document.getElementById('onboard-dash-pw');
        var confirmInput = document.getElementById('onboard-dash-pw2');
        var errorEl = document.getElementById('onboard-dash-err');

        async function doDashSetup() {
            var pass = passInput.value;
            var confirm = confirmInput.value;
            errorEl.textContent = '';

            if (pass.length < 4) {
                errorEl.textContent = 'Password must be at least 4 characters.';
                return;
            }
            if (pass !== confirm) {
                errorEl.textContent = 'Passwords do not match.';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Creating...';

            try {
                var res = await fetch('/api/auth/setup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pass })
                });
                var data = await res.json();
                if (data.success) {
                    _authPassword = pass;
                    btn.textContent = 'Success!';
                    setTimeout(() => {
                        initDashboard();
                    }, 500);
                } else {
                    errorEl.textContent = data.error || 'Setup failed.';
                    btn.disabled = false;
                    btn.textContent = 'Save & Continue →';
                }
            } catch (e) {
                errorEl.textContent = 'Network error: ' + e.message;
                btn.disabled = false;
                btn.textContent = 'Save & Continue →';
            }
        }

        // Clean up previous listeners if function is called multiple times
        var newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', doDashSetup);

        confirmInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') doDashSetup(); });
        passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') confirmInput.focus(); });
        setTimeout(function () { passInput.focus(); }, 100);
    }

    // Help manage unified steps
    var _unifiedStep = 1;
    function unifiedShowStep(stepNum) {
        _unifiedStep = stepNum;
        document.querySelectorAll('.onboarding-step[data-onboard-step]').forEach(function(el) {
            el.classList.remove('active');
        });
        var target = document.querySelector('.onboarding-step[data-onboard-step="' + stepNum + '"]');
        if (target) target.classList.add('active');

        // Update dots
        var dots = document.querySelectorAll('.onboarding-dot[data-dot]');
        dots.forEach(function(dot) {
            var d = parseInt(dot.getAttribute('data-dot'));
            dot.classList.remove('active', 'done');
            if (d < stepNum) dot.classList.add('done');
            if (d === stepNum) dot.classList.add('active');
        });
    }

    function showLoginOverlay() {
        var overlay = document.createElement('div');
        overlay.id = 'auth-setup-overlay';
        overlay.innerHTML = [
            '<div class="auth-setup-card">',
            '  <div class="auth-setup-icon">🔐</div>',
            '  <h2>Pubky Node</h2>',
            '  <p class="auth-setup-desc">Enter your dashboard password to continue.</p>',
            '  <div class="auth-setup-field">',
            '    <input type="password" id="auth-login-pass" placeholder="Password" autocomplete="current-password">',
            '  </div>',
            '  <button id="auth-login-btn" class="btn-primary auth-setup-submit">🔓 Login</button>',
            '  <div id="auth-login-error" class="auth-setup-error"></div>',
            '</div>'
        ].join('\n');
        document.body.appendChild(overlay);

        var btn = document.getElementById('auth-login-btn');
        var passInput = document.getElementById('auth-login-pass');
        var errorEl = document.getElementById('auth-login-error');

        async function doLogin() {
            var pass = passInput.value;
            errorEl.textContent = '';
            if (!pass) { errorEl.textContent = 'Enter your password.'; return; }

            btn.disabled = true;
            btn.textContent = 'Logging in...';

            try {
                var res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pass })
                });
                var data = await res.json();
                if (data.success) {
                    _authPassword = pass;
                    overlay.remove();
                    initDashboard();
                } else {
                    errorEl.textContent = data.error || 'Login failed.';
                    btn.disabled = false;
                    btn.textContent = '🔓 Login';
                    passInput.select();
                }
            } catch (e) {
                errorEl.textContent = 'Network error: ' + e.message;
                btn.disabled = false;
                btn.textContent = '🔓 Login';
            }
        }

        btn.addEventListener('click', doLogin);
        passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); });
        setTimeout(function () { passInput.focus(); }, 100);
    }

    const POLL_INTERVAL = 3000;
    const HISTORY_KEY = 'pubky_explorer_history';
    const MAX_HISTORY = 10;

    // ========== Tab Navigation ==========

    function initTabs() {
        const navItems = document.querySelectorAll('.nav-item');
        // Include icon buttons that act as tab switchers
        const allTabTriggers = document.querySelectorAll('.nav-item, [data-tab].btn-icon');

        function switchToTab(target) {
            // Update tab button active states (only for .nav-item elements)
            navItems.forEach(function (t) { t.classList.remove('active'); });
            var matchingTab = document.querySelector('.nav-item[data-tab="' + target + '"]');
            if (matchingTab) matchingTab.classList.add('active');
            // Update content panels
            document.querySelectorAll('.tab-content').forEach(function (panel) {
                panel.classList.remove('active');
            });
            var targetPanel = document.getElementById('tab-' + target);
            if (targetPanel) targetPanel.classList.add('active');
        }

        allTabTriggers.forEach(function (trigger) {
            trigger.addEventListener('click', function () {
                switchToTab(trigger.dataset.tab);
            });
        });

        // Expose for external use
        window._switchToTab = switchToTab;
    }

    // ========== Status Polling ==========

    async function fetchStatus() {
        try {
            const res = await authFetch('/api/status');
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.json();
        } catch (e) {
            console.error('Failed to fetch status:', e);
            return null;
        }
    }

    function formatUptime(secs) {
        if (secs < 60) return secs + 's';
        if (secs < 3600) return Math.floor(secs / 60) + 'm ' + (secs % 60) + 's';
        var h = Math.floor(secs / 3600);
        var m = Math.floor((secs % 3600) / 60);
        if (h < 24) return h + 'h ' + m + 'm';
        var d = Math.floor(h / 24);
        return d + 'd ' + (h % 24) + 'h';
    }

    function formatInterval(secs) {
        if (secs < 60) return secs + 's';
        if (secs < 3600) return Math.floor(secs / 60) + ' min';
        return Math.floor(secs / 3600) + ' hr';
    }

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(0) + 'K';
        return String(n);
    }

    function truncateId(id, len) {
        if (!id || id.length <= len) return id || '--';
        return id.substring(0, len) + '…';
    }

    // ========== Help Tooltips ==========

    var HELP_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

    function helpTip(title, body, opts) {
        opts = opts || {};
        var cls = 'help-tip' + (opts.amber ? ' help-tip-amber' : '');
        var link = opts.guideLink
            ? '<span class="help-tooltip-link" data-action="guide">' + opts.guideLink + '</span>'
            : '';
        return '<span class="' + cls + '">' + HELP_SVG +
            '<div class="help-tooltip">' +
            '<div class="help-tooltip-title">' + title + '</div>' +
            '<div class="help-tooltip-body">' + body + link + '</div>' +
            '</div></span>';
    }

    function setStatus(online) {
        var el = document.getElementById('connection-status');
        el.className = 'status-indicator ' + (online ? 'online' : 'offline');
        if (online) {
            el.querySelector('.status-label').textContent = 'Connected';
        } else {
            el.querySelector('.status-label').innerHTML = 'Disconnected' +
                helpTip('Connection Lost',
                    'The dashboard cannot reach the node\'s API.' +
                    '<ul>' +
                    '<li>Ensure pubky-node is running</li>' +
                    '<li>Check if port 9090 is blocked</li>' +
                    '<li>Try restarting the node</li>' +
                    '</ul>'
                );
        }
    }

    function update(data) {
        if (!data) {
            setStatus(false);
            return;
        }

        try {
        setStatus(true);

        // Header
        var versionEl = document.getElementById('version');
        if (versionEl) versionEl.textContent = 'v' + data.version;

        // Stats
        var uptimeStr = formatUptime(data.uptime_secs);
        var uptimeEl = document.getElementById('uptime');
        if (uptimeEl) uptimeEl.textContent = uptimeStr;
        var headerUptime = document.getElementById('header-uptime');
        if (headerUptime) headerUptime.textContent = uptimeStr;
        var dhtSize = data.dht ? data.dht.dht_size_estimate : 0;
        var rtEl = document.getElementById('routing-table-size');
        if (rtEl) rtEl.textContent = formatNumber(dhtSize);
        var dashDhtEl = document.getElementById('dash-dht-size');
        if (dashDhtEl) dashDhtEl.textContent = dhtSize > 0 ? formatNumber(dhtSize) + ' peers' : 'Initializing…';
        var wlEl = document.getElementById('watchlist-count');
        if (wlEl) wlEl.textContent = data.watchlist.key_count;

        // DHT Panel
        if (data.dht) {
            var dht = data.dht;
            document.getElementById('node-id').textContent = truncateId(dht.id, 18);
            document.getElementById('node-id').title = dht.id;
            document.getElementById('listen-addr').textContent = dht.local_addr;

            var modeEl = document.getElementById('dht-mode');
            if (dht.server_mode) {
                modeEl.innerHTML = '● Server';
                modeEl.style.color = 'var(--green)';
            } else {
                modeEl.innerHTML = '● Client' +
                    helpTip('Client Mode',
                        'Your node is behind a firewall and cannot accept inbound connections.' +
                        '<ul>' +
                        '<li>Enable UPnP on your router</li>' +
                        '<li>Or forward your DHT UDP port</li>' +
                        '<li>Node still works, but is less efficient</li>' +
                        '</ul>',
                        { amber: true, guideLink: '→ View Setup Guide' }
                    );
                modeEl.style.color = 'var(--amber)';
            }

            var fwEl = document.getElementById('firewalled');
            if (dht.firewalled) {
                fwEl.innerHTML = '● Yes' +
                    helpTip('Firewalled',
                        'Inbound connections are blocked. Your node can still participate, but won\'t serve data to others.' +
                        '<ul>' +
                        '<li>Forward UDP port (see config.toml [dht].port) on your router</li>' +
                        '<li>Or enable UPnP for automatic port mapping</li>' +
                        '<li>Disable OS firewall for this port</li>' +
                        '</ul>',
                        { guideLink: '→ View Setup Guide' }
                    );
                fwEl.style.color = 'var(--red)';
            } else {
                fwEl.innerHTML = '● No';
                fwEl.style.color = 'var(--green)';
            }

            document.getElementById('rt-detail').textContent =
                '~' + dht.dht_size_estimate.toLocaleString() + ' nodes';
            document.getElementById('dht-badge').textContent =
                '~' + formatNumber(dht.dht_size_estimate);
            document.getElementById('dht-badge').className =
                'badge' + (dht.dht_size_estimate > 0 ? ' badge-active' : '');
        }

        // Relay Panel
        document.getElementById('relay-port').textContent = data.relay_port;
        var relayUrl = 'http://localhost:' + data.relay_port + '/';
        var relayLink = document.getElementById('relay-url');
        relayLink.textContent = relayUrl;
        relayLink.href = relayUrl;

        // UPnP / Network Panel
        if (data.upnp) {
            var upnp = data.upnp;
            var isActive = upnp.status === 'Active';
            var isFailed = upnp.status === 'Failed';

            var upnpStatusEl = document.getElementById('upnp-status');
            if (isActive) {
                upnpStatusEl.innerHTML = '● Active';
                upnpStatusEl.style.color = 'var(--green)';
            } else if (isFailed) {
                upnpStatusEl.innerHTML = '● Failed' +
                    helpTip('UPnP Failed',
                        'Automatic port mapping failed. Your router may not support UPnP, or it may be disabled.' +
                        '<ul>' +
                        '<li>Log into your router and enable UPnP/NAT-PMP</li>' +
                        '<li>Or manually forward your DHT port (UDP)</li>' +
                        '<li>Use <code>--no-upnp</code> flag to silence this</li>' +
                        '</ul>',
                        { guideLink: '→ View Setup Guide' }
                    );
                upnpStatusEl.style.color = 'var(--red)';
            } else {
                upnpStatusEl.innerHTML = '● ' + upnp.status;
                upnpStatusEl.style.color = 'var(--amber)';
            }

            document.getElementById('upnp-external-ip').textContent =
                upnp.external_ip || '--';
            document.getElementById('upnp-port').textContent =
                upnp.port ? 'UDP ' + upnp.port : '--';

            document.getElementById('upnp-badge').textContent =
                isActive ? 'Mapped' : upnp.status;
            document.getElementById('upnp-badge').className =
                'badge' + (isActive ? ' badge-active' : isFailed ? ' badge-warning' : '');

            // Show/hide inline UPnP setup guide
            document.getElementById('upnp-guide').style.display =
                isFailed ? '' : 'none';
        }

        // Watchlist Panel
        var wl = data.watchlist;
        document.getElementById('watchlist-badge').textContent =
            wl.key_count > 0 ? wl.key_count + ' keys' : 'Off';
        document.getElementById('watchlist-badge').className =
            'badge' + (wl.key_count > 0 ? ' badge-active' : '');
        document.getElementById('republish-interval').textContent =
            formatInterval(wl.republish_interval_secs);

        // PKDNS Panel
        var dns = data.dns;
        var dnsBadge = document.getElementById('dns-badge');
        document.getElementById('dns-status').textContent = dns.status;
        document.getElementById('dns-socket').textContent = dns.socket;
        document.getElementById('dns-forward').textContent = dns.forward;

        if (dns.status === 'Running') {
            dnsBadge.textContent = 'Active';
            dnsBadge.className = 'badge badge-active';
            document.getElementById('dns-disabled-note').style.display = 'none';
            document.getElementById('dns-restart-notice').style.display = 'none';
            if (dns.system_dns_active) {
                // System DNS is already pointing to us
                document.getElementById('dns-connected').style.display = 'block';
                document.getElementById('dns-guide').style.display = 'none';
            } else {
                // Show setup instructions
                document.getElementById('dns-connected').style.display = 'none';
                document.getElementById('dns-guide').style.display = 'block';
            }
            // Set the IP from the socket (strip port)
            var guideIp = document.getElementById('dns-guide-ip');
            if (guideIp) guideIp.textContent = dns.socket.split(':')[0] || '127.0.0.1';
        } else if (dns.status === 'Disabled') {
            dnsBadge.textContent = 'Off';
            dnsBadge.className = 'badge';
            document.getElementById('dns-connected').style.display = 'none';
            document.getElementById('dns-guide').style.display = 'none';
            document.getElementById('dns-disabled-note').style.display = 'block';
            // Don't hide restart notice here — let it show if just toggled
        } else {
            dnsBadge.textContent = 'Not Found';
            dnsBadge.className = 'badge badge-warning';
            document.getElementById('dns-connected').style.display = 'none';
            document.getElementById('dns-guide').style.display = 'none';
            document.getElementById('dns-disabled-note').style.display = 'none';
            // Don't hide restart notice here — let it show if just toggled
        }

        // HTTP Proxy Panel
        var proxy = data.proxy;
        var proxyBadge = document.getElementById('proxy-badge');
        document.getElementById('proxy-status').textContent = proxy.status;
        document.getElementById('proxy-port').textContent = proxy.port;
        document.getElementById('proxy-requests').textContent = proxy.requests_served;
        if (proxy.status === 'Running') {
            proxyBadge.textContent = 'Active';
            proxyBadge.className = 'badge badge-active';
        } else {
            proxyBadge.textContent = 'Off';
            proxyBadge.className = 'badge';
        }

        // Footer
        document.getElementById('last-updated').textContent =
            'Last updated: ' + new Date().toLocaleTimeString();
        } catch (e) {
            console.error('update() crashed:', e.message, e.stack);
        }
    }

    async function poll() {
        var data = await fetchStatus();
        update(data);
        // Also update homeserver status for dashboard overview card
        if (typeof loadHsStatus === 'function') {
            try { loadHsStatus(); } catch(e) {}
        }
    }

    // ========== Key Explorer ==========

    var ZBASE32 = /^[13456789abcdefghijkmnopqrstuwxyz]{52}$/i;

    function validateKey(key) {
        var cleaned = key.replace(/^pk:/i, '').trim();
        if (cleaned.length === 0) return { valid: false, error: 'Please enter a public key' };
        if (cleaned.length !== 52) return { valid: false, error: 'Public key must be exactly 52 characters (got ' + cleaned.length + ')' };
        if (!ZBASE32.test(cleaned)) return { valid: false, error: 'Invalid z-base-32 encoding' };
        return { valid: true, key: cleaned };
    }

    function showExplorer(state) {
        ['explorer-results', 'explorer-empty', 'explorer-loading', 'explorer-error'].forEach(function (id) {
            var el = document.getElementById(id);
            el.classList.remove('visible');
            el.style.display = '';
        });
        if (state) {
            var el = document.getElementById(state);
            el.classList.add('visible');
        }
    }

    function saveHistory(key) {
        try {
            var history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
            history = history.filter(function (h) { return h.key !== key; });
            history.unshift({ key: key, time: Date.now() });
            if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        } catch (e) { /* ignore */ }
    }

    function renderHistory() {
        try {
            var history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
            var container = document.getElementById('explorer-history');
            var list = document.getElementById('history-list');
            if (history.length === 0) {
                container.style.display = 'none';
                return;
            }
            container.style.display = '';
            list.innerHTML = '';
            history.forEach(function (h) {
                var el = document.createElement('div');
                el.className = 'history-item';
                var ago = formatTimeAgo(h.time);
                el.innerHTML = '<span class="history-key">' + h.key + '</span><span class="history-time">' + ago + '</span>';
                el.onclick = function () {
                    document.getElementById('explorer-input').value = h.key;
                    resolveKey();
                };
                list.appendChild(el);
            });
        } catch (e) { /* ignore */ }
    }

    function formatTimeAgo(ts) {
        var diff = Math.floor((Date.now() - ts) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    function linkifyKeys(text) {
        // Match 52-char z-base-32 keys in record values
        return text.replace(/([13456789abcdefghijkmnopqrstuwxyz]{52})/gi, function (key) {
            return '<a href="#" class="link key-link" data-key="' + key + '">' + key.substring(0, 12) + '…' + key.substring(48) + '</a>';
        });
    }

    function renderRecords(data) {
        var meta = document.getElementById('explorer-meta');
        var elapsed = data.elapsed_secs;
        var elapsedStr;
        if (elapsed < 60) elapsedStr = elapsed + 's ago';
        else if (elapsed < 3600) elapsedStr = Math.floor(elapsed / 60) + 'm ago';
        else elapsedStr = Math.floor(elapsed / 3600) + 'h ago';

        meta.innerHTML =
            '<div class="meta-item"><span class="meta-label">Records</span><span class="meta-value">' + data.records.length + '</span></div>' +
            '<div class="meta-item"><span class="meta-label">Packet Size</span><span class="meta-value">' + data.compressed_size + ' / 1000 B</span></div>' +
            '<div class="meta-item"><span class="meta-label">Last Seen</span><span class="meta-value">' + elapsedStr + '</span></div>' +
            '<div class="meta-item"><span class="meta-label">Public Key</span><span class="meta-value">' + truncateId(data.public_key, 24) + '</span></div>';

        var body = document.getElementById('dns-records-body');
        body.innerHTML = '';
        data.records.forEach(function (rec) {
            var row = document.createElement('div');
            row.className = 'dns-row';
            var badgeClass = 'type-badge type-badge-' + rec.record_type;
            var valueHtml = linkifyKeys(escapeHtml(rec.value));
            row.innerHTML =
                '<span class="dns-name">' + escapeHtml(rec.name) + '</span>' +
                '<span><span class="' + badgeClass + '">' + rec.record_type + '</span></span>' +
                '<span class="dns-value" title="' + escapeHtml(rec.value) + '">' + valueHtml + '</span>' +
                '<span class="dns-ttl">' + rec.ttl + '</span>';
            body.appendChild(row);
        });

        // Make key links navigate to explorer
        body.addEventListener('click', function (e) {
            var link = e.target.closest('.key-link');
            if (link) {
                e.preventDefault();
                document.getElementById('explorer-input').value = link.dataset.key;
                resolveKey();
            }
        });
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    window.resolveKey = async function resolveKey() {
        var input = document.getElementById('explorer-input');
        var errorEl = document.getElementById('explorer-error');
        var btn = document.getElementById('explorer-btn');

        errorEl.classList.remove('visible');

        var raw = input.value;
        var result = validateKey(raw);
        if (!result.valid) {
            errorEl.textContent = result.error;
            errorEl.classList.add('visible');
            return;
        }

        var key = result.key;
        btn.disabled = true;
        btn.querySelector('span').textContent = 'Resolving…';
        showExplorer('explorer-loading');

        try {
            var res = await authFetch('/api/resolve/' + encodeURIComponent(key));
            if (res.status === 404) {
                showExplorer('explorer-empty');
                return;
            }
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var data = await res.json();

            if (!data.records || data.records.length === 0) {
                showExplorer('explorer-empty');
                return;
            }

            renderRecords(data);
            showExplorer('explorer-results');

            // Show pubky URI bar
            var uriBar = document.getElementById('explorer-uri-bar');
            var uriVal = document.getElementById('explorer-pubky-uri');
            if (uriBar && uriVal) {
                uriVal.textContent = 'pubky://' + key + '/';
                uriBar.style.display = '';
            }

            saveHistory(key);
            renderHistory();
        } catch (e) {
            errorEl.textContent = 'Failed to resolve: ' + e.message;
            errorEl.classList.add('visible');
            showExplorer('explorer-error');
        } finally {
            btn.disabled = false;
            btn.querySelector('span').textContent = 'Resolve';
        }
    };

    // ========== Watchlist CRUD ==========

    async function fetchWatchlistKeys() {
        try {
            var res = await authFetch('/api/watchlist');
            if (!res.ok) return;
            var data = await res.json();
            renderWatchlistKeys(data.keys);
        } catch (e) { /* ignore */ }
    }

    function renderWatchlistKeys(keys) {
        var container = document.getElementById('watchlist-keys');
        container.innerHTML = '';
        if (!keys || keys.length === 0) {
            container.innerHTML = '<div class="empty-state">No keys — add one above to start watching</div>';
            return;
        }
        keys.forEach(function (key) {
            var el = document.createElement('div');
            el.className = 'watchlist-key';
            el.innerHTML = '<span class="key-label" title="Click to copy">' + key + '</span>' +
                '<button class="copy-btn copy-btn-sm" title="Copy key" data-copy="' + key + '">' +
                '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                '<rect x="9" y="9" width="13" height="13" rx="2"/>' +
                '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
                '</svg>' +
                '</button>' +
                '<button class="key-remove" title="Remove" data-key="' + key + '">×</button>';
            container.appendChild(el);
        });
    }

    async function addWatchlistKey() {
        var input = document.getElementById('watchlist-input');
        var errorEl = document.getElementById('watchlist-error');
        var key = input.value.trim();
        errorEl.classList.remove('visible');

        if (!key) return;

        try {
            var res = await authFetch('/api/watchlist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: key }),
            });
            if (!res.ok) {
                var errText = await res.text();
                errorEl.textContent = errText;
                errorEl.classList.add('visible');
                return;
            }
            var data = await res.json();
            input.value = '';
            renderWatchlistKeys(data.keys);
        } catch (e) {
            errorEl.textContent = 'Failed: ' + e.message;
            errorEl.classList.add('visible');
        }
    }

    async function removeWatchlistKey(key) {
        try {
            var res = await authFetch('/api/watchlist/' + encodeURIComponent(key), {
                method: 'DELETE',
            });
            if (!res.ok) return;
            var data = await res.json();
            renderWatchlistKeys(data.keys);
        } catch (e) { /* ignore */ }
    }

    // ========== Init ==========

    async function initDashboard() {
        initTabs();
        poll();
        setInterval(poll, POLL_INTERVAL);
        fetchWatchlistKeys();
        initEventListeners();

        // ── Post-login: check vault state and decide what to show ──
        try {
            var res = await authFetch('/api/vault/status');
            if (res.ok) {
                var vdata = await res.json();
                if (!vdata.exists) {
                    // No vault — show onboarding in CREATE mode
                    var overlay = document.getElementById('unified-onboarding-overlay');
                    if (overlay) overlay.style.display = 'flex';
                    var btn = document.getElementById('unified-vault-btn');
                    if (btn) {
                        btn.dataset.mode = 'create';
                        btn.textContent = 'Secure Vault & Continue';
                        document.getElementById('unified-vault-confirm-wrap').style.display = 'block';
                    }
                    unifiedShowStep(2);
                    return;
                } else if (!vdata.unlocked) {
                    // Vault exists but locked — show step 2 in UNLOCK mode
                    var overlay = document.getElementById('unified-onboarding-overlay');
                    if (overlay) overlay.style.display = 'flex';
                    
                    document.getElementById('onboard-vault-title').textContent = 'Unlock Vault';
                    document.getElementById('onboard-vault-desc').textContent = 'Enter your vault password to continue setup.';
                    document.getElementById('unified-vault-confirm-wrap').style.display = 'none'; // hide confirm
                    
                    var btn = document.getElementById('unified-vault-btn');
                    if (btn) {
                        btn.dataset.mode = 'unlock';
                        btn.textContent = 'Unlock Vault & Continue';
                    }
                    unifiedShowStep(2);
                    return;
                }
                
                // Vault exists & unlocked — check homeserver status
                var hsRes = await authFetch('/api/homeserver/status');
                if (hsRes.ok) {
                    var hsData = await hsRes.json();
                    if (hsData.state === 'stopped') {
                        // Homeserver not running — show launch overlay
                        var overlay = document.getElementById('unified-onboarding-overlay');
                        if (overlay) overlay.style.display = 'flex';
                        unifiedShowStep(3);
                        return;
                    }
                }
            }
        } catch (e) {
            console.error('Failed to check vault status:', e);
        }
        
        // Everything is running, make sure overlay is hidden
        var overlay = document.getElementById('unified-onboarding-overlay');
        if (overlay) overlay.style.display = 'none';
    }

    // Start auth check — initDashboard() called after successful login/setup
    checkAuthSetup();

    function initEventListeners() {

        // Explorer: Resolve button click
        document.getElementById('explorer-btn')?.addEventListener('click', function () {
            resolveKey();
        });

        // Explorer: Enter key
        document.getElementById('explorer-input')?.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                resolveKey();
            }
        });

        // Help tooltip guide links (delegated)
        document.addEventListener('click', function (e) {
            var link = e.target.closest('[data-action="guide"]');
            if (link) {
                var guideTab = document.querySelector('[data-tab=guide]');
                if (guideTab) guideTab.click();
            }
        });

        // Watchlist: Add button + Enter key
        document.getElementById('watchlist-add-btn')?.addEventListener('click', addWatchlistKey);
        document.getElementById('watchlist-input')?.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addWatchlistKey();
            }
        });

        // Watchlist: Remove + Copy (delegated)
        document.getElementById('watchlist-keys')?.addEventListener('click', function (e) {
            var removeBtn = e.target.closest('.key-remove');
            if (removeBtn) {
                removeWatchlistKey(removeBtn.dataset.key);
                return;
            }
            var copyBtn = e.target.closest('.copy-btn');
            if (copyBtn) {
                var text = copyBtn.dataset.copy;
                navigator.clipboard.writeText(text).then(function () {
                    copyBtn.classList.add('copied');
                    setTimeout(function () { copyBtn.classList.remove('copied'); }, 1500);
                });
            }
        });

        // Relay: Copy URL
        document.getElementById('relay-copy')?.addEventListener('click', function () {
            var url = document.getElementById('relay-url').textContent;
            var btn = this;
            navigator.clipboard.writeText(url).then(function () {
                btn.classList.add('copied');
                btn.title = 'Copied!';
                setTimeout(function () {
                    btn.classList.remove('copied');
                    btn.title = 'Copy relay URL';
                }, 1500);
            });
        });

        // PKDNS: Enable/Disable toggle
        async function toggleDns(enabled) {
            try {
                var res = await authFetch('/api/dns/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: enabled }),
                });
                if (res.ok) {
                    document.getElementById('dns-guide').style.display = 'none';
                    document.getElementById('dns-disabled-note').style.display = 'none';
                    document.getElementById('dns-restart-notice').style.display = 'block';
                }
            } catch (e) { /* ignore */ }
        }

        document.getElementById('dns-enable-btn')?.addEventListener('click', function () {
            toggleDns(true);
        });
        document.getElementById('dns-disable-btn')?.addEventListener('click', function () {
            toggleDns(false);
        });

        // Set System DNS
        async function setSystemDns(endpoint, feedbackId) {
            var feedback = document.getElementById(feedbackId || 'dns-system-feedback');
            feedback.style.display = 'block';
            feedback.className = 'dns-system-feedback';
            feedback.textContent = 'Waiting for admin password...';
            try {
                var res = await authFetch('/api/dns/' + endpoint, { method: 'POST' });
                if (res.ok) {
                    var data = await res.json();
                    feedback.className = 'dns-system-feedback success';
                    feedback.textContent = '✓ ' + data.message;
                } else {
                    var err = await res.text();
                    feedback.className = 'dns-system-feedback error';
                    feedback.textContent = '✗ ' + err;
                }
            } catch (e) {
                feedback.className = 'dns-system-feedback error';
                feedback.textContent = '✗ Failed to set DNS';
            }
        }

        document.getElementById('dns-set-system-btn')?.addEventListener('click', function () {
            setSystemDns('set-system');
        });
        document.getElementById('dns-reset-system-btn')?.addEventListener('click', function () {
            setSystemDns('reset-system');
        });
        document.getElementById('dns-reset-connected-btn')?.addEventListener('click', function () {
            setSystemDns('reset-system', 'dns-connected-feedback');
        });
        document.getElementById('dns-disable-btn2')?.addEventListener('click', function () {
            toggleDns(false);
        });

        // Node Controls
        document.getElementById('node-restart-btn')?.addEventListener('click', function () {
            if (confirm('Restart Pubky Node?')) {
                authFetch('/api/node/restart', { method: 'POST' });
                document.getElementById('connection-status').querySelector('.status-label').textContent = 'Restarting...';
            }
        });
        document.getElementById('node-shutdown-btn')?.addEventListener('click', function () {
            if (confirm('Shutdown Pubky Node? You will need to start it again manually.')) {
                authFetch('/api/node/shutdown', { method: 'POST' });
                document.getElementById('connection-status').querySelector('.status-label').textContent = 'Shutting down...';
            }
        });

        // === Collapsible Guides ===
        document.getElementById('upnp-guide-toggle')?.addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });
        document.getElementById('dns-connected-toggle')?.addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });
        document.getElementById('vanity-info-toggle')?.addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });

        // === HTTP Proxy Setup ===
        document.getElementById('proxy-setup-btn')?.addEventListener('click', async function () {
            var feedback = document.getElementById('proxy-setup-feedback');
            feedback.style.display = 'block';
            feedback.textContent = 'Configuring /etc/hosts... (admin password may be required)';
            feedback.className = 'dns-system-feedback';
            try {
                var res = await authFetch('/api/proxy/setup-hosts', { method: 'POST' });
                var data = await res.json();
                if (res.ok) {
                    feedback.textContent = '✅ ' + data.message;
                    feedback.className = 'dns-system-feedback success';
                } else {
                    feedback.textContent = '❌ ' + (data || 'Failed');
                    feedback.className = 'dns-system-feedback error';
                }
            } catch (e) {
                feedback.textContent = '❌ ' + e.message;
                feedback.className = 'dns-system-feedback error';
            }
            updateProxyHostsState();
        });
        document.getElementById('proxy-reset-btn')?.addEventListener('click', async function () {
            var feedback = document.getElementById('proxy-setup-feedback');
            feedback.style.display = 'block';
            feedback.textContent = 'Resetting /etc/hosts... (admin password may be required)';
            feedback.className = 'dns-system-feedback';
            try {
                var res = await authFetch('/api/proxy/reset-hosts', { method: 'POST' });
                var data = await res.json();
                if (res.ok) {
                    feedback.textContent = '✅ ' + data.message;
                    feedback.className = 'dns-system-feedback success';
                } else {
                    feedback.textContent = '❌ ' + (data || 'Failed');
                    feedback.className = 'dns-system-feedback error';
                }
            } catch (e) {
                feedback.textContent = '❌ ' + e.message;
                feedback.className = 'dns-system-feedback error';
            }
            updateProxyHostsState();
        });

        // Check if /etc/hosts already has proxy entries
        function updateProxyHostsState() {
            authFetch('/api/proxy/hosts-status').then(function (r) { return r.json(); }).then(function (d) {
                if (d.configured) {
                    document.getElementById('proxy-setup-unconfigured').style.display = 'none';
                    document.getElementById('proxy-setup-configured').style.display = 'flex';
                } else {
                    document.getElementById('proxy-setup-unconfigured').style.display = 'flex';
                    document.getElementById('proxy-setup-configured').style.display = 'none';
                }
            }).catch(function () { });
        }
        updateProxyHostsState();

        // === Vanity Key Generator ===
        var vanityPolling = null;
        var vanityInput = document.getElementById('vanity-input');
        var vanityStartBtn = document.getElementById('vanity-start-btn');
        var vanityStopBtn = document.getElementById('vanity-stop-btn');
        var Z32_CHARS = 'ybndrfg8ejkmcpqxot1uwisza345h769';

        // Live time estimate as user types
        vanityInput.addEventListener('input', function () {
            var val = vanityInput.value.toLowerCase();
            var estimateEl = document.getElementById('vanity-estimate');
            if (!val) { estimateEl.style.display = 'none'; return; }
            // Validate z-base32
            for (var i = 0; i < val.length; i++) {
                if (Z32_CHARS.indexOf(val[i]) === -1) {
                    estimateEl.style.display = 'block';
                    estimateEl.textContent = '❌ Invalid character: "' + val[i] + '" — valid z-base32: ' + Z32_CHARS;
                    estimateEl.className = 'vanity-estimate error';
                    return;
                }
            }
            var combos = Math.pow(32, val.length);
            var timeLabels = ['Instant', 'Instant', 'Instant', 'Instant', 'Seconds', 'Minutes', 'Hours', 'Days', 'Weeks', 'Months', 'Years'];
            estimateEl.style.display = 'block';
            estimateEl.className = 'vanity-estimate';
            estimateEl.textContent = '~' + combos.toLocaleString() + ' combinations • ~' + (timeLabels[val.length] || 'Years+');
        });

        vanityStartBtn.addEventListener('click', async function () {
            var prefix = vanityInput.value.trim().toLowerCase();
            if (!prefix) return;
            var suffix = document.getElementById('vanity-suffix').checked;

            vanityStartBtn.style.display = 'none';
            vanityStopBtn.style.display = 'inline-flex';
            document.getElementById('vanity-result').style.display = 'none';
            document.getElementById('vanity-progress').style.display = 'block';
            document.getElementById('vanity-badge').textContent = 'Grinding';
            document.getElementById('vanity-badge').className = 'badge badge-warning';

            try {
                await authFetch('/api/keys/vanity/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prefix: prefix, suffix: suffix })
                });
            } catch (e) { /* ignore */ }

            // Start polling
            if (vanityPolling) clearInterval(vanityPolling);
            vanityPolling = setInterval(pollVanity, 500);
        });

        vanityStopBtn.addEventListener('click', async function () {
            if (vanityPolling) { clearInterval(vanityPolling); vanityPolling = null; }
            await authFetch('/api/keys/vanity/stop', { method: 'POST' });
            vanityStartBtn.style.display = 'inline-flex';
            vanityStopBtn.style.display = 'none';
            document.getElementById('vanity-progress').style.display = 'none';
            document.getElementById('vanity-badge').textContent = 'Stopped';
            document.getElementById('vanity-badge').className = 'badge';
        });

        async function pollVanity() {
            try {
                var res = await authFetch('/api/keys/vanity/status');
                var data = await res.json();

                document.getElementById('vanity-keys-checked').textContent = data.keys_checked.toLocaleString() + ' keys';
                document.getElementById('vanity-rate').textContent = Math.round(data.rate).toLocaleString() + ' keys/s';
                document.getElementById('vanity-elapsed').textContent = data.elapsed_secs.toFixed(1) + 's';

                // Progress bar (approximate)
                var total = Math.pow(32, data.target.length);
                var pct = Math.min(100, (data.keys_checked / total) * 100);
                document.getElementById('vanity-progress-fill').style.width = pct + '%';

                if (data.result) {
                    clearInterval(vanityPolling);
                    vanityPolling = null;
                    document.getElementById('vanity-progress').style.display = 'none';
                    document.getElementById('vanity-result').style.display = 'block';
                    document.getElementById('vanity-pubkey').textContent = data.result.pubkey;
                    document.getElementById('vanity-seed').textContent = data.result.seed;
                    vanityStartBtn.style.display = 'inline-flex';
                    vanityStopBtn.style.display = 'none';
                    document.getElementById('vanity-badge').textContent = 'Found!';
                    document.getElementById('vanity-badge').className = 'badge badge-active';
                }

                if (!data.running && !data.result) {
                    clearInterval(vanityPolling);
                    vanityPolling = null;
                    vanityStartBtn.style.display = 'inline-flex';
                    vanityStopBtn.style.display = 'none';
                    document.getElementById('vanity-progress').style.display = 'none';
                    document.getElementById('vanity-badge').textContent = 'Ready';
                    document.getElementById('vanity-badge').className = 'badge';
                }
            } catch (e) { /* ignore */ }
        }

        // Copy buttons for vanity result
        document.getElementById('vanity-copy-pubkey')?.addEventListener('click', function () {
            navigator.clipboard.writeText(document.getElementById('vanity-pubkey').textContent);
            this.title = 'Copied!';
            setTimeout(function () { document.getElementById('vanity-copy-pubkey').title = 'Copy public key'; }, 1500);
        });
        document.getElementById('vanity-copy-seed')?.addEventListener('click', function () {
            navigator.clipboard.writeText(document.getElementById('vanity-seed').textContent);
            this.title = 'Copied!';
            setTimeout(function () { document.getElementById('vanity-copy-seed').title = 'Copy seed'; }, 1500);
        });

        // Save vanity key to vault
        document.getElementById('vanity-save-vault-btn')?.addEventListener('click', async function () {
            var pubkey = document.getElementById('vanity-pubkey').textContent;
            var seed = document.getElementById('vanity-seed').textContent;
            if (!pubkey || pubkey === '--' || !seed || seed === '--') return;

            // Convert z-base-32 seed to hex
            var seedHex = normalizeSecretKey(seed);
            if (!seedHex) { this.textContent = 'Invalid seed format'; return; }

            this.disabled = true;
            this.textContent = 'Saving...';

            try {
                var res = await authFetch('/api/vault/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: 'Vanity: ' + pubkey.slice(0, 8) + '...',
                        secret_hex: seedHex,
                        pubkey: pubkey,
                        key_type: 'vanity'
                    })
                });
                var data = await res.json();
                if (data.success) {
                    this.textContent = '✅ Saved!';
                    // Refresh vault if unlocked
                    if (typeof loadVaultKeys === 'function') loadVaultKeys();
                } else {
                    this.textContent = data.error || 'Failed';
                }
            } catch (e) {
                this.textContent = 'Error';
            }

            var btn = this;
            setTimeout(function () {
                btn.disabled = false;
                btn.textContent = '💾 Save to Vault';
            }, 3000);
        });

        // ========== PKARR Publisher ==========

        var publisherRecordsEl = document.getElementById('publisher-records');
        var publisherRecordCount = 0;

        function addPublisherRecord(type, name, value, ttl) {
            publisherRecordCount++;
            var id = publisherRecordCount;
            var row = document.createElement('div');
            row.className = 'publisher-record-row';
            row.id = 'pub-record-' + id;
            row.innerHTML =
                '<select class="pub-rec-type">' +
                '<option value="HTTPS"' + (type === 'HTTPS' ? ' selected' : '') + '>HTTPS</option>' +
                '<option value="A"' + (type === 'A' ? ' selected' : '') + '>A</option>' +
                '<option value="AAAA"' + (type === 'AAAA' ? ' selected' : '') + '>AAAA</option>' +
                '<option value="CNAME"' + (type === 'CNAME' ? ' selected' : '') + '>CNAME</option>' +
                '<option value="TXT"' + (type === 'TXT' ? ' selected' : '') + '>TXT</option>' +
                '</select>' +
                '<input type="text" placeholder="name" value="' + (name || '') + '" class="pub-rec-name">' +
                '<input type="text" placeholder="value" value="' + (value || '') + '" class="pub-rec-value">' +
                '<input type="number" placeholder="TTL" value="' + (ttl || '3600') + '" class="pub-rec-ttl">' +
                '<button class="btn-sm pub-rec-remove" data-id="' + id + '">✕</button>';
            publisherRecordsEl.appendChild(row);
        }

        // --- Vault key dropdown ---
        async function loadPublisherVaultKeys() {
            var sel = document.getElementById('publisher-vault-select');
            try {
                var resp = await authFetch('/api/vault/keys');
                if (!resp.ok) {
                    sel.innerHTML = '<option value="">Vault locked — unlock or use Manual</option>';
                    return;
                }
                var data = await resp.json();
                var keys = data.keys || [];
                sel.innerHTML = '<option value="">— Select a vault key (' + keys.length + ') —</option>';
                keys.forEach(function (k) {
                    var label = (k.name || 'Unnamed') + ' — ' + (k.pubkey || '').slice(0, 12) + '…';
                    var opt = document.createElement('option');
                    opt.value = k.pubkey;
                    opt.textContent = label;
                    sel.appendChild(opt);
                });
            } catch (e) {
                sel.innerHTML = '<option value="">No vault — use Manual</option>';
            }
        }
        // Load on init and after vault changes
        loadPublisherVaultKeys();

        // --- Source tab switching ---
        document.querySelectorAll('.pub-source-tab').forEach(function (tab) {
            tab.addEventListener('click', function () {
                document.querySelectorAll('.pub-source-tab').forEach(function (t) { t.classList.remove('active'); });
                this.classList.add('active');
                var source = this.dataset.source;
                document.getElementById('pub-source-vault').style.display = source === 'vault' ? '' : 'none';
                document.getElementById('pub-source-manual').style.display = source === 'manual' ? '' : 'none';
            });
        });

        // --- Get active key source ---
        function getPublisherKeySource() {
            var active = document.querySelector('.pub-source-tab.active');
            return active ? active.dataset.source : 'vault';
        }

        // Preset buttons
        document.querySelectorAll('.publisher-preset-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                document.querySelectorAll('.publisher-preset-btn').forEach(function (b) { b.classList.remove('active'); });
                this.classList.add('active');
                publisherRecordsEl.innerHTML = '';
                publisherRecordCount = 0;
                var preset = this.dataset.preset;
                if (preset === 'homeserver') {
                    addPublisherRecord('HTTPS', '_pubky', 'homeserver.pubky.app', '3600');
                } else {
                    addPublisherRecord('A', '@', '', '3600');
                }
            });
        });

        // Add record button
        document.getElementById('publisher-add-record')?.addEventListener('click', function () {
            addPublisherRecord('A', '@', '', '3600');
        });

        // Remove record (delegated)
        publisherRecordsEl.addEventListener('click', function (e) {
            var btn = e.target.closest('.pub-rec-remove');
            if (btn) {
                var row = document.getElementById('pub-record-' + btn.dataset.id);
                if (row) row.remove();
            }
        });

        // Generate keypair → save to vault → select it
        document.getElementById('publisher-generate-key')?.addEventListener('click', async function () {
            var bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            var hex = Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');

            var statusEl = document.getElementById('publisher-status');
            statusEl.style.display = 'block';
            statusEl.style.background = 'rgba(99,102,241,0.15)';
            statusEl.style.color = '#a5b4fc';
            statusEl.textContent = '⏳ Generating key and saving to vault...';

            // Publish a dummy packet to get the public key from the server
            try {
                var resp = await authFetch('/api/publish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        secret_key: hex,
                        records: [{ type: 'TXT', name: '_generated', value: 'temp', ttl: 300 }],
                        add_to_watchlist: false
                    })
                });
                var data = await resp.json();
                if (data.public_key) {
                    // Save to vault
                    await authFetch('/api/vault/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: 'PKARR: ' + data.public_key.slice(0, 8) + '...',
                            secret_hex: hex,
                            pubkey: data.public_key,
                            key_type: 'pkarr'
                        })
                    });
                    // Reload dropdown and select the new key
                    await loadPublisherVaultKeys();
                    document.getElementById('publisher-vault-select').value = data.public_key;
                    // Switch to vault tab
                    document.querySelectorAll('.pub-source-tab').forEach(function (t) { t.classList.remove('active'); });
                    document.querySelector('.pub-source-tab[data-source="vault"]').classList.add('active');
                    document.getElementById('pub-source-vault').style.display = '';
                    document.getElementById('pub-source-manual').style.display = 'none';
                    statusEl.style.background = 'rgba(34,197,94,0.15)';
                    statusEl.style.color = '#4ade80';
                    statusEl.textContent = '✅ Key generated and saved to vault: ' + data.public_key.slice(0, 16) + '…';
                } else {
                    throw new Error('No public key returned');
                }
            } catch (e) {
                // Fallback: put in manual field
                document.getElementById('publisher-secret-key').value = hex;
                document.getElementById('publisher-secret-key').type = 'text';
                document.querySelectorAll('.pub-source-tab').forEach(function (t) { t.classList.remove('active'); });
                document.querySelector('.pub-source-tab[data-source="manual"]').classList.add('active');
                document.getElementById('pub-source-vault').style.display = 'none';
                document.getElementById('pub-source-manual').style.display = '';
                statusEl.style.background = 'rgba(245,158,11,0.15)';
                statusEl.style.color = '#fbbf24';
                statusEl.textContent = '⚠ Key generated (vault unavailable). Copy and save this key!';
            }
        });

        // Toggle key visibility
        document.getElementById('publisher-toggle-key')?.addEventListener('click', function () {
            var inp = document.getElementById('publisher-secret-key');
            inp.type = inp.type === 'password' ? 'text' : 'password';
        });

        // Publish to DHT
        document.getElementById('publisher-submit-btn')?.addEventListener('click', async function () {
            var statusEl = document.getElementById('publisher-status');
            var badge = document.getElementById('publisher-badge');
            var source = getPublisherKeySource();
            var secretHex = null;

            if (source === 'vault') {
                // Get secret from vault via export
                var pubkey = document.getElementById('publisher-vault-select').value;
                if (!pubkey) {
                    statusEl.style.display = 'block';
                    statusEl.style.background = 'rgba(239,68,68,0.15)';
                    statusEl.style.color = '#f87171';
                    statusEl.textContent = '❌ Select a key from the vault dropdown.';
                    return;
                }
                try {
                    var expResp = await authFetch('/api/vault/export', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pubkey: pubkey })
                    });
                    var expData = await expResp.json();
                    if (!expResp.ok || !expData.secret_hex) {
                        throw new Error(expData.error || 'Failed to export key');
                    }
                    secretHex = expData.secret_hex;
                } catch (e) {
                    statusEl.style.display = 'block';
                    statusEl.style.background = 'rgba(239,68,68,0.15)';
                    statusEl.style.color = '#f87171';
                    statusEl.textContent = '❌ Vault export failed: ' + e.message;
                    return;
                }
            } else {
                // Manual key
                var raw = document.getElementById('publisher-secret-key').value.trim();
                secretHex = normalizeSecretKey(raw);
                if (!secretHex) {
                    statusEl.style.display = 'block';
                    statusEl.style.background = 'rgba(239,68,68,0.15)';
                    statusEl.style.color = '#f87171';
                    statusEl.textContent = '❌ Invalid key format. Accepts hex (64/128 chars) or z-base-32.';
                    return;
                }
            }

            // Collect records
            var rows = publisherRecordsEl.querySelectorAll('.publisher-record-row');
            if (rows.length === 0) {
                statusEl.style.display = 'block';
                statusEl.style.background = 'rgba(239,68,68,0.15)';
                statusEl.style.color = '#f87171';
                statusEl.textContent = '❌ Add at least one record';
                return;
            }

            var records = [];
            for (var i = 0; i < rows.length; i++) {
                var row = rows[i];
                records.push({
                    type: row.querySelector('.pub-rec-type').value,
                    name: row.querySelector('.pub-rec-name').value.trim(),
                    value: row.querySelector('.pub-rec-value').value.trim(),
                    ttl: parseInt(row.querySelector('.pub-rec-ttl').value) || 3600
                });
            }

            var addToWatchlist = document.getElementById('publisher-add-watchlist').checked;

            // Update UI
            this.disabled = true;
            this.textContent = '⏳ Publishing...';
            badge.textContent = 'Publishing';
            badge.className = 'badge badge-warn';
            statusEl.style.display = 'block';
            statusEl.style.background = 'rgba(99,102,241,0.15)';
            statusEl.style.color = '#a5b4fc';
            statusEl.textContent = '⏳ Signing and publishing to DHT...';

            try {
                var resp = await authFetch('/api/publish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        secret_key: secretHex,
                        records: records,
                        add_to_watchlist: addToWatchlist
                    })
                });
                var data = await resp.json();

                if (resp.ok && data.success) {
                    statusEl.style.background = 'rgba(34,197,94,0.15)';
                    statusEl.style.color = '#4ade80';
                    statusEl.textContent = '✅ ' + data.message;
                    badge.textContent = 'Published';
                    badge.className = 'badge badge-success';

                    // Refresh watchlist
                    if (addToWatchlist) {
                        fetchWatchlistKeys();
                    }

                    // Clear manual secret key for security
                    if (source === 'manual') {
                        document.getElementById('publisher-secret-key').value = '';
                        document.getElementById('publisher-secret-key').type = 'password';
                    }

                    // Show success feedback with pubky URI
                    var pubkey = data.public_key || '';
                    if (pubkey) {
                        var feedbackEl = document.getElementById('publisher-success-feedback');
                        var uriEl = document.getElementById('publisher-pubky-uri');
                        if (feedbackEl && uriEl) {
                            uriEl.textContent = 'pubky://' + pubkey + '/';
                            feedbackEl.style.display = '';
                            feedbackEl._pubkey = pubkey;
                        }
                    }
                } else {
                    throw new Error(data.message || JSON.stringify(data));
                }
            } catch (e) {
                statusEl.style.background = 'rgba(239,68,68,0.15)';
                statusEl.style.color = '#f87171';
                statusEl.textContent = '❌ ' + (e.message || 'Publish failed');
                badge.textContent = 'Error';
                badge.className = 'badge badge-error';
            }

            this.disabled = false;
            this.textContent = '🚀 Sign & Publish to DHT';
            setTimeout(function () {
                badge.textContent = 'Ready';
                badge.className = 'badge';
            }, 5000);
        });

        // Initialize with homeserver preset
        addPublisherRecord('HTTPS', '_pubky', 'homeserver.pubky.app', '3600');

        renderHistory();

        // ========== Settings Tab ==========

        // Load settings info
        async function loadSettings() {
            try {
                var res = await authFetch('/api/settings');
                if (!res.ok) return;
                var data = await res.json();
                document.getElementById('settings-data-dir').textContent = data.data_dir || '—';
                document.getElementById('settings-config-file').textContent = data.config_file || '—';
                document.getElementById('settings-auth-file').textContent = data.auth_file || '—';
                document.getElementById('settings-port').textContent = data.dashboard_port || '9090';
                document.getElementById('settings-platform').textContent =
                    (data.platform || 'unknown') + ' / ' + (data.arch || 'unknown');
            } catch (e) { /* ignore */ }

            // Version from status data
            try {
                var statusRes = await authFetch('/api/status');
                if (statusRes.ok) {
                    var statusData = await statusRes.json();
                    document.getElementById('settings-version').textContent = 'v' + (statusData.version || '0.0.0');
                }
            } catch (e) { /* ignore */ }
        }
        loadSettings();

        // Change password handler
        document.getElementById('settings-change-pw-btn')?.addEventListener('click', async function () {
            var currentPw = document.getElementById('settings-current-pw').value;
            var newPw = document.getElementById('settings-new-pw').value;
            var confirmPw = document.getElementById('settings-confirm-pw').value;
            var feedback = document.getElementById('settings-pw-feedback');
            feedback.textContent = '';
            feedback.className = 'settings-feedback';

            if (!currentPw) {
                feedback.textContent = 'Enter your current password.';
                feedback.className = 'settings-feedback error';
                return;
            }
            if (newPw.length < 4) {
                feedback.textContent = 'New password must be at least 4 characters.';
                feedback.className = 'settings-feedback error';
                return;
            }
            if (newPw !== confirmPw) {
                feedback.textContent = 'New passwords do not match.';
                feedback.className = 'settings-feedback error';
                return;
            }

            this.disabled = true;
            this.textContent = 'Changing...';

            try {
                var res = await authFetch('/api/auth/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        current_password: currentPw,
                        new_password: newPw
                    })
                });
                var data = await res.json();
                if (data.success) {
                    // Update the stored password for future API calls
                    _authPassword = newPw;
                    feedback.textContent = '✅ Password changed successfully.';
                    feedback.className = 'settings-feedback success';
                    document.getElementById('settings-current-pw').value = '';
                    document.getElementById('settings-new-pw').value = '';
                    document.getElementById('settings-confirm-pw').value = '';
                } else {
                    feedback.textContent = data.error || 'Failed to change password.';
                    feedback.className = 'settings-feedback error';
                }
            } catch (e) {
                feedback.textContent = 'Network error: ' + e.message;
                feedback.className = 'settings-feedback error';
            }

            this.disabled = false;
            this.textContent = '🔄 Change Password';
        });

        // ========== Key Vault ==========

        async function loadVaultStatus() {
            try {
                var res = await authFetch('/api/vault/status');
                if (!res.ok) return;
                var data = await res.json();
                var badge = document.getElementById('vault-badge');
                var createEl = document.getElementById('vault-create');
                var lockedEl = document.getElementById('vault-locked');
                var unlockedEl = document.getElementById('vault-unlocked');
                var addForm = document.getElementById('vault-add-form');

                createEl.style.display = 'none';
                lockedEl.style.display = 'none';
                unlockedEl.style.display = 'none';
                addForm.style.display = 'none';

                if (!data.exists) {
                    createEl.style.display = 'block';
                    badge.textContent = 'No Vault';
                    badge.className = 'badge';
                    updateSidebarVaultWidget('none');
                } else if (!data.unlocked) {
                    lockedEl.style.display = 'block';
                    badge.textContent = 'Locked';
                    badge.className = 'badge badge-warning';
                    updateSidebarVaultWidget('locked');
                } else {
                    unlockedEl.style.display = 'block';
                    badge.textContent = 'Unlocked';
                    badge.className = 'badge badge-green';
                    updateSidebarVaultWidget('unlocked');
                    loadVaultKeys();
                }
            } catch (e) { /* ignore */ }
        }

        function updateSidebarVaultWidget(state) {
            var widget = document.getElementById('sidebar-vault-widget');
            var icon = document.getElementById('sidebar-vault-icon');
            var text = document.getElementById('sidebar-vault-text');
            if (!widget) return;

            if (state === 'none') {
                widget.className = 'vault-widget';
                text.textContent = 'No Vault';
            } else if (state === 'locked') {
                widget.className = 'vault-widget locked';
                text.textContent = 'Vault Locked';
                icon.innerHTML = '<rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />';
            } else if (state === 'unlocked') {
                widget.className = 'vault-widget unlocked';
                text.textContent = 'Vault Unlocked';
                icon.innerHTML = '<rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /><path d="M12 11v4" stroke-width="2" stroke-linecap="round"/>';
            }
        }

        document.getElementById('sidebar-vault-widget')?.addEventListener('click', function() {
            if (window._switchToTab) window._switchToTab('vault');
        });

        async function loadVaultKeys() {
            try {
                var res = await authFetch('/api/vault/keys');
                if (!res.ok) return;
                var data = await res.json();
                renderVaultKeys(data.keys || []);
            } catch (e) { /* ignore */ }
        }

        function renderVaultKeys(keys) {
            var list = document.getElementById('vault-keys-list');
            var empty = document.getElementById('vault-empty');
            list.innerHTML = '';

            if (keys.length === 0) {
                empty.style.display = 'block';
                return;
            }
            empty.style.display = 'none';

            keys.forEach(function (k) {
                var item = document.createElement('div');
                item.className = 'vault-key-item';

                var truncPk = k.pubkey.length > 16 ? k.pubkey.slice(0, 8) + '...' + k.pubkey.slice(-8) : k.pubkey;

                item.innerHTML = [
                    '<div class="vault-key-info">',
                    '  <div class="vault-key-meta">',
                    '    <span class="vault-key-name" data-pk="' + k.pubkey + '" title="Click to rename" style="cursor:pointer;">' + escapeHtml(k.name) + '</span>',
                    '    <span class="vault-key-type ' + k.key_type + '">' + k.key_type + '</span>',
                    '  </div>',
                    '  <span class="vault-key-pubkey" title="' + k.pubkey + '">' + truncPk + '</span>',
                    '</div>',
                    '<div class="vault-key-actions">',
                    '  <button class="vault-copy-btn" data-pk="' + k.pubkey + '" title="Copy pubkey">📋</button>',
                    '  <button class="vault-export-btn" data-pk="' + k.pubkey + '" title="Export secret">🔑</button>',
                    '  <button class="vault-delete-btn danger" data-pk="' + k.pubkey + '" data-name="' + escapeHtml(k.name) + '" title="Delete">🗑</button>',
                    '</div>'
                ].join('');
                list.appendChild(item);
            });

            // Inline rename on click
            list.querySelectorAll('.vault-key-name').forEach(function (span) {
                span.addEventListener('click', function () {
                    var pk = this.dataset.pk;
                    var oldName = this.textContent;
                    var input = document.createElement('input');
                    input.type = 'text';
                    input.value = oldName;
                    input.className = 'vault-rename-input';
                    input.maxLength = 40;
                    this.replaceWith(input);
                    input.focus();
                    input.select();

                    async function saveRename() {
                        var newName = input.value.trim();
                        if (!newName || newName === oldName) {
                            loadVaultKeys();
                            return;
                        }
                        try {
                            await authFetch('/api/vault/rename', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ pubkey: pk, name: newName })
                            });
                        } catch (e) { /* ignore */ }
                        loadVaultKeys();
                    }

                    input.addEventListener('blur', saveRename);
                    input.addEventListener('keydown', function (e) {
                        if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
                        if (e.key === 'Escape') { input.value = oldName; input.blur(); }
                    });
                });
            });

            // Copy pubkey
            list.querySelectorAll('.vault-copy-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    navigator.clipboard.writeText(this.dataset.pk);
                    this.textContent = '✅';
                    var b = this;
                    setTimeout(function () { b.textContent = '📋'; }, 1500);
                });
            });

            list.querySelectorAll('.vault-export-btn').forEach(function (btn) {
                btn.addEventListener('click', async function () {
                    try {
                        var res = await authFetch('/api/vault/export', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pubkey: this.dataset.pk })
                        });
                        var data = await res.json();
                        if (data.secret_hex) {
                            openRingExportModal(data.secret_hex);
                        }
                    } catch (e) { /* ignore */ }
                });
            });

            list.querySelectorAll('.vault-delete-btn').forEach(function (btn) {
                btn.addEventListener('click', async function () {
                    if (!confirm('Delete key "' + this.dataset.name + '"? This cannot be undone.')) return;
                    try {
                        var res = await authFetch('/api/vault/delete/' + encodeURIComponent(this.dataset.pk), {
                            method: 'DELETE'
                        });
                        if (res.ok) loadVaultKeys();
                    } catch (e) { /* ignore */ }
                });
            });
        }

        // Export entire vault as JSON file
        document.getElementById('vault-export-all-btn')?.addEventListener('click', async function () {
            try {
                var res = await authFetch('/api/vault/export-all');
                if (!res.ok) return;
                var data = await res.json();
                var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'pubky-vault-backup.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                this.textContent = '✅ Exported';
                var btn = this;
                setTimeout(function () { btn.textContent = '📥 Export'; }, 2000);
            } catch (e) { /* ignore */ }
        });

        // Import vault from JSON file
        document.getElementById('vault-import-btn')?.addEventListener('click', function () {
            document.getElementById('vault-import-file').click();
        });
        document.getElementById('vault-import-file')?.addEventListener('change', function () {
            var file = this.files[0];
            if (!file) return;
            var reader = new FileReader();
            reader.onload = async function (e) {
                try {
                    var data = JSON.parse(e.target.result);
                    if (!data.keys || !Array.isArray(data.keys)) {
                        alert('Invalid vault backup file.');
                        return;
                    }
                    var res = await authFetch('/api/vault/import', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ keys: data.keys })
                    });
                    var result = await res.json();
                    if (result.success) {
                        alert('Imported ' + result.imported + ' key(s).');
                        loadVaultKeys();
                    } else {
                        alert(result.error || 'Import failed.');
                    }
                } catch (err) {
                    alert('Error reading file: ' + err.message);
                }
            };
            reader.readAsText(file);
            this.value = ''; // reset
        });

        function escapeHtml(str) {
            var div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        // Load vault status on init
        loadVaultStatus();

        // Create vault
        document.getElementById('vault-create-btn')?.addEventListener('click', async function () {
            var pw = document.getElementById('vault-create-pw').value;
            var confirm = document.getElementById('vault-create-confirm').value;
            var err = document.getElementById('vault-create-error');
            err.textContent = '';

            if (pw.length < 4) { err.textContent = 'Password must be at least 4 characters.'; return; }
            if (pw !== confirm) { err.textContent = 'Passwords do not match.'; return; }

            this.disabled = true;
            this.textContent = 'Creating...';

            try {
                var res = await authFetch('/api/vault/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pw })
                });
                var data = await res.json();
                if (data.success) {
                    loadVaultStatus();
                } else {
                    err.textContent = data.error || 'Failed to create vault.';
                }
            } catch (e) { err.textContent = 'Network error.'; }

            this.disabled = false;
            this.textContent = '🔐 Create Vault';
        });

        // Unlock vault
        document.getElementById('vault-unlock-btn')?.addEventListener('click', async function () {
            var pw = document.getElementById('vault-unlock-pw').value;
            var err = document.getElementById('vault-unlock-error');
            err.textContent = '';

            if (!pw) { err.textContent = 'Enter your vault password.'; return; }

            this.disabled = true;
            this.textContent = 'Unlocking...';

            try {
                var res = await authFetch('/api/vault/unlock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: pw })
                });
                var data = await res.json();
                if (data.success) {
                    document.getElementById('vault-unlock-pw').value = '';
                    loadVaultStatus();
                } else {
                    err.textContent = data.error || 'Invalid password.';
                }
            } catch (e) { err.textContent = 'Network error.'; }

            this.disabled = false;
            this.textContent = '🔓 Unlock Vault';
        });

        // Lock vault
        document.getElementById('vault-lock-btn')?.addEventListener('click', async function () {
            await authFetch('/api/vault/lock', { method: 'POST' });
            loadVaultStatus();
        });

        // Show/hide add key form
        document.getElementById('vault-add-manual-btn')?.addEventListener('click', function () {
            var form = document.getElementById('vault-add-form');
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
        });
        document.getElementById('vault-add-cancel-btn')?.addEventListener('click', function () {
            document.getElementById('vault-add-form').style.display = 'none';
        });

        // Save key to vault
        var ZBASE32_CHARS = 'ybndrfg8ejkmcpqxot1uwisza345h769';
        function zbase32ToHex(str) {
            str = str.toLowerCase();
            var bits = '';
            for (var i = 0; i < str.length; i++) {
                var idx = ZBASE32_CHARS.indexOf(str[i]);
                if (idx < 0) return null;
                bits += ('00000' + idx.toString(2)).slice(-5);
            }
            var hex = '';
            for (var i = 0; i + 7 < bits.length; i += 8) {
                hex += ('0' + parseInt(bits.slice(i, i + 8), 2).toString(16)).slice(-2);
            }
            return hex;
        }

        function isHex(s) { return /^[0-9a-fA-F]+$/.test(s); }

        function normalizeSecretKey(raw) {
            raw = raw.trim();
            // 64 or 128 hex chars — use as-is
            if ((raw.length === 64 || raw.length === 128) && isHex(raw)) return raw;
            // 52-char z-base-32 (32 bytes = Ed25519 secret key)
            if (raw.length === 52) {
                var hex = zbase32ToHex(raw);
                if (hex && hex.length === 64) return hex;
            }
            // 103-char z-base-32 (64 bytes = Ed25519 seed)
            if (raw.length === 103 || raw.length === 104) {
                var hex = zbase32ToHex(raw);
                if (hex && hex.length === 128) return hex;
            }
            return null;
        }

        document.getElementById('vault-add-save-btn')?.addEventListener('click', async function () {
            var name = document.getElementById('vault-add-name').value || 'Unnamed Key';
            var secret = document.getElementById('vault-add-secret').value;
            var pubkey = document.getElementById('vault-add-pubkey').value;
            var err = document.getElementById('vault-add-error');
            err.textContent = '';

            var secretHex = normalizeSecretKey(secret);
            if (!secretHex) { err.textContent = 'Invalid key format. Accepts: hex (64/128 chars) or z-base-32.'; return; }
            if (!pubkey) { err.textContent = 'Public key is required.'; return; }

            try {
                var res = await authFetch('/api/vault/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: name,
                        secret_hex: secretHex,
                        pubkey: pubkey,
                        key_type: 'manual'
                    })
                });
                var data = await res.json();
                if (data.success) {
                    document.getElementById('vault-add-name').value = '';
                    document.getElementById('vault-add-secret').value = '';
                    document.getElementById('vault-add-pubkey').value = '';
                    document.getElementById('vault-add-form').style.display = 'none';
                    loadVaultKeys();
                } else {
                    err.textContent = data.error || 'Failed to add key.';
                }
            } catch (e) { err.textContent = 'Network error.'; }
        });

        // Enter key support for vault forms
        document.getElementById('vault-unlock-pw')?.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') document.getElementById('vault-unlock-btn').click();
        });
        document.getElementById('vault-create-confirm')?.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') document.getElementById('vault-create-btn').click();
        });

        // ========== Homeserver Tab ==========

        // Status polling
        // Track current server pubkey for cross-referencing
        var _hsServerPubkey = null;

        async function loadHsStatus() {
            try {
                var res = await authFetch('/api/homeserver/status');
                var data = await res.json();
                var badge = document.getElementById('hs-state-badge');
                badge.textContent = data.state.charAt(0).toUpperCase() + data.state.slice(1);
                badge.className = 'badge' + (data.state === 'running' ? ' badge-success' : data.state === 'error' ? ' badge-error' : '');

                // Dashboard overview stat card
                var dashHs = document.getElementById('dash-hs-status');
                if (dashHs) {
                    if (data.state === 'running') {
                        dashHs.textContent = '● Online';
                        dashHs.style.color = 'var(--green)';
                    } else if (data.state === 'starting') {
                        dashHs.textContent = '◐ Starting…';
                        dashHs.style.color = 'var(--yellow, #eab308)';
                    } else if (data.state === 'error') {
                        dashHs.textContent = '● Error';
                        dashHs.style.color = 'var(--red)';
                    } else {
                        dashHs.textContent = '○ Stopped';
                        dashHs.style.color = 'var(--text-muted)';
                    }
                }

                var info = document.getElementById('hs-server-info');
                var startBtn = document.getElementById('hs-start-btn');
                var stopBtn = document.getElementById('hs-stop-btn');
                var changeKeyBtn = document.getElementById('hs-key-change-btn');

                // Always show key summary if we have a pubkey (even when stopped)
                _hsServerPubkey = data.pubkey || null;
                updateHsKeySummary(_hsServerPubkey);

                if (data.state === 'running') {
                    info.style.display = 'block';
                    startBtn.style.display = 'none';
                    stopBtn.style.display = 'inline-flex';
                    if (changeKeyBtn) changeKeyBtn.style.display = 'inline-flex';
                    document.getElementById('hs-pid').textContent = data.pid || '—';
                    var secs = data.uptime_secs || 0;
                    var h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
                    document.getElementById('hs-uptime').textContent = h ? h + 'h ' + m + 'm' : m + 'm ' + (secs % 60) + 's';
                    if (data.ports) {
                        document.getElementById('hs-port-icann').textContent = '127.0.0.1:' + data.ports.icann;
                        document.getElementById('hs-port-pubky').textContent = '127.0.0.1:' + data.ports.pubky;
                        document.getElementById('hs-port-admin').textContent = '127.0.0.1:' + data.ports.admin;
                    }
                    loadHsStats();
                    loadHsTunnelStatus();
                    loadHsNexusStatus();
                } else {
                    info.style.display = 'none';
                    startBtn.style.display = 'inline-flex';
                    stopBtn.style.display = 'none';
                    if (changeKeyBtn) changeKeyBtn.style.display = _hsServerPubkey ? 'inline-flex' : 'none';
                    document.getElementById('hs-stats-badge').textContent = 'Offline';
                    document.getElementById('hs-stats-badge').className = 'badge';
                    document.getElementById('hs-quickstart-btn').style.display = 'none';
                }
            } catch (e) { /* ignore */ }
        }

        // Load and display tunnel URL in the status card
        async function loadHsTunnelStatus() {
            var tunnelEl = document.getElementById('hs-tunnel-url');
            if (!tunnelEl) return;
            try {
                var res = await authFetch('/api/tunnel/status');
                var data = await res.json();
                if (data.state === 'running' && data.public_url) {
                    tunnelEl.innerHTML = '<a href="' + data.public_url + '" target="_blank" style="color:#818cf8; text-decoration:none;">' + data.public_url.replace('https://', '') + '</a>';
                } else if (data.state === 'starting') {
                    tunnelEl.textContent = '⏳ Starting…';
                } else {
                    tunnelEl.textContent = 'Not active';
                    tunnelEl.style.color = '#64748b';
                }
            } catch (e) {
                tunnelEl.textContent = '—';
            }
        }

        // Auto-check Nexus indexing status for the HS pubkey
        async function loadHsNexusStatus() {
            var nexusEl = document.getElementById('hs-nexus-status');
            if (!nexusEl || !_hsServerPubkey) return;
            try {
                var res = await authFetch('/api/profile/' + encodeURIComponent(_hsServerPubkey) + '/nexus');
                var data = await res.json();
                var prod = data.production || {};
                if (prod.indexed) {
                    nexusEl.innerHTML = '<span style="color:#4ade80;">✅ Indexed</span>';
                } else {
                    nexusEl.innerHTML = '<span style="color:#f59e0b;">⚠️ Not indexed</span>';
                }
            } catch (e) {
                nexusEl.textContent = '—';
            }
        }

        // Update the rich server key summary card
        function updateHsKeySummary(pubkey) {
            var summary = document.getElementById('hs-key-summary');
            if (!pubkey) {
                summary.style.display = 'none';
                return;
            }
            summary.style.display = 'block';

            // Truncated key display
            var truncated = pubkey.length > 20 ? pubkey.slice(0, 10) + '…' + pubkey.slice(-10) : pubkey;
            var keyDisplay = document.getElementById('hs-key-display');
            keyDisplay.textContent = truncated;
            keyDisplay.title = 'Click to copy: ' + pubkey;
            keyDisplay.onclick = function () {
                navigator.clipboard.writeText(pubkey);
                keyDisplay.textContent = '✅ Copied!';
                setTimeout(function () { keyDisplay.textContent = truncated; }, 1500);
            };

            // Copy button
            document.getElementById('hs-key-copy-btn').onclick = function () {
                navigator.clipboard.writeText(pubkey);
                this.textContent = '✅';
                var btn = this;
                setTimeout(function() { btn.textContent = '📋'; }, 1500);
            };

            // Explorer link
            var explorerLink = document.getElementById('hs-key-explorer-link');
            explorerLink.href = 'https://app.pubky.org/explorer?key=' + pubkey;

            // PKARR status — resolve via local relay
            checkPkarrStatus(pubkey);

            // Cross-reference with vault keys for label
            loadVaultKeyLabel(pubkey);
        }

        // Check PKARR publication status via local relay
        async function checkPkarrStatus(pubkey) {
            var statusEl = document.getElementById('hs-key-pkarr-status');
            try {
                var res = await fetch('http://localhost:6881/pkarr/' + pubkey);
                if (res.ok) {
                    statusEl.innerHTML = '<span style="color:#4ade80;">✅ PKARR</span>';
                } else {
                    statusEl.innerHTML = '<span style="color:#f59e0b;">⚠️ PKARR</span>';
                }
            } catch (e) {
                statusEl.innerHTML = '<span style="color:#64748b;">— PKARR</span>';
            }
        }

        // Find vault key label for server key
        async function loadVaultKeyLabel(pubkey) {
            var labelEl = document.getElementById('hs-key-label');
            try {
                var res = await authFetch('/api/vault/keys');
                if (!res.ok) {
                    labelEl.style.display = 'none';
                    return;
                }
                var data = await res.json();
                var keys = data.keys || [];
                var match = keys.find(function(k) { return k.pubkey === pubkey; });
                if (match) {
                    labelEl.textContent = '🏠 ' + match.name;
                    labelEl.style.display = 'inline-block';
                } else {
                    labelEl.textContent = '🏠 Server Key';
                    labelEl.style.display = 'inline-block';
                    labelEl.style.background = 'rgba(245,158,11,0.2)';
                    labelEl.style.color = '#fbbf24';
                }
            } catch (e) {
                labelEl.style.display = 'none';
            }
        }

        // Load stats from admin /info + our config API
        async function loadHsStats() {
            try {
                var res = await authFetch('/api/homeserver/info');
                if (!res.ok) return;
                var data = await res.json();
                var badge = document.getElementById('hs-stats-badge');
                badge.textContent = 'Connected';
                badge.className = 'badge badge-success';
                document.getElementById('hs-users').textContent = data.num_users != null ? data.num_users : (data.users_count != null ? data.users_count : '—');

                // Version and signup_mode aren't in admin /info — get from our config
                try {
                    var cfgRes = await authFetch('/api/homeserver/config');
                    if (cfgRes.ok) {
                        var cfg = await cfgRes.json();
                        document.getElementById('hs-signup-mode').textContent = cfg.signup_mode || '—';
                    }
                } catch(e) { /* ignore */ }

                // Update server key from info if available
                var pk = data.public_key || _hsServerPubkey;
                if (pk && pk !== _hsServerPubkey) {
                    _hsServerPubkey = pk;
                    updateHsKeySummary(pk);
                }

                // Show quickstart button if vault is unlocked and no users
                var userCount = data.num_users != null ? data.num_users : data.users_count;
                var qsBtn = document.getElementById('hs-quickstart-btn');
                if (qsBtn) {
                    if (userCount != null && userCount === 0) {
                        try {
                            var vRes = await authFetch('/api/vault/keys');
                            qsBtn.style.display = vRes.ok ? 'inline-flex' : 'none';
                        } catch(e) {
                            qsBtn.style.display = 'none';
                        }
                    } else {
                        qsBtn.style.display = 'none';
                    }
                }
            } catch (e) { /* ignore */ }
        }

        // ⚡ Quickstart — one-click identity
        var quickstartBtn = document.getElementById('hs-quickstart-btn');
        if (quickstartBtn) {
            quickstartBtn.addEventListener('click', async function () {
                quickstartBtn.disabled = true;
                quickstartBtn.textContent = '⏳ Creating…';
                var resultDiv = document.getElementById('hs-quickstart-result');
                var msgDiv = document.getElementById('hs-quickstart-msg');
                resultDiv.style.display = 'block';
                msgDiv.textContent = 'Generating key, signing up, publishing…';
                try {
                    var res = await authFetch('/api/quickstart', { method: 'POST' });
                    var data = await res.json();
                    if (data.success) {
                        msgDiv.innerHTML = '✅ <strong>Identity created!</strong><br>' +
                            '<span style="font-size:11px;color:#94a3b8;">Pubky: </span>' +
                            '<code style="font-size:11px;color:#6366f1;">pubky://' + data.pubkey + '</code><br>' +
                            '<span style="font-size:11px;color:#94a3b8;">Homeserver: </span>' +
                            '<code style="font-size:11px;">' + data.homeserver + '</code><br>' +
                            (data.pkarr_published ? '<span style="font-size:11px;color:#4ade80;">✅ PKARR published to DHT</span>' : '<span style="font-size:11px;color:#f59e0b;">⚠️ PKARR publish pending</span>');
                        quickstartBtn.style.display = 'none';
                        loadHsStatus();
                    } else {
                        msgDiv.innerHTML = '❌ ' + (data.error || 'Failed');
                        if (data.step === 'vault') {
                            msgDiv.innerHTML += '<br><span style="font-size:11px;">Unlock your vault first (Keys tab).</span>';
                        }
                    }
                } catch (e) {
                    msgDiv.textContent = '❌ Network error';
                }
                quickstartBtn.disabled = false;
                quickstartBtn.textContent = '⚡ Create My Identity';
            });
        }

        // Prerequisites check
        document.getElementById('hs-check-btn')?.addEventListener('click', async function () {
            this.textContent = '⏳';
            try {
                var res = await authFetch('/api/homeserver/setup-check');
                var data = await res.json();
                document.getElementById('hs-pg-status').textContent = data.postgres_ok ? '✅ ' + data.postgres_msg : '❌ ' + data.postgres_msg;
                document.getElementById('hs-pg-status').style.color = data.postgres_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-db-status').textContent = data.db_ok ? '✅ ' + data.db_msg : '❌ ' + data.db_msg;
                document.getElementById('hs-db-status').style.color = data.db_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-bin-status').textContent = data.binary_ok ? '✅ Installed' : '❌ Not found';
                document.getElementById('hs-bin-status').style.color = data.binary_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-bin-status').title = data.binary_ok ? data.binary_path : 'Binary not found. Use Fix All to build from source.';
                document.getElementById('hs-cfg-status').textContent = data.config_ok ? '✅ Ready' : '❌ Not generated';
                document.getElementById('hs-cfg-status').style.color = data.config_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-cfg-status').title = data.config_ok ? data.config_path : 'Config not generated yet.';

                // Enable/disable Start button based on binary availability
                var startBtn = document.getElementById('hs-start-btn');
                if (!data.binary_ok) {
                    startBtn.disabled = true;
                    startBtn.title = 'pubky-homeserver binary not found. Build with build-sidecars.sh or install to PATH.';
                    startBtn.textContent = '⚠️ Binary Missing';
                } else {
                    startBtn.disabled = false;
                    startBtn.title = '';
                    startBtn.textContent = '▶ Start Server';
                }
            } catch (e) { /* ignore */ }
            this.textContent = 'Check';
        });

        // Generate config
        document.getElementById('hs-gen-config-btn')?.addEventListener('click', async function () {
            try {
                var res = await authFetch('/api/homeserver/generate-config', { method: 'POST' });
                var data = await res.json();
                this.textContent = data.success ? '✅ Generated' : '❌ Failed';
                var btn = this;
                setTimeout(function () { btn.textContent = 'Generate Config'; }, 2000);
            } catch (e) { /* ignore */ }
        });

        // Start server
        document.getElementById('hs-start-btn')?.addEventListener('click', async function () {
            var msg = document.getElementById('hs-control-msg');
            this.disabled = true;
            this.textContent = '⏳ Starting...';
            msg.style.display = 'block';
            msg.textContent = 'Starting homeserver...';
            msg.style.background = 'rgba(99,102,241,0.15)';
            msg.style.color = '#a5b4fc';
            try {
                var res = await authFetch('/api/homeserver/start', { method: 'POST' });
                var data = await res.json();
                if (data.success) {
                    msg.textContent = '✅ ' + data.message;
                    msg.style.background = 'rgba(34,197,94,0.15)';
                    msg.style.color = '#4ade80';
                } else {
                    msg.textContent = '❌ ' + (data.error || 'Failed');
                    msg.style.background = 'rgba(239,68,68,0.15)';
                    msg.style.color = '#f87171';
                }
            } catch (e) {
                msg.textContent = '❌ ' + e.message;
                msg.style.background = 'rgba(239,68,68,0.15)';
                msg.style.color = '#f87171';
            }
            this.disabled = false;
            this.textContent = '▶ Start Server';
            loadHsStatus();
        });

        // Stop server
        document.getElementById('hs-stop-btn')?.addEventListener('click', async function () {
            this.disabled = true;
            try {
                await authFetch('/api/homeserver/stop', { method: 'POST' });
            } catch (e) { /* ignore */ }
            this.disabled = false;
            loadHsStatus();
        });

        // Generate signup token
        document.getElementById('hs-gen-token-btn')?.addEventListener('click', async function () {
            var display = document.getElementById('hs-token-display');
            this.textContent = '⏳';
            try {
                // Fetch token + server pubkey in parallel
                var [tokenRes, infoRes, statusRes] = await Promise.all([
                    authFetch('/api/homeserver/signup-token'),
                    authFetch('/api/homeserver/info').catch(function () { return null; }),
                    authFetch('/api/status').catch(function () { return null; }),
                ]);
                var data = await tokenRes.json();

                if (!tokenRes.ok) {
                    var errMsg = data.error || 'Homeserver returned ' + tokenRes.status;
                    document.getElementById('hs-token-value').textContent = '❌ ' + errMsg;
                    display.style.display = 'block';
                    document.getElementById('hs-invite-badge').textContent = 'Error';
                    document.getElementById('hs-invite-badge').className = 'badge badge-error';
                    this.textContent = 'Generate Token';
                    return;
                }

                if (data.token) {
                    document.getElementById('hs-token-value').textContent = data.token;
                    display.style.display = 'block';

                    // Build pubkyring://signup deeplink
                    // Format: pubkyring://signup?hs={homeserver_pubkey}&st={token}&relay={relay_url}
                    var qrContainer = document.getElementById('hs-token-qr');
                    qrContainer.innerHTML = '';
                    try {
                        var params = new URLSearchParams();
                        params.set('st', data.token);

                        // Include homeserver public key if available
                        if (infoRes && infoRes.ok) {
                            var info = await infoRes.json();
                            if (info.public_key) {
                                params.set('hs', info.public_key);
                            }
                        }

                        // Include relay URL if available
                        if (statusRes && statusRes.ok) {
                            var status = await statusRes.json();
                            if (status.relay_port) {
                                // Build relay URL from current window host + relay port
                                var relayHost = window.location.hostname || '127.0.0.1';
                                params.set('relay', 'http://' + relayHost + ':' + status.relay_port);
                            }
                        }

                        var deeplink = 'pubkyring://signup?' + params.toString();

                        // Show the full deeplink as a subtitle
                        var existing = document.getElementById('hs-signup-deeplink');
                        if (!existing) {
                            existing = document.createElement('div');
                            existing.id = 'hs-signup-deeplink';
                            existing.style.cssText = 'font-size:10px;color:#6b7280;margin-top:6px;word-break:break-all;font-family:monospace;';
                            qrContainer.parentNode.appendChild(existing);
                        }
                        existing.textContent = deeplink;

                        var qr = qrcode(0, 'M');
                        qr.addData(deeplink);
                        qr.make();
                        qrContainer.innerHTML = qr.createSvgTag(4, 0);
                    } catch (e) {
                        qrContainer.innerHTML = '<p style="color:#888;font-size:12px;">QR generation failed</p>';
                    }

                    document.getElementById('hs-invite-badge').textContent = 'Generated';
                    document.getElementById('hs-invite-badge').className = 'badge badge-success';
                } else {
                    document.getElementById('hs-token-value').textContent = '❌ No token returned. Is signup mode set to "Token Required"?';
                    display.style.display = 'block';
                    document.getElementById('hs-invite-badge').textContent = 'Error';
                    document.getElementById('hs-invite-badge').className = 'badge badge-error';
                }
            } catch (e) {
                document.getElementById('hs-token-value').textContent = '❌ ' + (e.message || 'Failed to connect to homeserver');
                display.style.display = 'block';
                document.getElementById('hs-invite-badge').textContent = 'Error';
                document.getElementById('hs-invite-badge').className = 'badge badge-error';
            }
            this.textContent = 'Generate Token';
        });

        // Copy token
        document.getElementById('hs-token-copy')?.addEventListener('click', function () {
            navigator.clipboard.writeText(document.getElementById('hs-token-value').textContent);
            this.textContent = '✅';
            var btn = this;
            setTimeout(function () { btn.textContent = '📋'; }, 1500);
        });

        // Load config into form
        async function loadHsConfig() {
            try {
                var res = await authFetch('/api/homeserver/config');
                var cfg = await res.json();
                document.getElementById('hs-cfg-db-url').value = cfg.database_url || '';
                document.getElementById('hs-cfg-signup-mode').value = cfg.signup_mode || 'token_required';
                document.getElementById('hs-cfg-admin-pw').value = cfg.admin_password || '';
                document.getElementById('hs-cfg-public-ip').value = cfg.public_ip || '';
                document.getElementById('hs-cfg-domain').value = cfg.icann_domain || '';
                document.getElementById('hs-cfg-quota').value = cfg.storage_quota_mb || 0;
            } catch (e) { /* ignore */ }
        }

        // Save config
        document.getElementById('hs-save-config-btn')?.addEventListener('click', async function () {
            var msg = document.getElementById('hs-config-msg');
            try {
                var res = await authFetch('/api/homeserver/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        database_url: document.getElementById('hs-cfg-db-url').value,
                        signup_mode: document.getElementById('hs-cfg-signup-mode').value,
                        admin_password: document.getElementById('hs-cfg-admin-pw').value,
                        public_ip: document.getElementById('hs-cfg-public-ip').value,
                        icann_domain: document.getElementById('hs-cfg-domain').value,
                        storage_quota_mb: parseInt(document.getElementById('hs-cfg-quota').value) || 0,
                    })
                });
                var data = await res.json();
                msg.textContent = data.success ? '✅ Saved' : '❌ ' + (data.error || 'Failed');
                msg.style.color = data.success ? '#4ade80' : '#f87171';
            } catch (e) {
                msg.textContent = '❌ Error';
                msg.style.color = '#f87171';
            }
            setTimeout(function () { msg.textContent = ''; }, 3000);
        });

        // Load HS status and config when tab is clicked — auto-check everything
        document.querySelector('[data-tab="homeserver"]').addEventListener('click', function () {
            loadHsStatus();
            loadHsConfig();
            onHsTabActivated();
            // Auto-run prerequisites check
            document.getElementById('hs-check-btn').click();
        });

        // ========== Ring Export Modal ==========

        function openRingExportModal(secretHex) {
            document.getElementById('export-hex-value').textContent = secretHex;

            // Generate pubkyring://migrate deeplink QR
            var deeplink = 'pubkyring://migrate?index=0&total=1&key=' + secretHex;
            var qrContainer = document.getElementById('export-qr-container');
            qrContainer.innerHTML = '';

            try {
                var qr = qrcode(0, 'M');
                qr.addData(deeplink);
                qr.make();
                qrContainer.innerHTML = qr.createSvgTag(4, 0);
            } catch (e) {
                qrContainer.innerHTML = '<p style="color:#888;font-size:12px;">QR generation failed</p>';
            }

            document.getElementById('ring-export-modal').classList.add('active');
        }

        document.getElementById('ring-export-close')?.addEventListener('click', function () {
            document.getElementById('ring-export-modal').classList.remove('active');
            document.getElementById('export-qr-container').innerHTML = '';
        });

        // Close on overlay click
        document.getElementById('ring-export-modal')?.addEventListener('click', function (e) {
            if (e.target === this) {
                this.classList.remove('active');
                document.getElementById('export-qr-container').innerHTML = '';
            }
        });

        document.getElementById('export-copy-hex')?.addEventListener('click', function () {
            var hex = document.getElementById('export-hex-value').textContent;
            navigator.clipboard.writeText(hex);
            this.textContent = '✅';
            var btn = this;
            setTimeout(function () { btn.textContent = '📋'; }, 1500);
        });

        // ─── PKARR Publish ───────────────────────────────
        var publishPkarrBtn = document.getElementById('hs-publish-pkarr-btn');
        var publishPkarrMsg = document.getElementById('hs-publish-pkarr-msg');
        if (publishPkarrBtn) {
            publishPkarrBtn.addEventListener('click', async function () {
                publishPkarrBtn.disabled = true;
                publishPkarrMsg.textContent = 'Publishing…';
                try {
                    var res = await authFetch('/api/homeserver/publish-pkarr', { method: 'POST' });
                    var data = await res.json();
                    if (res.ok) {
                        publishPkarrMsg.textContent = '✅ Published! Next auto-publish in 4h.';
                        publishPkarrMsg.style.color = 'var(--success)';
                    } else {
                        publishPkarrMsg.textContent = '❌ ' + (data.error || 'Failed');
                        publishPkarrMsg.style.color = 'var(--danger)';
                    }
                } catch (e) {
                    publishPkarrMsg.textContent = '❌ ' + e.message;
                    publishPkarrMsg.style.color = 'var(--danger)';
                } finally {
                    publishPkarrBtn.disabled = false;
                }
            });
        }

        // ─── Profile Editor ─────────────────────────────────
        var profileKeySelect = document.getElementById('profile-key-select');
        var profileFormContainer = document.getElementById('profile-form-container');
        var profileSaveBtn = document.getElementById('profile-save-btn');
        var profileVerifyBtn = document.getElementById('profile-verify-btn');
        var profileNexusBtn = document.getElementById('profile-nexus-btn');
        var profileMsg = document.getElementById('profile-msg');
        var profileNexusResult = document.getElementById('profile-nexus-result');
        var profileAddLinkBtn = document.getElementById('profile-add-link-btn');
        var profileBadge = document.getElementById('hs-profile-badge');

        // Populate key selector from identities (signed-up keys)
        async function populateProfileKeys() {
            try {
                var res = await authFetch('/api/identity/list');
                var identities = await res.json();
                profileKeySelect.innerHTML = '<option value="">— Select an identity —</option>';
                if (Array.isArray(identities) && identities.length > 0) {
                    for (var i = 0; i < identities.length; i++) {
                        var id = identities[i];
                        var opt = document.createElement('option');
                        opt.value = id.pubkey;
                        var label = id.pubkey.substring(0, 12) + '…';
                        opt.textContent = label + ' (' + id.status + ')';
                        profileKeySelect.appendChild(opt);
                    }
                }
                // Also add vault keys that might not be signed up
                var vaultRes = await authFetch('/api/vault/keys');
                var vaultData = await vaultRes.json();
                var keys = vaultData.keys || [];
                var existingOpts = new Set();
                for (var j = 1; j < profileKeySelect.options.length; j++) {
                    existingOpts.add(profileKeySelect.options[j].value);
                }
                for (var k = 0; k < keys.length; k++) {
                    if (!existingOpts.has(keys[k].pubkey)) {
                        var opt2 = document.createElement('option');
                        opt2.value = keys[k].pubkey;
                        var lbl = keys[k].label || keys[k].pubkey.substring(0, 12) + '…';
                        opt2.textContent = lbl + ' (vault only)';
                        profileKeySelect.appendChild(opt2);
                    }
                }
            } catch (e) {
                console.warn('Failed to populate profile keys:', e);
            }
        }

        // Load profile from homeserver
        async function loadProfile(pubkey) {
            profileMsg.textContent = 'Loading…';
            profileMsg.style.color = '';
            try {
                var res = await authFetch('/api/profile/' + encodeURIComponent(pubkey));
                var data = await res.json();
                if (data.exists && data.profile) {
                    var p = data.profile;
                    document.getElementById('profile-name').value = p.name || '';
                    document.getElementById('profile-bio').value = p.bio || '';
                    document.getElementById('profile-status').value = p.status || '';
                    // Populate links
                    var linksList = document.getElementById('profile-links-list');
                    linksList.innerHTML = '';
                    if (p.links && p.links.length > 0) {
                        for (var i = 0; i < p.links.length; i++) {
                            addLinkRow(p.links[i].title, p.links[i].url);
                        }
                    }
                    profileBadge.textContent = 'Saved';
                    profileBadge.className = 'badge badge-success';
                    profileMsg.textContent = '';
                } else {
                    // No profile yet — clear form
                    document.getElementById('profile-name').value = '';
                    document.getElementById('profile-bio').value = '';
                    document.getElementById('profile-status').value = '';
                    document.getElementById('profile-links-list').innerHTML = '';
                    profileBadge.textContent = 'New';
                    profileBadge.className = 'badge badge-warning';
                    profileMsg.textContent = 'No profile yet — create one!';
                    profileMsg.style.color = 'var(--warning)';
                }
                profileFormContainer.style.display = '';
            } catch (e) {
                profileMsg.textContent = '❌ ' + e.message;
                profileMsg.style.color = 'var(--danger)';
            }
        }

        // Save profile
        async function saveProfile() {
            var pubkey = profileKeySelect.value;
            if (!pubkey) return;
            var name = document.getElementById('profile-name').value.trim();
            if (name.length < 3) {
                profileMsg.textContent = '❌ Name must be at least 3 characters';
                profileMsg.style.color = 'var(--danger)';
                return;
            }
            profileSaveBtn.disabled = true;
            profileMsg.textContent = 'Saving…';
            profileMsg.style.color = '';

            // Collect links
            var linkRows = document.getElementById('profile-links-list').querySelectorAll('.profile-link-row');
            var links = [];
            linkRows.forEach(function (row) {
                var title = row.querySelector('.profile-link-title').value.trim();
                var url = row.querySelector('.profile-link-url').value.trim();
                if (title && url) links.push({ title: title, url: url });
            });

            var payload = {
                name: name,
                bio: document.getElementById('profile-bio').value.trim() || null,
                status: document.getElementById('profile-status').value.trim() || null,
                links: links.length > 0 ? links : null,
            };

            try {
                var res = await authFetch('/api/profile/' + encodeURIComponent(pubkey), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                var data = await res.json();
                if (res.ok && data.ok) {
                    profileMsg.textContent = '✅ Profile saved!';
                    profileMsg.style.color = 'var(--success)';
                    profileBadge.textContent = 'Saved';
                    profileBadge.className = 'badge badge-success';
                } else {
                    profileMsg.textContent = '❌ ' + (data.error || 'Failed');
                    profileMsg.style.color = 'var(--danger)';
                }
            } catch (e) {
                profileMsg.textContent = '❌ ' + e.message;
                profileMsg.style.color = 'var(--danger)';
            } finally {
                profileSaveBtn.disabled = false;
            }
        }

        // Add a link row to the links list
        function addLinkRow(title, url) {
            var list = document.getElementById('profile-links-list');
            var row = document.createElement('div');
            row.className = 'profile-link-row';
            row.style.cssText = 'display:flex;gap:6px;margin-bottom:4px;align-items:center;';
            row.innerHTML = '<input type="text" class="publisher-key-input profile-link-title" placeholder="Title" value="' + (title || '').replace(/"/g, '&quot;') + '" style="flex:1;min-width:80px;">' +
                '<input type="text" class="publisher-key-input profile-link-url" placeholder="https://…" value="' + (url || '').replace(/"/g, '&quot;') + '" style="flex:2;min-width:120px;">' +
                '<button class="btn-sm" style="color:var(--danger);padding:4px 8px;" title="Remove link">✕</button>';
            row.querySelector('button').addEventListener('click', function () { row.remove(); });
            list.appendChild(row);
        }

        // Check Nexus indexing
        async function checkProfileNexus(pubkey) {
            profileNexusResult.style.display = '';
            profileNexusResult.innerHTML = '<span style="color:var(--text-secondary);">Checking Nexus…</span>';
            try {
                var res = await authFetch('/api/profile/' + encodeURIComponent(pubkey) + '/nexus');
                var data = await res.json();
                var html = '<strong>Nexus Indexing Status</strong><br>';
                var prodStatus = data.production || {};
                var stagingStatus = data.staging || {};
                html += '🏭 <strong>Production:</strong> ' + (prodStatus.indexed ? '✅ Indexed' : '⚠️ Not indexed (' + (prodStatus.status || '?') + ')') + '<br>';
                html += '🧪 <strong>Staging:</strong> ' + (stagingStatus.indexed ? '✅ Indexed' : '⚠️ Not indexed (' + (stagingStatus.status || '?') + ')') + '<br>';
                if (prodStatus.indexed && prodStatus.data) {
                    html += '<br><em>Profile on Nexus:</em> ' + (prodStatus.data.name || '—');
                    html += '<br><a href="https://app.pubky.app/profile/' + pubkey + '" target="_blank" style="color:var(--primary);">View on pubky-app →</a>';
                }
                profileNexusResult.innerHTML = html;
                // Also update the status card Nexus badge
                var nexusEl = document.getElementById('hs-nexus-status');
                if (nexusEl) {
                    nexusEl.innerHTML = prodStatus.indexed ? '<span style="color:#4ade80;">✅ Indexed</span>' : '<span style="color:#f59e0b;">⚠️ Not indexed</span>';
                }
            } catch (e) {
                profileNexusResult.innerHTML = '❌ ' + e.message;
            }
        }

        // Verify via tunnel
        async function verifyProfile(pubkey) {
            profileMsg.textContent = 'Verifying via tunnel…';
            profileMsg.style.color = '';
            try {
                var res = await authFetch('/api/profile/' + encodeURIComponent(pubkey) + '/verify');
                var data = await res.json();
                if (data.reachable) {
                    profileMsg.textContent = '✅ Profile reachable at ' + data.tunnel_url;
                    profileMsg.style.color = 'var(--success)';
                } else {
                    profileMsg.textContent = '⚠️ Not reachable: ' + (data.reason || data.error || 'tunnel may not be active');
                    profileMsg.style.color = 'var(--warning)';
                }
            } catch (e) {
                profileMsg.textContent = '❌ ' + e.message;
                profileMsg.style.color = 'var(--danger)';
            }
        }

        // Event listeners
        if (profileKeySelect) {
            profileKeySelect.addEventListener('change', function () {
                var pk = profileKeySelect.value;
                var emptyState = document.getElementById('profile-empty-state');
                if (pk) {
                    if (emptyState) emptyState.style.display = 'none';
                    loadProfile(pk);
                } else {
                    if (emptyState) emptyState.style.display = 'block';
                    profileFormContainer.style.display = 'none';
                    profileBadge.textContent = '—';
                    profileBadge.className = 'badge';
                }
            });
        }
        if (profileSaveBtn) profileSaveBtn.addEventListener('click', function () { saveProfile(); });
        if (profileAddLinkBtn) profileAddLinkBtn.addEventListener('click', function () { addLinkRow('', ''); });
        if (profileVerifyBtn) profileVerifyBtn.addEventListener('click', function () {
            var pk = profileKeySelect.value;
            if (pk) verifyProfile(pk);
        });
        if (profileNexusBtn) profileNexusBtn.addEventListener('click', function () {
            var pk = profileKeySelect.value;
            if (pk) checkProfileNexus(pk);
        });

        // Auto-populate on Homeserver tab activation
        var _profileKeysLoaded = false;
        function onHsTabActivated() {
            if (!_profileKeysLoaded) {
                _profileKeysLoaded = true;
                populateProfileKeys();
            }
        }

        // ─── Log Stream SSE ──────────────────────────────
        var logOutput = document.getElementById('hs-log-output');
        var logBadge = document.getElementById('hs-log-badge');
        var logFilter = document.getElementById('hs-log-filter');
        var logClear = document.getElementById('hs-log-clear-btn');
        var _logLines = [];
        var _logEs = null;

        function renderLogs() {
            var filter = (logFilter ? logFilter.value.toLowerCase() : '');
            var html = _logLines
                .filter(function (l) { return !filter || l.toLowerCase().includes(filter); })
                .map(function (l) {
                    var cls = l.includes('ERROR') || l.includes('error') ? 'color:var(--danger)' :
                        l.includes('WARN') || l.includes('warn') ? 'color:var(--warning)' :
                            '';
                    return '<span style="' + cls + '">' + escHtml(l) + '</span>';
                })
                .join('\n');
            if (logOutput) {
                logOutput.innerHTML = html || '<span style="color:var(--text-tertiary);">No matching log lines.</span>';
                logOutput.scrollTop = logOutput.scrollHeight;
            }
        }

        function escHtml(s) {
            return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        function startLogStream() {
            if (_logEs) return;
            _logEs = new EventSource('/api/logs/stream');
            if (logBadge) { logBadge.textContent = 'Live'; logBadge.className = 'badge badge-active'; }
            _logEs.onmessage = function (e) {
                _logLines.push(e.data);
                if (_logLines.length > 2000) _logLines.shift();
                renderLogs();
            };
            _logEs.onerror = function () {
                if (logBadge) { logBadge.textContent = 'Disconnected'; logBadge.className = 'badge'; }
                _logEs.close(); _logEs = null;
                setTimeout(startLogStream, 5000);
            };
        }

        // Start when homeserver tab is visited
        document.querySelectorAll('.tab').forEach(function (t) {
            t.addEventListener('click', function () {
                if (t.dataset.tab === 'homeserver' && !_logEs) {
                    startLogStream();
                    hsLoadUsers();
                    hsTunnelRefresh();
                    hsIdentityLoad();
                }
            });
        });

        if (logFilter) logFilter.addEventListener('input', renderLogs);
        if (logClear) logClear.addEventListener('click', function () { _logLines = []; renderLogs(); });

        // ─── Users & Quota ───────────────────────────────
        var usersTable = document.getElementById('hs-users-table');
        var usersBadge = document.getElementById('hs-users-badge');
        var usersRefreshBtn = document.getElementById('hs-users-refresh-btn');
        var userSearch = document.getElementById('hs-user-search');

        var _allUsers = [];

        async function hsLoadUsers() {
            if (!usersTable) return;
            usersTable.innerHTML = '<span style="color:var(--text-tertiary);">Loading…</span>';
            try {
                var res = await authFetch('/api/homeserver/users');
                var data = await res.json();
                _allUsers = data.users || [];
                if (usersBadge) usersBadge.textContent = _allUsers.length + ' users';
                renderUsersTable(_allUsers);
                // Populate file browser select
                var sel = document.getElementById('hs-files-user-select');
                if (sel) {
                    var existing = sel.value;
                    sel.innerHTML = '<option value="">— select user —</option>';
                    _allUsers.forEach(function (u) {
                        var o = document.createElement('option');
                        o.value = u.pubkey || u;
                        o.textContent = (u.pubkey || u).substring(0, 20) + '…';
                        sel.appendChild(o);
                    });
                    sel.value = existing;
                }
            } catch (e) {
                usersTable.innerHTML = '<span style="color:var(--danger);">Error: ' + e.message + '</span>';
            }
        }

        function renderUsersTable(users) {
            var filter = userSearch ? userSearch.value.toLowerCase() : '';
            var shown = users.filter(function (u) {
                var pk = (u.pubkey || u).toLowerCase();
                return !filter || pk.includes(filter);
            });

            if (!shown.length) {
                usersTable.innerHTML = '<span style="color:var(--text-tertiary);">No users found.</span>';
                return;
            }

            var rows = shown.map(function (u) {
                var pk = u.pubkey || u;
                var short = pk.substring(0, 24) + '…';
                var disabled = u.disabled ? ' disabled' : '';
                return [
                    '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-color);">',
                    '  <span class="mono" title="' + pk + '" style="flex:1;overflow:hidden;text-overflow:ellipsis;">' + short + '</span>',
                    '  <input type="number" min="0" placeholder="quota MB" value="' + (u.quota_mb || 0) + '"',
                    '    style="width:80px;padding:3px 6px;border-radius:5px;border:1px solid var(--border-color);background:var(--surface-1);color:var(--text-primary);font-size:11px;"',
                    '    data-pubkey="' + pk + '" class="user-quota-input">',
                    '  <button class="btn-sm btn-secondary user-quota-save" data-pubkey="' + pk + '" title="Save quota" style="padding:3px 8px;">💾</button>',
                    '  <button class="btn-sm ' + (disabled ? 'btn-primary user-enable-btn' : 'btn-danger user-disable-btn') + '"',
                    '    data-pubkey="' + pk + '" style="padding:3px 8px;">' + (disabled ? 'Enable' : 'Disable') + '</button>',
                    '</div>'
                ].join('');
            }).join('');

            usersTable.innerHTML = rows;

            // Bind quota save buttons
            usersTable.querySelectorAll('.user-quota-save').forEach(function (btn) {
                btn.addEventListener('click', async function () {
                    var pk = btn.dataset.pubkey;
                    var inp = usersTable.querySelector('.user-quota-input[data-pubkey="' + pk + '"]');
                    var mb = parseInt(inp ? inp.value : 0, 10);
                    btn.disabled = true;
                    try {
                        var res = await authFetch('/api/homeserver/users/' + encodeURIComponent(pk) + '/quota', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ quota_mb: mb })
                        });
                        var d = await res.json();
                        btn.textContent = d.error ? '❌' : '✅';
                        setTimeout(function () { btn.textContent = '💾'; }, 1500);
                    } catch (e) { btn.textContent = '❌'; }
                    btn.disabled = false;
                });
            });

            // Bind disable/enable buttons
            usersTable.querySelectorAll('.user-disable-btn, .user-enable-btn').forEach(function (btn) {
                btn.addEventListener('click', async function () {
                    var pk = btn.dataset.pubkey;
                    var isDisable = btn.classList.contains('user-disable-btn');
                    var action = isDisable ? 'disable' : 'enable';
                    btn.disabled = true;
                    try {
                        var res = await authFetch('/api/homeserver/user-action/' + action, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pubkey: pk })
                        });
                        if (res.ok) hsLoadUsers(); // refresh
                    } catch (e) { console.error(e); }
                    btn.disabled = false;
                });
            });
        }

        if (usersRefreshBtn) usersRefreshBtn.addEventListener('click', hsLoadUsers);
        if (userSearch) userSearch.addEventListener('input', function () { renderUsersTable(_allUsers); });

        // ─── Cloudflare Tunnel ───────────────────────────
        var tunnelBadge = document.getElementById('hs-tunnel-badge');
        var tunnelUrl = document.getElementById('hs-tunnel-url');
        var tunnelNoBin = document.getElementById('hs-tunnel-no-binary');
        var tunnelStartBtn = document.getElementById('hs-tunnel-start-btn');
        var tunnelStopBtn = document.getElementById('hs-tunnel-stop-btn');

        async function hsTunnelRefresh() {
            try {
                var res = await authFetch('/api/tunnel/status');
                var data = await res.json();
                var st = data.state || 'stopped';
                if (tunnelBadge) {
                    tunnelBadge.textContent = st.charAt(0).toUpperCase() + st.slice(1);
                    tunnelBadge.className = 'badge' + (st === 'running' ? ' badge-active' : st === 'starting' ? ' badge-warning' : '');
                }
                if (tunnelUrl) {
                    if (data.public_url) {
                        tunnelUrl.style.display = '';
                        tunnelUrl.innerHTML = '🌐 <a href="' + data.public_url + '" target="_blank" rel="noopener" style="color:var(--primary);">' + data.public_url + '</a>';
                    } else {
                        tunnelUrl.style.display = 'none';
                    }
                }
                if (!data.binary_available && tunnelNoBin) tunnelNoBin.style.display = '';
                if (tunnelStartBtn) tunnelStartBtn.disabled = (st === 'running' || st === 'starting');
                if (tunnelStopBtn) tunnelStopBtn.disabled = (st === 'stopped');
            } catch (e) { console.error('tunnel status:', e); }
        }

        if (tunnelStartBtn) {
            tunnelStartBtn.addEventListener('click', async function () {
                tunnelStartBtn.disabled = true;
                if (tunnelBadge) tunnelBadge.textContent = 'Starting…';
                try {
                    await authFetch('/api/tunnel/start', { method: 'POST' });
                    setTimeout(hsTunnelRefresh, 3000);
                    setTimeout(hsTunnelRefresh, 8000);
                } catch (e) { console.error(e); hsTunnelRefresh(); }
            });
        }
        if (tunnelStopBtn) {
            tunnelStopBtn.addEventListener('click', async function () {
                tunnelStopBtn.disabled = true;
                try {
                    await authFetch('/api/tunnel/stop', { method: 'POST' });
                    setTimeout(hsTunnelRefresh, 1000);
                } catch (e) { console.error(e); hsTunnelRefresh(); }
            });
        }
        // ─── Relay Tunnel ─────────────────────────────────
        var relayTunnelBadge = document.getElementById('relay-tunnel-badge');
        var relayTunnelUrl = document.getElementById('relay-tunnel-url');
        var relayTunnelStartBtn = document.getElementById('relay-tunnel-start-btn');
        var relayTunnelStopBtn = document.getElementById('relay-tunnel-stop-btn');

        async function relayTunnelRefresh() {
            try {
                var res = await authFetch('/api/relay-tunnel/status');
                var data = await res.json();
                var st = data.state || 'stopped';
                if (relayTunnelBadge) {
                    relayTunnelBadge.textContent = st.charAt(0).toUpperCase() + st.slice(1);
                    relayTunnelBadge.className = 'badge' + (st === 'running' ? ' badge-active' : st === 'starting' ? ' badge-warning' : '');
                }
                if (relayTunnelUrl) {
                    if (data.public_url) {
                        relayTunnelUrl.style.display = '';
                        relayTunnelUrl.innerHTML = '🌐 <a href="' + data.public_url + '" target="_blank" rel="noopener" style="color:var(--primary);">' + data.public_url + '</a>';
                    } else {
                        relayTunnelUrl.style.display = 'none';
                    }
                }
                if (relayTunnelStartBtn) {
                    if (!data.binary_available) {
                        relayTunnelStartBtn.disabled = true;
                        relayTunnelStartBtn.title = 'cloudflared binary not found. Run build-sidecars.sh to download it.';
                    } else {
                        relayTunnelStartBtn.disabled = (st === 'running' || st === 'starting');
                        relayTunnelStartBtn.title = '';
                    }
                }
                if (relayTunnelStopBtn) relayTunnelStopBtn.disabled = (st === 'stopped');
            } catch (e) { console.error('relay tunnel status:', e); }
        }

        if (relayTunnelStartBtn) {
            relayTunnelStartBtn.addEventListener('click', async function () {
                relayTunnelStartBtn.disabled = true;
                if (relayTunnelBadge) relayTunnelBadge.textContent = 'Starting…';
                try {
                    await authFetch('/api/relay-tunnel/start', { method: 'POST' });
                    setTimeout(relayTunnelRefresh, 3000);
                    setTimeout(relayTunnelRefresh, 8000);
                } catch (e) { console.error(e); relayTunnelRefresh(); }
            });
        }
        if (relayTunnelStopBtn) {
            relayTunnelStopBtn.addEventListener('click', async function () {
                relayTunnelStopBtn.disabled = true;
                try {
                    await authFetch('/api/relay-tunnel/stop', { method: 'POST' });
                    setTimeout(relayTunnelRefresh, 1000);
                } catch (e) { console.error(e); relayTunnelRefresh(); }
            });
        }

        // ─── DNS Tunnel (DoH) ────────────────────────────
        var dnsTunnelBadge = document.getElementById('dns-tunnel-badge');
        var dnsTunnelUrl = document.getElementById('dns-tunnel-url');
        var dnsTunnelStartBtn = document.getElementById('dns-tunnel-start-btn');
        var dnsTunnelStopBtn = document.getElementById('dns-tunnel-stop-btn');

        async function dnsTunnelRefresh() {
            try {
                var res = await authFetch('/api/dns-tunnel/status');
                var data = await res.json();
                var st = data.state || 'stopped';
                if (dnsTunnelBadge) {
                    dnsTunnelBadge.textContent = st.charAt(0).toUpperCase() + st.slice(1);
                    dnsTunnelBadge.className = 'badge' + (st === 'running' ? ' badge-active' : st === 'starting' ? ' badge-warning' : '');
                }
                if (dnsTunnelUrl) {
                    if (data.public_url) {
                        dnsTunnelUrl.style.display = '';
                        dnsTunnelUrl.innerHTML = '🌐 <a href="' + data.public_url + '/dns-query" target="_blank" rel="noopener" style="color:var(--primary);">' + data.public_url + '/dns-query</a>';
                    } else {
                        dnsTunnelUrl.style.display = 'none';
                    }
                }
                if (dnsTunnelStartBtn) {
                    if (!data.binary_available) {
                        dnsTunnelStartBtn.disabled = true;
                        dnsTunnelStartBtn.title = 'cloudflared binary not found';
                    } else {
                        dnsTunnelStartBtn.disabled = (st === 'running' || st === 'starting');
                        dnsTunnelStartBtn.title = '';
                    }
                }
                if (dnsTunnelStopBtn) dnsTunnelStopBtn.disabled = (st === 'stopped');
            } catch (e) { console.error('dns tunnel status:', e); }
        }

        if (dnsTunnelStartBtn) {
            dnsTunnelStartBtn.addEventListener('click', async function () {
                dnsTunnelStartBtn.disabled = true;
                if (dnsTunnelBadge) dnsTunnelBadge.textContent = 'Starting…';
                try {
                    await authFetch('/api/dns-tunnel/start', { method: 'POST' });
                    setTimeout(dnsTunnelRefresh, 3000);
                    setTimeout(dnsTunnelRefresh, 8000);
                } catch (e) { console.error(e); dnsTunnelRefresh(); }
            });
        }
        if (dnsTunnelStopBtn) {
            dnsTunnelStopBtn.addEventListener('click', async function () {
                dnsTunnelStopBtn.disabled = true;
                try {
                    await authFetch('/api/dns-tunnel/stop', { method: 'POST' });
                    setTimeout(dnsTunnelRefresh, 1000);
                } catch (e) { console.error(e); dnsTunnelRefresh(); }
            });
        }

        // ─── Identity Signup ─────────────────────────────
        var identityKeySelect = document.getElementById('hs-identity-key-select');
        var identityToken = document.getElementById('hs-identity-token');
        var identitySignupBtn = document.getElementById('hs-identity-signup-btn');
        var identityMsg = document.getElementById('hs-identity-msg');
        var identityListEl = document.getElementById('hs-identity-list');
        var identityBadge = document.getElementById('hs-identity-badge');

        function hsIdentityLoad() {
            // Populate key selector from the vault
            authFetch('/api/keys').then(function (res) { return res.json(); }).then(function (data) {
                if (!identityKeySelect) return;
                var keys = data.keys || [];
                identityKeySelect.innerHTML = '<option value="">— select a key —</option>';
                keys.forEach(function (k) {
                    var o = document.createElement('option');
                    o.value = k.pubkey || k;
                    o.textContent = (k.name ? k.name + ' (' : '') + (k.pubkey || k).substring(0, 20) + '…' + (k.name ? ')' : '');
                    identityKeySelect.appendChild(o);
                });
            }).catch(function () { });

            // Load registered identities
            authFetch('/api/identity/list').then(function (res) { return res.json(); }).then(function (data) {
                var ids = data.identities || [];
                if (identityBadge) identityBadge.textContent = ids.length ? ids.length + ' registered' : '—';
                if (!identityListEl) return;
                if (!ids.length) { identityListEl.innerHTML = ''; return; }
                identityListEl.innerHTML = '<b style="font-size:11px;color:var(--text-tertiary);display:block;margin-bottom:6px;">Registered identities:</b>' +
                    ids.map(function (id) {
                        var ts = id.signed_up_at ? new Date(id.signed_up_at * 1000).toLocaleDateString() : '—';
                        return '<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-color);">' +
                            '<span class="mono" style="flex:1;">' + (id.pubkey || '').substring(0, 24) + '…</span>' +
                            '<span style="color:var(--text-tertiary);">' + ts + '</span>' +
                            '<span class="badge ' + (id.status === 'active' ? 'badge-active' : '') + '">' + (id.status || '?') + '</span>' +
                            '</div>';
                    }).join('');
            }).catch(function () { });
        }

        if (identitySignupBtn) {
            identitySignupBtn.addEventListener('click', async function () {
                var pubkey = identityKeySelect ? identityKeySelect.value : '';
                if (!pubkey) { identityMsg.textContent = 'Select a key first.'; return; }
                identitySignupBtn.disabled = true;
                identityMsg.textContent = 'Signing up…';
                try {
                    var body = { pubkey: pubkey };
                    var tok = identityToken ? identityToken.value.trim() : '';
                    var hsStatus = await authFetch('/api/homeserver/status').then(function (r) { return r.json(); }).catch(function () { return {}; });
                    body.homeserver_pubkey = hsStatus.pubkey || '';
                    if (tok) body.signup_token = tok;
                    var res = await authFetch('/api/identity/signup', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                    var data = await res.json();
                    if (res.ok) {
                        identityMsg.textContent = '✅ Signed up!';
                        identityMsg.style.color = 'var(--success)';
                        hsIdentityLoad();
                    } else {
                        identityMsg.textContent = '❌ ' + (data.error || 'Failed');
                        identityMsg.style.color = 'var(--danger)';
                    }
                } catch (e) {
                    identityMsg.textContent = '❌ ' + e.message;
                    identityMsg.style.color = 'var(--danger)';
                } finally {
                    identitySignupBtn.disabled = false;
                }
            });
        }

        // ─── WebDAV File Browser ─────────────────────────
        var filesRefreshBtn = document.getElementById('hs-files-refresh-btn');
        var filesTree = document.getElementById('hs-files-tree');
        var filesPreview = document.getElementById('hs-files-preview');
        var filesUserSelect = document.getElementById('hs-files-user-select');

        async function hsBrowseFiles(pubkey, path) {
            if (!pubkey || !filesTree) return;
            path = path || 'pub';
            filesTree.innerHTML = '<span style="color:var(--text-tertiary);">Browsing…</span>';
            try {
                // Use dav proxy: /hs/dav/{pubkey}/{path}
                var url = '/hs/dav/' + encodeURIComponent(pubkey) + '/' + path;
                var res = await authFetch(url, {
                    method: 'PROPFIND',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' }
                });
                var text = await res.text();
                // Parse XML to extract hrefs
                var hrefs = [], parser = new DOMParser();
                var doc = parser.parseFromString(text, 'application/xml');
                var refs = doc.querySelectorAll('href');
                refs.forEach(function (el) { hrefs.push(el.textContent.trim()); });
                // Filter out the current directory itself
                hrefs = hrefs.filter(function (h) { return h !== url && h !== url + '/'; });
                if (!hrefs.length) {
                    filesTree.innerHTML = '<span style="color:var(--text-tertiary);">Empty directory.</span>';
                    return;
                }
                filesTree.innerHTML = hrefs.map(function (h) {
                    var name = h.split('/').filter(Boolean).pop();
                    var isDir = h.endsWith('/');
                    return '<div style="padding:3px 0;cursor:pointer;" data-href="' + h + '" data-dir="' + isDir + '">' +
                        (isDir ? '📁 ' : '📄 ') + name +
                        '</div>';
                }).join('');
                // Bind clicks
                filesTree.querySelectorAll('[data-href]').forEach(function (el) {
                    el.addEventListener('click', async function () {
                        if (el.dataset.dir === 'true') {
                            hsBrowseFiles(pubkey, path + '/' + el.textContent.trim().replace(/^📁 /, '').replace(/^📄 /, ''));
                        } else {
                            if (!filesPreview) return;
                            filesPreview.style.display = '';
                            filesPreview.textContent = 'Loading…';
                            try {
                                var fr = await authFetch(el.dataset.href);
                                filesPreview.textContent = await fr.text();
                            } catch (e) { filesPreview.textContent = 'Error: ' + e.message; }
                        }
                    });
                });
            } catch (e) {
                filesTree.innerHTML = '<span style="color:var(--danger);">Error: ' + e.message + '</span>';
            }
        }

        if (filesRefreshBtn) {
            filesRefreshBtn.addEventListener('click', function () {
                var pk = filesUserSelect ? filesUserSelect.value : '';
                hsBrowseFiles(pk);
            });
        }

        // Dev badge removed — no longer needed

        // ========== Unified Onboarding Sequence ==========

        // Step 2: Vault Creation
        var uVaultBtn = document.getElementById('unified-vault-btn');
        if (uVaultBtn) {
            uVaultBtn.addEventListener('click', async function () {
                var pw = document.getElementById('unified-vault-pwd').value;
                var pw2 = document.getElementById('unified-vault-pwd-conf').value;
                var err = document.getElementById('unified-vault-err');
                err.textContent = '';
                var isUnlock = uVaultBtn.dataset.mode === 'unlock';

                if (pw.length < 4) { err.textContent = 'Password must be at least 4 characters.'; return; }
                if (!isUnlock && pw !== pw2) { err.textContent = 'Passwords do not match.'; return; }

                uVaultBtn.disabled = true;
                uVaultBtn.textContent = 'Securing...';
                try {
                    var endpoint = isUnlock ? '/api/vault/unlock' : '/api/vault/create';
                    var res = await authFetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: pw })
                    });
                    var data = await res.json();
                    if (data.success) {
                        unifiedShowStep(3);
                    } else {
                        err.textContent = data.error || (isUnlock ? 'Failed to unlock vault.' : 'Failed to create vault.');
                    }
                } catch (e) { err.textContent = 'Network error: ' + e.message; }
                uVaultBtn.disabled = false;
                uVaultBtn.textContent = isUnlock ? 'Unlock Vault & Continue →' : 'Secure Vault & Continue →';
            });
        }

        // Step 3: Launch
        var uLaunchBtn = document.getElementById('unified-launch-btn');
        if (uLaunchBtn) {
            uLaunchBtn.addEventListener('click', async function () {
                var err = document.getElementById('unified-hs-err');
                err.textContent = '';
                var logBox = document.getElementById('unified-launch-log');
                
                function addLog(msg, color) {
                    var span = document.createElement('div');
                    span.innerHTML = msg;
                    if(color) span.style.color = color;
                    logBox.appendChild(span);
                    logBox.scrollTop = logBox.scrollHeight;
                }

                uLaunchBtn.disabled = true;
                unifiedShowStep(4);
                logBox.innerHTML = '⏳ Initialization started...<br>';
                document.getElementById('unified-done-btn').style.display = 'none';

                try {
                    var signupMode = document.getElementById('unified-hs-signup').value;
                    var accessMode = document.querySelector('input[name="unified-hs-access"]:checked');
                    var useTunnel = accessMode && accessMode.value === 'tunnel';

                    // 1. Config
                    addLog('⏳ Saving Homeserver configuration...', 'var(--text-secondary)');
                    await authFetch('/api/homeserver/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ signup_mode: signupMode })
                    });

                    // 2. Start Homeserver
                    addLog('⏳ Booting Homeserver process...', 'var(--text-secondary)');
                    var hsRes = await authFetch('/api/homeserver/start', { method: 'POST' });
                    var hsData = await hsRes.json();
                    if (!hsData.success) throw new Error(hsData.error || 'Failed to start homeserver');
                    addLog('✅ Homeserver is running!', 'var(--success)');

                    // 3. Quickstart (Keygen, Signup, PKARR, Watchlist)
                    addLog('⏳ Generating Sovereign Identity & Publishing...', 'var(--text-secondary)');
                    var qsRes = await authFetch('/api/quickstart', { method: 'POST' });
                    var qsData = await qsRes.json();
                    if (!qsRes.ok || !qsData.success) throw new Error(qsData.error || 'Failed to setup identity');
                    addLog('✅ Identity created (pubky://' + qsData.pubkey.substring(0,8) + '...)', 'var(--success)');
                    if (qsData.pkarr_published) {
                        addLog('✅ Routing record published to DHT', 'var(--success)');
                    }

                    // 4. Tunnel
                    if (useTunnel) {
                        addLog('⏳ Establishing Cloudflare Relay Tunnel...', 'var(--text-secondary)');
                        var tunnelRes = await authFetch('/api/tunnel/start', { method: 'POST' });
                        if (!tunnelRes.ok) {
                            addLog('⚠ Tunnel failed. You may configure it later in the UI.', 'var(--warning)');
                        } else {
                            addLog('✅ Tunnel connected', 'var(--success)');
                            // Auto-publish PKARR again with new tunnel URL
                            await authFetch('/api/homeserver/publish-pkarr', { method: 'POST' });
                        }
                    }

                    addLog('<br>🎉 <strong>Welcome to the Sovereign Web!</strong>', 'var(--primary)');
                    document.getElementById('unified-done-btn').style.display = 'block';

                } catch (e) {
                    addLog('❌ Error: ' + e.message, 'var(--danger)');
                    var retryBtn = document.createElement('button');
                    retryBtn.className = 'btn btn-secondary onboarding-btn';
                    retryBtn.style.marginTop = '10px';
                    retryBtn.textContent = 'Retry Setup';
                    retryBtn.onclick = function() { 
                        unifiedShowStep(3); 
                        uLaunchBtn.disabled = false;
                    };
                    logBox.appendChild(retryBtn);
                }
            });
        }

        // Step 4: Done
        var uDoneBtn = document.getElementById('unified-done-btn');
        if (uDoneBtn) {
            uDoneBtn.addEventListener('click', function() {
                var overlay = document.getElementById('unified-onboarding-overlay');
                if (overlay) overlay.style.display = 'none';
                if (typeof loadVaultStatus === 'function') loadVaultStatus();
                if (typeof loadVaultKeys === 'function') loadVaultKeys();
            });
        }

        // Vault state check now handled in initDashboard() after login

        // ========== Stage 2: Global Copy Helper ==========

        window.copyToClipboard = function (text, label) {
            navigator.clipboard.writeText(text).then(function () {
                showCopyToast(label || 'Copied to clipboard');
            });
        };

        function showCopyToast(msg) {
            var existing = document.getElementById('copy-toast');
            if (existing) existing.remove();
            var toast = document.createElement('div');
            toast.id = 'copy-toast';
            toast.className = 'copy-toast';
            toast.textContent = '✅ ' + msg;
            document.body.appendChild(toast);
            requestAnimationFrame(function () {
                toast.classList.add('show');
            });
            setTimeout(function () {
                toast.classList.remove('show');
                setTimeout(function () { toast.remove(); }, 300);
            }, 2000);
        }

        // Publisher: Verify button — switches to Explorer tab and auto-resolves
        var pubVerifyBtn = document.getElementById('publisher-verify-btn');
        if (pubVerifyBtn) {
            pubVerifyBtn.addEventListener('click', function () {
                var feedbackEl = document.getElementById('publisher-success-feedback');
                var pubkey = feedbackEl ? feedbackEl._pubkey : '';
                if (!pubkey) return;
                // Switch to Explorer tab
                var explorerTab = document.querySelector('[data-tab="explorer"]');
                if (explorerTab) explorerTab.click();
                // Fill and resolve
                var input = document.getElementById('explorer-key');
                if (input) input.value = pubkey;
                setTimeout(function () {
                    document.getElementById('explorer-btn').click();
                }, 200);
            });
        }

        // Publisher: Copy URI button
        var pubCopyBtn = document.getElementById('publisher-copy-uri-btn');
        if (pubCopyBtn) {
            pubCopyBtn.addEventListener('click', function () {
                var uri = document.getElementById('publisher-pubky-uri').textContent;
                copyToClipboard(uri, 'Pubky URI copied');
            });
        }

        // Explorer: Copy URI button
        var explorerCopyBtn = document.getElementById('explorer-copy-uri-btn');
        if (explorerCopyBtn) {
            explorerCopyBtn.addEventListener('click', function () {
                var uri = document.getElementById('explorer-pubky-uri').textContent;
                copyToClipboard(uri, 'Pubky URI copied');
            });
        }

        // ========== Stage 2: Reachability Self-Test ==========

        async function checkReachability() {
            try {
                var res = await authFetch('/api/reachability-check');
                var data = await res.json();

                // Network Status tab dots
                var dht = document.getElementById('tl-dht');
                var relay = document.getElementById('tl-relay');
                var tunnel = document.getElementById('tl-tunnel');
                var suggestion = document.getElementById('reachability-suggestion');

                if (dht) {
                    dht.className = 'traffic-dot ' + (data.dht_healthy ? 'green' : 'red');
                }
                if (relay) {
                    relay.className = 'traffic-dot ' + (data.relay_reachable ? 'green' : 'red');
                }
                if (tunnel) {
                    tunnel.className = 'traffic-dot ' + (data.tunnel_active ? 'green' : 'amber');
                }
                if (suggestion && data.suggestion) {
                    suggestion.textContent = data.suggestion;
                    suggestion.style.display = '';
                }

                // Dashboard overview dots (mirror)
                var dashDht = document.getElementById('dash-tl-dht');
                var dashRelay = document.getElementById('dash-tl-relay');
                var dashTunnel = document.getElementById('dash-tl-tunnel');
                if (dashDht) dashDht.className = 'traffic-dot ' + (data.dht_healthy ? 'green' : 'red');
                if (dashRelay) dashRelay.className = 'traffic-dot ' + (data.relay_reachable ? 'green' : 'red');
                if (dashTunnel) dashTunnel.className = 'traffic-dot ' + (data.tunnel_active ? 'green' : 'amber');
            } catch (e) { /* ignore */ }
        }

        async function updateDashboardTunnels() {
            try {
                // HS Tunnel
                var hsRes = await authFetch('/api/tunnel/status');
                var hsData = await hsRes.json();
                var hsBadge = document.getElementById('dash-hs-tunnel-badge');
                var hsUrl = document.getElementById('dash-hs-tunnel-url');
                if (hsBadge) {
                    if (hsData.state === 'running') {
                        hsBadge.textContent = 'Running';
                        hsBadge.className = 'badge badge-sm badge-success';
                    } else if (hsData.state === 'starting') {
                        hsBadge.textContent = 'Starting…';
                        hsBadge.className = 'badge badge-sm';
                    } else {
                        hsBadge.textContent = 'Stopped';
                        hsBadge.className = 'badge badge-sm badge-stopped';
                    }
                }
                if (hsUrl) {
                    if (hsData.public_url) {
                        hsUrl.href = hsData.public_url;
                        hsUrl.textContent = hsData.public_url.replace('https://', '');
                        hsUrl.style.display = '';
                    } else {
                        hsUrl.style.display = 'none';
                    }
                }
            } catch (e) { /* ignore */ }
            try {
                // Relay Tunnel
                var rlRes = await authFetch('/api/relay-tunnel/status');
                var rlData = await rlRes.json();
                var rlBadge = document.getElementById('dash-relay-tunnel-badge');
                var rlUrl = document.getElementById('dash-relay-tunnel-url');
                if (rlBadge) {
                    if (rlData.state === 'running') {
                        rlBadge.textContent = 'Running';
                        rlBadge.className = 'badge badge-sm badge-success';
                    } else if (rlData.state === 'starting') {
                        rlBadge.textContent = 'Starting…';
                        rlBadge.className = 'badge badge-sm';
                    } else {
                        rlBadge.textContent = 'Stopped';
                        rlBadge.className = 'badge badge-sm badge-stopped';
                    }
                }
                if (rlUrl) {
                    if (rlData.public_url) {
                        rlUrl.href = rlData.public_url;
                        rlUrl.textContent = rlData.public_url.replace('https://', '');
                        rlUrl.style.display = '';
                    } else {
                        rlUrl.style.display = 'none';
                    }
                }
            } catch (e) { /* ignore */ }
            try {
                // DNS Tunnel (DoH)
                var dnsRes = await authFetch('/api/dns-tunnel/status');
                var dnsData = await dnsRes.json();
                var dnsBadge = document.getElementById('dash-dns-tunnel-badge');
                var dnsUrl = document.getElementById('dash-dns-tunnel-url');
                if (dnsBadge) {
                    if (dnsData.state === 'running') {
                        dnsBadge.textContent = 'Running';
                        dnsBadge.className = 'badge badge-sm badge-success';
                    } else if (dnsData.state === 'starting') {
                        dnsBadge.textContent = 'Starting…';
                        dnsBadge.className = 'badge badge-sm';
                    } else {
                        dnsBadge.textContent = 'Stopped';
                        dnsBadge.className = 'badge badge-sm badge-stopped';
                    }
                }
                if (dnsUrl) {
                    if (dnsData.public_url) {
                        dnsUrl.href = dnsData.public_url + '/dns-query';
                        dnsUrl.textContent = dnsData.public_url.replace('https://', '') + '/dns-query';
                        dnsUrl.style.display = '';
                    } else {
                        dnsUrl.style.display = 'none';
                    }
                }
            } catch (e) { /* ignore */ }
        }

        // Check on Networks tab visit
        document.querySelectorAll('.tab').forEach(function (t) {
            t.addEventListener('click', function () {
                if (t.dataset.tab === 'networks') {
                    checkReachability();
                    dnsTunnelRefresh();
                }
                // Also update dashboard tunnels when visiting Dashboard tab
                if (t.dataset.tab === 'dashboard') {
                    checkReachability();
                    updateDashboardTunnels();
                }
            });
        });

        // Manual refresh
        var reachBtn = document.getElementById('reachability-refresh-btn');
        if (reachBtn) {
            reachBtn.addEventListener('click', function () {
                reachBtn.textContent = '⏳';
                checkReachability().then(function () { reachBtn.textContent = 'Check'; });
            });
        }

        // Auto-check on initial load
        setTimeout(function() {
            checkReachability();
            updateDashboardTunnels();
        }, 1500);

        // ========== Stage 3: Recovery Tab ==========

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            var units = ['B', 'KB', 'MB', 'GB'];
            var i = Math.floor(Math.log(bytes) / Math.log(1024));
            return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
        }

        async function fetchBackupStatus() {
            try {
                var res = await authFetch('/api/backup/status');
                var data = await res.json();
                document.getElementById('backup-count').textContent = data.backup_count || 0;
                document.getElementById('backup-active-syncs').textContent = data.active_syncs || 0;
                document.getElementById('backup-total-size').textContent = formatBytes(data.total_size || 0);

                // Show backup dir as clickable link
                var dirEl = document.getElementById('backup-dir-display');
                if (dirEl && data.backup_dir) {
                    dirEl.textContent = '📂 ' + data.backup_dir;
                    dirEl.title = 'Click to open in Finder: ' + data.backup_dir;
                    dirEl.onclick = function(e) {
                        e.preventDefault();
                        fetch('/api/backup/open-dir', { method: 'POST', headers: authHeaders() })
                            .then(function(r) { if (!r.ok) console.warn('Could not open folder'); });
                    };
                }

                var badge = document.getElementById('backup-status-badge');
                if (data.backup_count > 0) {
                    badge.textContent = data.active_syncs > 0 ? 'Syncing' : 'Idle';
                    badge.className = 'badge ' + (data.active_syncs > 0 ? 'badge-warn' : 'badge-success');
                } else {
                    badge.textContent = 'No Backups';
                    badge.className = 'badge';
                }
            } catch (e) { /* ignore */ }
        }

        async function fetchBackupList() {
            try {
                var res = await authFetch('/api/backup/list');
                var data = await res.json();
                var list = document.getElementById('backup-list');
                var empty = document.getElementById('backup-empty');
                var backups = data.backups || [];

                // Update dropdowns
                var exportSelect = document.getElementById('backup-export-select');
                var verifySelect = document.getElementById('backup-verify-select');
                exportSelect.innerHTML = '<option value="">— Select identity to export —</option>';
                verifySelect.innerHTML = '<option value="">— Select identity to verify —</option>';

                if (backups.length === 0) {
                    list.innerHTML = '';
                    list.appendChild(empty);
                    empty.style.display = '';
                    return;
                }

                empty.style.display = 'none';
                list.innerHTML = '';

                backups.forEach(function (b) {
                    var item = document.createElement('div');
                    item.className = 'backup-item';
                    var lastSync = b.last_sync ? b.last_sync : 'Never';
                    var statusIcon = b.is_syncing ? '⏳' : (b.last_error ? '⚠' : '✅');
                    item.innerHTML =
                        '<span class="backup-item-pubky" title="' + b.pubky + '">' + statusIcon + ' ' + b.pubky + '</span>' +
                        '<span class="backup-item-size">' + formatBytes(b.data_size || 0) + ' (' + (b.file_count || 0) + ' files)</span>' +
                        '<div class="backup-item-actions">' +
                            '<button class="btn-sm btn-secondary backup-sync-btn" data-pubky="' + b.pubky + '" title="Force sync">⟳</button>' +
                            '<button class="btn-sm btn-secondary backup-remove-btn" data-pubky="' + b.pubky + '" title="Remove">✕</button>' +
                        '</div>';
                    list.appendChild(item);

                    // Dropdown options
                    var opt1 = document.createElement('option');
                    opt1.value = b.pubky;
                    opt1.textContent = b.pubky.substring(0, 12) + '…';
                    exportSelect.appendChild(opt1);

                    var opt2 = opt1.cloneNode(true);
                    verifySelect.appendChild(opt2);
                });

                // Wire sync/remove buttons
                list.querySelectorAll('.backup-sync-btn').forEach(function (btn) {
                    btn.addEventListener('click', async function () {
                        btn.textContent = '⏳';
                        await authFetch('/api/backup/force-sync', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pubky: btn.dataset.pubky })
                        });
                        btn.textContent = '⟳';
                        fetchBackupStatus();
                        fetchBackupList();
                    });
                });

                list.querySelectorAll('.backup-remove-btn').forEach(function (btn) {
                    btn.addEventListener('click', async function () {
                        await authFetch('/api/backup/stop', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ pubky: btn.dataset.pubky })
                        });
                        fetchBackupStatus();
                        fetchBackupList();
                    });
                });

            } catch (e) { /* ignore */ }
        }

        // Add backup button
        document.getElementById('backup-add-btn')?.addEventListener('click', async function () {
            var input = document.getElementById('backup-add-pubky');
            var pubky = input.value.trim();
            if (!pubky) return;

            var res = await authFetch('/api/backup/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pubky: pubky })
            });
            var data = await res.json();

            if (res.ok) {
                input.value = '';
                showCopyToast('Backup added for ' + pubky.substring(0, 12) + '…');
                // Auto-trigger sync for the new identity
                authFetch('/api/backup/force-sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pubky: pubky })
                });
                fetchBackupStatus();
                fetchBackupList();
            } else {
                showCopyToast(data.error || 'Failed to add backup');
            }
        });

        // Sync All button
        document.getElementById('backup-sync-all-btn')?.addEventListener('click', async function () {
            var btn = this;
            btn.disabled = true;
            btn.textContent = '⏳ Syncing…';
            try {
                await authFetch('/api/backup/sync-all', { method: 'POST' });
                showCopyToast('Sync-all triggered — running in background');
                // Poll for updates every 2s for 30s
                var polls = 0;
                var poller = setInterval(function() {
                    fetchBackupStatus();
                    fetchBackupList();
                    polls++;
                    if (polls > 15) clearInterval(poller);
                }, 2000);
            } catch (e) { showCopyToast('Sync failed'); }
            btn.disabled = false;
            btn.textContent = '⟳ Sync All Now';
        });

        // ─── Snapshots ──────────────────────────────────────────
        async function fetchSnapshots() {
            try {
                var res = await authFetch('/api/backup/snapshots');
                var data = await res.json();
                var list = document.getElementById('snapshot-list');
                var empty = document.getElementById('snapshot-empty');
                var badge = document.getElementById('snapshot-count-badge');
                var snaps = data.snapshots || [];
                badge.textContent = snaps.length;
                if (snaps.length === 0) {
                    list.innerHTML = '';
                    empty.style.display = 'block';
                    return;
                }
                empty.style.display = 'none';
                list.innerHTML = snaps.map(function(s) {
                    var tier = s.tier || 'manual';
                    var tierColors = { daily:'#22c55e', monthly:'#3b82f6', quarterly:'#a855f7', yearly:'#f59e0b', manual:'#6b7280' };
                    var tierColor = tierColors[tier] || '#6b7280';
                    var displayTs = s.display_ts || s.timestamp || '';
                    return '<div style="background:rgba(30,30,50,0.6);border:1px solid rgba(139,92,246,0.2);border-radius:8px;padding:10px 12px;">' +
                        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">' +
                            '<div style="display:flex;align-items:center;gap:8px;">' +
                                '<span style="font-size:0.65rem;padding:1px 6px;border-radius:4px;background:' + tierColor + '22;color:' + tierColor + ';border:1px solid ' + tierColor + '44;text-transform:uppercase;font-weight:600;letter-spacing:0.5px;">' + tier + '</span>' +
                                '<span style="font-family:var(--mono);font-size:0.78rem;color:#c4b5fd;">' + displayTs + '</span>' +
                            '</div>' +
                        '</div>' +
                        '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                            '<span style="font-size:0.78rem;color:#9ca3af;">' + (s.file_count || 0) + ' files · ' + formatBytes(s.size || 0) + '</span>' +
                            '<div style="display:flex;gap:6px;">' +
                                '<button class="btn-sm" onclick="restoreSnapshot(\'' + s.pubky + '\',\'' + s.timestamp + '\')" style="font-size:0.72rem;padding:2px 8px;background:rgba(59,130,246,0.2);color:#60a5fa;border:1px solid rgba(59,130,246,0.3);">⏪ Restore</button>' +
                                '<button class="btn-sm" onclick="deleteSnapshot(\'' + s.pubky + '\',\'' + s.timestamp + '\')" style="font-size:0.72rem;padding:2px 8px;background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3);">🗑</button>' +
                            '</div>' +
                        '</div>' +
                    '</div>';
                }).join('');
            } catch (e) { /* ignore */ }
        }

        document.getElementById('snapshot-create-btn')?.addEventListener('click', async function () {
            var btn = this;
            // Get the first backed-up pubky
            var pubky = null;
            try {
                var listRes = await authFetch('/api/backup/list');
                var listData = await listRes.json();
                if (listData.pubkeys && listData.pubkeys.length > 0) {
                    pubky = listData.pubkeys[0];
                }
            } catch(e) {}
            if (!pubky) { showCopyToast('No backup data to snapshot'); return; }

            btn.disabled = true;
            btn.textContent = '⏳ Creating…';
            try {
                var res = await authFetch('/api/backup/snapshot', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pubky: pubky })
                });
                var data = await res.json();
                if (data.error) {
                    showCopyToast('Error: ' + data.error);
                } else {
                    showCopyToast('Snapshot created: ' + data.timestamp);
                    fetchSnapshots();
                }
            } catch (e) { showCopyToast('Snapshot failed'); }
            btn.disabled = false;
            btn.textContent = '📸 Create Snapshot';
        });

        window.restoreSnapshot = async function(pubky, timestamp) {
            if (!confirm('Restore snapshot ' + timestamp + '?\n\nThis will replace your current backup data with this snapshot. The sync cursor is preserved so new events will still be fetched.')) return;
            try {
                var res = await authFetch('/api/backup/snapshot/restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pubky: pubky, timestamp: timestamp })
                });
                var data = await res.json();
                if (data.error) { showCopyToast('Error: ' + data.error); }
                else { showCopyToast('Restored to ' + timestamp); fetchBackupStatus(); fetchBackupList(); }
            } catch (e) { showCopyToast('Restore failed'); }
        };

        window.deleteSnapshot = async function(pubky, timestamp) {
            if (!confirm('Delete snapshot ' + timestamp + '?')) return;
            try {
                var res = await authFetch('/api/backup/snapshot/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pubky: pubky, timestamp: timestamp })
                });
                var data = await res.json();
                if (data.error) { showCopyToast('Error: ' + data.error); }
                else { showCopyToast('Snapshot deleted'); fetchSnapshots(); }
            } catch (e) { showCopyToast('Delete failed'); }
        };

        // Initial snapshot load
        fetchSnapshots();

        // ─── Migration ─────────────────────────────────────────────
        // Populate migration pubky selector from backup list
        async function populateMigrationSelectors() {
            try {
                var res = await authFetch('/api/backup/list');
                var data = await res.json();
                var sel = document.getElementById('migration-pubky');
                sel.innerHTML = '<option value="">— Select identity —</option>';
                if (data.backups) {
                    data.backups.forEach(function(b) {
                        sel.innerHTML += '<option value="' + b.pubky + '">' + b.pubky.substring(0,16) + '… (' + (b.file_count || 0) + ' files)</option>';
                    });
                }
                // Populate source selector with snapshots
                var snapRes = await authFetch('/api/backup/snapshots');
                var snapData = await snapRes.json();
                var srcSel = document.getElementById('migration-source');
                srcSel.innerHTML = '<option value="latest">Latest backup</option>';
                if (snapData.snapshots) {
                    snapData.snapshots.forEach(function(s) {
                        var label = (s.tier || '') + ' ' + (s.display_ts || s.timestamp) + ' (' + (s.file_count || 0) + ' files)';
                        srcSel.innerHTML += '<option value="snapshot:' + s.timestamp + '">' + label + '</option>';
                    });
                }
            } catch(e) { /* ignore */ }
        }
        populateMigrationSelectors();

        // Preflight
        document.getElementById('migration-preflight-btn')?.addEventListener('click', async function() {
            var pubky = document.getElementById('migration-pubky').value;
            var target = document.getElementById('migration-target').value;
            var source = document.getElementById('migration-source').value;
            if (!pubky) { showToast('Select a pubky first', 'error'); return; }
            if (!target) { showToast('Enter target homeserver URL', 'error'); return; }

            var resultsDiv = document.getElementById('migration-preflight-results');
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = '<span style="color:#c4b5fd;">Running preflight checks…</span>';

            try {
                var res = await authFetch('/api/migration/preflight', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pubky: pubky, target_homeserver: target, source: source })
                });
                var data = await res.json();
                var html = '';
                (data.checks || []).forEach(function(c) {
                    var icon = c.passed ? '✅' : '❌';
                    html += '<div style="margin-bottom:4px;">' + icon + ' <strong>' + c.name + '</strong>: ' + c.detail + '</div>';
                });
                if (data.file_count) {
                    html += '<div style="margin-top:6px;color:#9ca3af;">📦 ' + data.file_count + ' files, ' + formatBytes(data.total_bytes || 0) + '</div>';
                }
                resultsDiv.innerHTML = html;
                document.getElementById('migration-execute-btn').disabled = !data.ok;
                if (data.ok) showToast('Preflight passed ✓', 'success');
            } catch(e) {
                resultsDiv.innerHTML = '<span style="color:#f87171;">Preflight failed: ' + e.message + '</span>';
            }
        });

        // Execute migration
        document.getElementById('migration-execute-btn')?.addEventListener('click', async function() {
            var pubky = document.getElementById('migration-pubky').value;
            var target = document.getElementById('migration-target').value;
            var source = document.getElementById('migration-source').value;
            var signupToken = document.getElementById('migration-signup-token').value;
            var dryRun = document.getElementById('migration-dryrun').checked;

            if (!pubky || !target) { showToast('Complete all required fields', 'error'); return; }

            var confirmMsg = dryRun
                ? 'Start dry-run migration? Data will be uploaded but PKARR will NOT be updated.'
                : '⚠️ LIVE MIGRATION: This will upload data AND update your PKARR record. Continue?';
            if (!confirm(confirmMsg)) return;

            this.disabled = true;
            document.getElementById('migration-progress').style.display = 'block';

            try {
                await authFetch('/api/migration/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        pubky: pubky,
                        target_homeserver: target,
                        source: source,
                        signup_token: signupToken || null,
                        dry_run: dryRun
                    })
                });
                // Start polling status
                pollMigrationStatus();
            } catch(e) {
                showToast('Migration launch failed: ' + e.message, 'error');
                this.disabled = false;
            }
        });

        // Poll migration status
        var migrationPollInterval = null;
        function pollMigrationStatus() {
            if (migrationPollInterval) clearInterval(migrationPollInterval);
            migrationPollInterval = setInterval(async function() {
                try {
                    var res = await authFetch('/api/migration/status');
                    var data = await res.json();
                    var phaseEl = document.getElementById('migration-phase');
                    var fileCountEl = document.getElementById('migration-file-count');
                    var progressBar = document.getElementById('migration-progress-bar');
                    var detailEl = document.getElementById('migration-status-detail');

                    var phaseLabels = {
                        idle: '⏸ Idle', backup: '📸 Creating snapshot…', signup: '🔐 Signing up…',
                        uploading: '📤 Uploading files…', pkarr: '🌐 Updating PKARR…',
                        done: '✅ Complete', error: '❌ Error'
                    };
                    phaseEl.textContent = phaseLabels[data.phase] || data.phase;
                    fileCountEl.textContent = (data.uploaded_files || 0) + ' / ' + (data.total_files || 0) + ' files';

                    var pct = data.total_files > 0 ? Math.round((data.uploaded_files / data.total_files) * 100) : 0;
                    progressBar.style.width = pct + '%';

                    var detail = formatBytes(data.uploaded_bytes || 0) + ' / ' + formatBytes(data.total_bytes || 0);
                    if (data.dry_run) detail += ' (dry run)';
                    if (data.error) detail += ' — ' + data.error;
                    detailEl.textContent = detail;

                    if (data.phase === 'done' || data.phase === 'error') {
                        clearInterval(migrationPollInterval);
                        migrationPollInterval = null;
                        document.getElementById('migration-execute-btn').disabled = false;
                        if (data.phase === 'done') {
                            showToast('Migration complete! ' + (data.dry_run ? '(dry run)' : 'PKARR updated.'), 'success');
                        } else {
                            showToast('Migration error: ' + (data.error || 'Unknown'), 'error');
                        }
                    }
                } catch(e) { /* ignore poll errors */ }
            }, 1000);
        }

        // Export bundle button
        document.getElementById('backup-export-btn')?.addEventListener('click', async function () {
            var pubky = document.getElementById('backup-export-select').value;
            if (!pubky) return;
            var includeKeys = document.getElementById('backup-export-keys').checked;

            var res = await authFetch('/api/backup/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pubky: pubky, include_keys: includeKeys })
            });
            var data = await res.json();
            var resultEl = document.getElementById('backup-export-result');

            if (res.ok) {
                resultEl.style.display = '';
                resultEl.innerHTML = '<strong>📦 Recovery Bundle</strong><br>' +
                    'Pubky: <code>' + data.pubky + '</code><br>' +
                    'Files: ' + data.file_count + ' | Size: ' + formatBytes(data.total_size || 0) + '<br>' +
                    (data.secret_key ? '🔑 Secret key included' : 'No secret key') + '<br>' +
                    '<button class="btn-sm btn-secondary" style="margin-top:8px;" onclick="copyToClipboard(JSON.stringify(' + JSON.stringify(data).replace(/'/g, "\\'") + ', null, 2), \'Bundle copied to clipboard\')">📋 Copy JSON</button>';
            } else {
                resultEl.style.display = '';
                resultEl.innerHTML = '❌ ' + (data.error || 'Export failed');
            }
        });

        // Verify button
        document.getElementById('backup-verify-btn')?.addEventListener('click', async function () {
            var pubky = document.getElementById('backup-verify-select').value;
            if (!pubky) return;

            var res = await authFetch('/api/backup/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pubky: pubky })
            });
            var data = await res.json();
            var resultEl = document.getElementById('backup-verify-result');

            if (res.ok && data.valid) {
                resultEl.className = 'backup-verify-result';
                resultEl.style.display = '';
                resultEl.innerHTML = '✅ <strong>Backup valid</strong><br>' +
                    'Files: ' + data.file_count + ' | Size: ' + formatBytes(data.total_size || 0) + '<br>' +
                    'Cursor: ' + (data.has_cursor ? 'Present' : 'Missing');
            } else {
                resultEl.className = 'backup-verify-result error';
                resultEl.style.display = '';
                resultEl.innerHTML = '❌ ' + (data.error || 'Verification failed');
            }
        });

        // Load backup data on Recovery tab visit
        document.querySelectorAll('.tab').forEach(function (t) {
            t.addEventListener('click', function () {
                if (t.dataset.tab === 'recovery') {
                    fetchBackupStatus();
                    fetchBackupList();
                }
            });
        });

        // ========== Stage 4: Hosting Wizard ==========

        // Legacy wizard code removed. Unification implemented above.

        // ========== Stage 4: API Explorer ==========

        document.querySelectorAll('.api-try-btn').forEach(function (btn) {
            btn.addEventListener('click', async function () {
                var endpoint = btn.closest('.api-endpoint');
                var method = endpoint.dataset.method;
                var path = endpoint.dataset.path;
                var responseEl = document.getElementById('hs-api-response');
                var bodyEl = document.getElementById('hs-api-resp-body');
                var statusEl = document.getElementById('hs-api-resp-status');
                var methodEl = document.getElementById('hs-api-resp-method');
                var pathEl = document.getElementById('hs-api-resp-path');

                btn.textContent = '⏳';
                responseEl.style.display = '';
                methodEl.textContent = method;
                methodEl.className = 'api-method ' + method.toLowerCase();
                pathEl.textContent = path;
                bodyEl.textContent = 'Loading…';

                try {
                    // Route through our proxy
                    var proxyPath = '/api/homeserver/info';
                    if (path === '/users') proxyPath = '/api/homeserver/users';
                    else if (path === '/generate_signup_token') proxyPath = '/api/homeserver/signup-token';
                    else if (path === '/metrics') proxyPath = '/api/homeserver/proxy-url';
                    else proxyPath = '/api/homeserver/info';

                    var res = await authFetch(proxyPath);
                    var data = await res.json();
                    statusEl.textContent = res.status;
                    statusEl.className = 'badge ' + (res.ok ? 'badge-success' : 'badge-error');
                    bodyEl.textContent = JSON.stringify(data, null, 2);
                } catch (e) {
                    statusEl.textContent = 'Error';
                    statusEl.className = 'badge badge-error';
                    bodyEl.textContent = e.message;
                }
                btn.textContent = 'Try';
            });
        });

        // ========== Stage 4: File Breadcrumb ==========

        window.renderFileBreadcrumb = function (path, onClick) {
            var bc = document.getElementById('hs-files-breadcrumb');
            if (!bc) return;
            bc.style.display = '';
            bc.innerHTML = '';
            var parts = path.split('/').filter(Boolean);
            parts.unshift('root');
            parts.forEach(function (part, idx) {
                if (idx > 0) {
                    var sep = document.createElement('span');
                    sep.className = 'file-breadcrumb-sep';
                    sep.textContent = '/';
                    bc.appendChild(sep);
                }
                var span = document.createElement('span');
                span.className = 'file-breadcrumb-item';
                span.textContent = part;
                span.addEventListener('click', function () {
                    var newPath = '/' + parts.slice(1, idx + 1).join('/');
                    if (onClick) onClick(newPath || '/');
                });
                bc.appendChild(span);
            });
        };

    } // end initEventListeners
})();

// ═══════ Layout Editor ═══════
(function() {
    'use strict';
    var currentLayout = null;

    // Open/close editor
    document.getElementById('layout-edit-btn').addEventListener('click', openLayoutEditor);
    document.getElementById('layout-editor-close').addEventListener('click', closeLayoutEditor);
    document.getElementById('layout-editor-overlay').addEventListener('click', function(e) {
        if (e.target === this) closeLayoutEditor();
    });
    document.getElementById('layout-save-btn').addEventListener('click', saveLayout);
    document.getElementById('layout-reset-btn').addEventListener('click', resetLayout);

    function openLayoutEditor() {
        fetch('/api/layout').then(r => r.json()).then(layout => {
            currentLayout = layout;
            renderPageList();
            document.getElementById('layout-editor-overlay').style.display = 'flex';
        }).catch(err => console.error('Failed to load layout:', err));
    }

    function closeLayoutEditor() {
        document.getElementById('layout-editor-overlay').style.display = 'none';
    }

    function renderPageList() {
        var container = document.getElementById('layout-page-list');
        container.innerHTML = '';
        currentLayout.pages.forEach(function(page, pageIdx) {
            var item = document.createElement('div');
            item.className = 'layout-page-item';
            item.draggable = true;
            item.dataset.pageIdx = pageIdx;

            // Header row
            var header = document.createElement('div');
            header.className = 'layout-page-header';

            var handle = document.createElement('span');
            handle.className = 'layout-drag-handle';
            handle.textContent = '⠿';

            var icon = document.createElement('span');
            icon.className = 'layout-page-icon';
            icon.textContent = page.icon;

            var label = document.createElement('input');
            label.className = 'layout-page-label';
            label.type = 'text';
            label.value = page.label;
            label.addEventListener('change', function() {
                currentLayout.pages[pageIdx].label = this.value;
            });
            label.addEventListener('click', function(e) { e.stopPropagation(); });

            var vis = document.createElement('button');
            vis.className = 'layout-vis-toggle' + (page.visible ? '' : ' hidden');
            vis.textContent = page.visible ? '👁' : '👁‍🗨';
            vis.title = page.visible ? 'Visible — click to hide' : 'Hidden — click to show';
            vis.addEventListener('click', function(e) {
                e.stopPropagation();
                currentLayout.pages[pageIdx].visible = !currentLayout.pages[pageIdx].visible;
                renderPageList();
            });

            var expand = document.createElement('button');
            expand.className = 'layout-page-expand';
            expand.textContent = '▶';
            expand.addEventListener('click', function(e) {
                e.stopPropagation();
                var panel = item.querySelector('.layout-cards-panel');
                panel.classList.toggle('open');
                expand.classList.toggle('open');
            });

            header.appendChild(handle);
            header.appendChild(icon);
            header.appendChild(label);
            header.appendChild(vis);
            header.appendChild(expand);

            // Cards panel
            var cardsPanel = document.createElement('div');
            cardsPanel.className = 'layout-cards-panel';
            page.cards.forEach(function(card, cardIdx) {
                var cardItem = document.createElement('div');
                cardItem.className = 'layout-card-item';
                cardItem.draggable = true;
                cardItem.dataset.cardIdx = cardIdx;

                var cardHandle = document.createElement('span');
                cardHandle.className = 'layout-card-handle';
                cardHandle.textContent = '⠿';

                var check = document.createElement('input');
                check.type = 'checkbox';
                check.className = 'layout-card-check';
                check.checked = card.visible;
                check.addEventListener('change', function() {
                    currentLayout.pages[pageIdx].cards[cardIdx].visible = this.checked;
                });

                var name = document.createElement('span');
                name.className = 'layout-card-name';
                name.textContent = card.id.replace(/-/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });

                cardItem.appendChild(cardHandle);
                cardItem.appendChild(check);
                cardItem.appendChild(name);
                cardsPanel.appendChild(cardItem);

                // Card drag-and-drop (reorder within page)
                cardItem.addEventListener('dragstart', function(e) {
                    e.stopPropagation();
                    e.dataTransfer.setData('text/plain', 'card:' + pageIdx + ':' + cardIdx);
                    e.dataTransfer.effectAllowed = 'move';
                    cardItem.classList.add('dragging');
                });
                cardItem.addEventListener('dragend', function() {
                    cardItem.classList.remove('dragging');
                    document.querySelectorAll('.layout-card-item.drag-over').forEach(function(el) { el.classList.remove('drag-over'); });
                });
                cardItem.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.dataTransfer.dropEffect = 'move';
                    cardItem.classList.add('drag-over');
                });
                cardItem.addEventListener('dragleave', function() {
                    cardItem.classList.remove('drag-over');
                });
                cardItem.addEventListener('drop', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    cardItem.classList.remove('drag-over');
                    var data = e.dataTransfer.getData('text/plain');
                    if (!data.startsWith('card:')) return;
                    var parts = data.split(':');
                    var srcPage = parseInt(parts[1], 10);
                    var srcCard = parseInt(parts[2], 10);
                    if (srcPage !== pageIdx) return; // only within same page
                    var cards = currentLayout.pages[pageIdx].cards;
                    var moved = cards.splice(srcCard, 1)[0];
                    var targetIdx = parseInt(cardItem.dataset.cardIdx, 10);
                    if (srcCard < targetIdx) targetIdx--;
                    cards.splice(targetIdx, 0, moved);
                    renderPageList();
                });
            });

            item.appendChild(header);
            item.appendChild(cardsPanel);
            container.appendChild(item);

            // Page drag-and-drop (reorder pages)
            item.addEventListener('dragstart', function(e) {
                if (e.target !== item && !handle.contains(e.target)) return;
                e.dataTransfer.setData('text/plain', 'page:' + pageIdx);
                e.dataTransfer.effectAllowed = 'move';
                item.classList.add('dragging');
            });
            item.addEventListener('dragend', function() {
                item.classList.remove('dragging');
                document.querySelectorAll('.layout-page-item.drag-over').forEach(function(el) { el.classList.remove('drag-over'); });
            });
            item.addEventListener('dragover', function(e) {
                e.preventDefault();
                var data = e.dataTransfer.types.indexOf('text/plain') >= 0;
                if (data) {
                    e.dataTransfer.dropEffect = 'move';
                    item.classList.add('drag-over');
                }
            });
            item.addEventListener('dragleave', function() {
                item.classList.remove('drag-over');
            });
            item.addEventListener('drop', function(e) {
                e.preventDefault();
                item.classList.remove('drag-over');
                var data = e.dataTransfer.getData('text/plain');
                if (!data.startsWith('page:')) return;
                var srcIdx = parseInt(data.split(':')[1], 10);
                var targetIdx = parseInt(item.dataset.pageIdx, 10);
                if (srcIdx === targetIdx) return;
                var pages = currentLayout.pages;
                var moved = pages.splice(srcIdx, 1)[0];
                if (srcIdx < targetIdx) targetIdx--;
                pages.splice(targetIdx, 0, moved);
                renderPageList();
            });
        });
    }

    function saveLayout() {
        fetch('/api/layout', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentLayout)
        }).then(r => r.json()).then(function(result) {
            if (result.status === 'ok') {
                rebuildSidebar();
                closeLayoutEditor();
            } else {
                alert('Save failed: ' + (result.error || 'unknown'));
            }
        }).catch(err => alert('Save failed: ' + err));
    }

    function resetLayout() {
        if (!confirm('Reset layout to defaults? This will undo all customizations.')) return;
        fetch('/api/layout/reset', { method: 'POST' }).then(r => r.json()).then(function(layout) {
            currentLayout = layout;
            renderPageList();
            rebuildSidebar();
        }).catch(err => alert('Reset failed: ' + err));
    }

    function rebuildSidebar() {
        if (!currentLayout) return;
        var nav = document.getElementById('nav-tabs');
        // Update nav item labels and visibility based on layout
        currentLayout.pages.forEach(function(page) {
            var btn = nav.querySelector('[data-tab="' + page.id + '"]');
            if (!btn) {
                // Try alternate tab names (network -> network, etc.)
                var altId = page.id === 'networks' ? 'network' : page.id;
                btn = nav.querySelector('[data-tab="' + altId + '"]');
            }
            if (btn) {
                // Update label text (preserve inner SVG icon)
                var svg = btn.querySelector('svg');
                btn.textContent = '';
                if (svg) btn.appendChild(svg);
                btn.appendChild(document.createTextNode('\n                        ' + page.label + '\n                    '));
                // Update visibility
                var section = btn.closest('.nav-section');
                if (section) {
                    if (page.visible) {
                        btn.style.display = '';
                    } else {
                        btn.style.display = 'none';
                    }
                }
            }
        });
    }

    // Apply layout on page load
    fetch('/api/layout').then(r => r.json()).then(function(layout) {
        currentLayout = layout;
        rebuildSidebar();
    }).catch(function() { /* layout API not available, use default HTML */ });

})();
