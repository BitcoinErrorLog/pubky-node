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
        var overlay = document.createElement('div');
        overlay.id = 'auth-setup-overlay';
        overlay.innerHTML = [
            '<div class="auth-setup-card">',
            '  <div class="auth-setup-icon">🔐</div>',
            '  <h2>Welcome to Pubky Node</h2>',
            '  <p class="auth-setup-desc">Set a dashboard password to secure your node.</p>',
            '  <div class="auth-setup-field">',
            '    <input type="password" id="auth-setup-pass" placeholder="Choose a password (4+ characters)" autocomplete="new-password">',
            '  </div>',
            '  <div class="auth-setup-field">',
            '    <input type="password" id="auth-setup-confirm" placeholder="Confirm password" autocomplete="new-password">',
            '  </div>',
            '  <button id="auth-setup-btn" class="btn-primary auth-setup-submit">🚀 Set Password & Enter</button>',
            '  <div id="auth-setup-error" class="auth-setup-error"></div>',
            '</div>'
        ].join('\n');
        document.body.appendChild(overlay);

        var btn = document.getElementById('auth-setup-btn');
        var passInput = document.getElementById('auth-setup-pass');
        var confirmInput = document.getElementById('auth-setup-confirm');
        var errorEl = document.getElementById('auth-setup-error');

        async function doSetup() {
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
            btn.textContent = 'Setting up...';

            try {
                var res = await fetch('/api/auth/setup', {
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
                    errorEl.textContent = data.error || 'Setup failed.';
                    btn.disabled = false;
                    btn.textContent = '🚀 Set Password & Enter';
                }
            } catch (e) {
                errorEl.textContent = 'Network error: ' + e.message;
                btn.disabled = false;
                btn.textContent = '🚀 Set Password & Enter';
            }
        }

        btn.addEventListener('click', doSetup);
        confirmInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') doSetup(); });
        passInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') confirmInput.focus(); });
        setTimeout(function () { passInput.focus(); }, 100);
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
        const tabs = document.querySelectorAll('.tab');
        // Include icon buttons that act as tab switchers
        const allTabTriggers = document.querySelectorAll('.tab, [data-tab].btn-icon');

        function switchToTab(target) {
            // Update tab button active states (only for .tab elements)
            tabs.forEach(function (t) { t.classList.remove('active'); });
            var matchingTab = document.querySelector('.tab[data-tab="' + target + '"]');
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

        setStatus(true);

        // Header
        document.getElementById('version').textContent = 'v' + data.version;

        // Stats
        var uptimeStr = formatUptime(data.uptime_secs);
        var uptimeEl = document.getElementById('uptime');
        if (uptimeEl) uptimeEl.textContent = uptimeStr;
        var headerUptime = document.getElementById('header-uptime');
        if (headerUptime) headerUptime.textContent = uptimeStr;
        var dhtSize = data.dht ? data.dht.dht_size_estimate : 0;
        var rtEl = document.getElementById('routing-table-size');
        if (rtEl) rtEl.textContent = formatNumber(dhtSize);
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
    }

    async function poll() {
        var data = await fetchStatus();
        update(data);
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

    function initDashboard() {
        initTabs();
        poll();
        setInterval(poll, POLL_INTERVAL);
        fetchWatchlistKeys();
        initEventListeners();
    }

    // Start auth check — initDashboard() called after successful login/setup
    checkAuthSetup();

    function initEventListeners() {

        // Explorer: Resolve button click
        document.getElementById('explorer-btn').addEventListener('click', function () {
            resolveKey();
        });

        // Explorer: Enter key
        document.getElementById('explorer-input').addEventListener('keydown', function (e) {
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
        document.getElementById('watchlist-add-btn').addEventListener('click', addWatchlistKey);
        document.getElementById('watchlist-input').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addWatchlistKey();
            }
        });

        // Watchlist: Remove + Copy (delegated)
        document.getElementById('watchlist-keys').addEventListener('click', function (e) {
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
        document.getElementById('relay-copy').addEventListener('click', function () {
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

        document.getElementById('dns-enable-btn').addEventListener('click', function () {
            toggleDns(true);
        });
        document.getElementById('dns-disable-btn').addEventListener('click', function () {
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

        document.getElementById('dns-set-system-btn').addEventListener('click', function () {
            setSystemDns('set-system');
        });
        document.getElementById('dns-reset-system-btn').addEventListener('click', function () {
            setSystemDns('reset-system');
        });
        document.getElementById('dns-reset-connected-btn').addEventListener('click', function () {
            setSystemDns('reset-system', 'dns-connected-feedback');
        });
        document.getElementById('dns-disable-btn2').addEventListener('click', function () {
            toggleDns(false);
        });

        // Node Controls
        document.getElementById('node-restart-btn').addEventListener('click', function () {
            if (confirm('Restart Pubky Node?')) {
                authFetch('/api/node/restart', { method: 'POST' });
                document.getElementById('connection-status').querySelector('.status-label').textContent = 'Restarting...';
            }
        });
        document.getElementById('node-shutdown-btn').addEventListener('click', function () {
            if (confirm('Shutdown Pubky Node? You will need to start it again manually.')) {
                authFetch('/api/node/shutdown', { method: 'POST' });
                document.getElementById('connection-status').querySelector('.status-label').textContent = 'Shutting down...';
            }
        });

        // === Collapsible Guides ===
        document.getElementById('upnp-guide-toggle').addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });
        document.getElementById('dns-connected-toggle').addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });
        document.getElementById('vanity-info-toggle').addEventListener('click', function () {
            this.parentElement.classList.toggle('expanded');
        });

        // === HTTP Proxy Setup ===
        document.getElementById('proxy-setup-btn').addEventListener('click', async function () {
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
        document.getElementById('proxy-reset-btn').addEventListener('click', async function () {
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
        document.getElementById('vanity-copy-pubkey').addEventListener('click', function () {
            navigator.clipboard.writeText(document.getElementById('vanity-pubkey').textContent);
            this.title = 'Copied!';
            setTimeout(function () { document.getElementById('vanity-copy-pubkey').title = 'Copy public key'; }, 1500);
        });
        document.getElementById('vanity-copy-seed').addEventListener('click', function () {
            navigator.clipboard.writeText(document.getElementById('vanity-seed').textContent);
            this.title = 'Copied!';
            setTimeout(function () { document.getElementById('vanity-copy-seed').title = 'Copy seed'; }, 1500);
        });

        // Save vanity key to vault
        document.getElementById('vanity-save-vault-btn').addEventListener('click', async function () {
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
        document.getElementById('publisher-add-record').addEventListener('click', function () {
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

        // Generate keypair
        document.getElementById('publisher-generate-key').addEventListener('click', function () {
            // Generate 32 random bytes as secret key
            var bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            var hex = Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
            document.getElementById('publisher-secret-key').value = hex;
            document.getElementById('publisher-secret-key').type = 'text';

            // Show info panel — actual pubkey will be computed server-side on publish
            var info = document.getElementById('publisher-generated-info');
            info.style.display = 'block';
            document.getElementById('publisher-pubkey-display').textContent = '(will be computed on publish)';
        });

        // Toggle key visibility
        document.getElementById('publisher-toggle-key').addEventListener('click', function () {
            var inp = document.getElementById('publisher-secret-key');
            inp.type = inp.type === 'password' ? 'text' : 'password';
        });

        // Copy pubkey
        document.getElementById('publisher-copy-pubkey').addEventListener('click', function () {
            var text = document.getElementById('publisher-pubkey-display').textContent;
            if (text && !text.startsWith('(')) {
                navigator.clipboard.writeText(text);
                this.textContent = '✓';
                var btn = this;
                setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
            }
        });

        // Publish to DHT
        document.getElementById('publisher-submit-btn').addEventListener('click', async function () {
            var secretKey = document.getElementById('publisher-secret-key').value.trim();
            var statusEl = document.getElementById('publisher-status');
            var badge = document.getElementById('publisher-badge');

            var secretHex = normalizeSecretKey(secretKey);
            if (!secretHex) {
                statusEl.style.display = 'block';
                statusEl.style.background = 'rgba(239,68,68,0.15)';
                statusEl.style.color = '#f87171';
                statusEl.textContent = '❌ Invalid key format. Accepts hex (64/128 chars) or z-base-32.';
                return;
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

                    // Show the public key
                    document.getElementById('publisher-generated-info').style.display = 'block';
                    document.getElementById('publisher-pubkey-display').textContent = data.public_key;

                    // Refresh watchlist
                    if (addToWatchlist) {
                        fetchWatchlistKeys();
                    }

                    // Save key to vault if checkbox checked
                    if (document.getElementById('publisher-save-vault').checked && data.public_key) {
                        try {
                            await authFetch('/api/vault/add', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    name: 'PKARR: ' + data.public_key.slice(0, 8) + '...',
                                    secret_hex: secretHex,
                                    pubkey: data.public_key,
                                    key_type: 'pkarr'
                                })
                            });
                        } catch (e) { /* ignore vault errors */ }
                    }

                    // Clear secret key for security
                    document.getElementById('publisher-secret-key').value = '';
                    document.getElementById('publisher-secret-key').type = 'password';
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
        document.getElementById('settings-change-pw-btn').addEventListener('click', async function () {
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
                } else if (!data.unlocked) {
                    lockedEl.style.display = 'block';
                    badge.textContent = 'Locked';
                    badge.className = 'badge badge-warning';
                } else {
                    unlockedEl.style.display = 'block';
                    badge.textContent = 'Unlocked';
                    badge.className = 'badge badge-green';
                    loadVaultKeys();
                }
            } catch (e) { /* ignore */ }
        }

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
        document.getElementById('vault-export-all-btn').addEventListener('click', async function () {
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
        document.getElementById('vault-import-btn').addEventListener('click', function () {
            document.getElementById('vault-import-file').click();
        });
        document.getElementById('vault-import-file').addEventListener('change', function () {
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
        document.getElementById('vault-create-btn').addEventListener('click', async function () {
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
        document.getElementById('vault-unlock-btn').addEventListener('click', async function () {
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
        document.getElementById('vault-lock-btn').addEventListener('click', async function () {
            await authFetch('/api/vault/lock', { method: 'POST' });
            loadVaultStatus();
        });

        // Show/hide add key form
        document.getElementById('vault-add-manual-btn').addEventListener('click', function () {
            var form = document.getElementById('vault-add-form');
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
        });
        document.getElementById('vault-add-cancel-btn').addEventListener('click', function () {
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

        document.getElementById('vault-add-save-btn').addEventListener('click', async function () {
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
        document.getElementById('vault-unlock-pw').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') document.getElementById('vault-unlock-btn').click();
        });
        document.getElementById('vault-create-confirm').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') document.getElementById('vault-create-btn').click();
        });

        // ========== Homeserver Tab ==========

        // Status polling
        async function loadHsStatus() {
            try {
                var res = await authFetch('/api/homeserver/status');
                var data = await res.json();
                var badge = document.getElementById('hs-state-badge');
                badge.textContent = data.state.charAt(0).toUpperCase() + data.state.slice(1);
                badge.className = 'badge' + (data.state === 'running' ? ' badge-success' : data.state === 'error' ? ' badge-error' : '');

                var info = document.getElementById('hs-server-info');
                var startBtn = document.getElementById('hs-start-btn');
                var stopBtn = document.getElementById('hs-stop-btn');

                if (data.state === 'running') {
                    info.style.display = 'block';
                    startBtn.style.display = 'none';
                    stopBtn.style.display = 'inline-flex';
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
                } else {
                    info.style.display = 'none';
                    startBtn.style.display = 'inline-flex';
                    stopBtn.style.display = 'none';
                    document.getElementById('hs-stats-badge').textContent = 'Offline';
                    document.getElementById('hs-stats-badge').className = 'badge';
                }
            } catch (e) { /* ignore */ }
        }

        // Load stats from admin /info
        async function loadHsStats() {
            try {
                var res = await authFetch('/api/homeserver/info');
                if (!res.ok) return;
                var data = await res.json();
                var badge = document.getElementById('hs-stats-badge');
                badge.textContent = 'Connected';
                badge.className = 'badge badge-success';
                document.getElementById('hs-version').textContent = data.version || '—';
                document.getElementById('hs-users').textContent = data.users_count != null ? data.users_count : '—';
                document.getElementById('hs-signup-mode').textContent = data.signup_mode || '—';
                document.getElementById('hs-server-key').textContent = data.public_key || '—';
            } catch (e) { /* ignore */ }
        }

        // Prerequisites check
        document.getElementById('hs-check-btn').addEventListener('click', async function () {
            this.textContent = '⏳';
            try {
                var res = await authFetch('/api/homeserver/setup-check');
                var data = await res.json();
                document.getElementById('hs-pg-status').textContent = data.postgres_ok ? '✅ ' + data.postgres_msg : '❌ ' + data.postgres_msg;
                document.getElementById('hs-pg-status').style.color = data.postgres_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-db-status').textContent = data.db_ok ? '✅ ' + data.db_msg : '❌ ' + data.db_msg;
                document.getElementById('hs-db-status').style.color = data.db_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-bin-status').textContent = data.binary_ok ? '✅ ' + data.binary_path : '❌ Not found';
                document.getElementById('hs-bin-status').style.color = data.binary_ok ? '#4ade80' : '#f87171';
                document.getElementById('hs-cfg-status').textContent = data.config_ok ? '✅ ' + data.config_path : '❌ Not generated';
                document.getElementById('hs-cfg-status').style.color = data.config_ok ? '#4ade80' : '#f87171';
            } catch (e) { /* ignore */ }
            this.textContent = 'Check';
        });

        // Generate config
        document.getElementById('hs-gen-config-btn').addEventListener('click', async function () {
            try {
                var res = await authFetch('/api/homeserver/generate-config', { method: 'POST' });
                var data = await res.json();
                this.textContent = data.success ? '✅ Generated' : '❌ Failed';
                var btn = this;
                setTimeout(function () { btn.textContent = 'Generate Config'; }, 2000);
            } catch (e) { /* ignore */ }
        });

        // Fix All — auto-install/configure prerequisites
        document.getElementById('hs-fix-btn').addEventListener('click', async function () {
            var logEl = document.getElementById('hs-fix-log');
            this.disabled = true;
            this.textContent = '⏳ Fixing...';
            logEl.style.display = 'block';
            logEl.innerHTML = '<div style="color:#a5b4fc;">Running auto-fix...</div>';
            try {
                var res = await authFetch('/api/homeserver/fix', { method: 'POST' });
                var data = await res.json();
                logEl.innerHTML = (data.log || []).map(function (l) {
                    return '<div>' + l + '</div>';
                }).join('');
                // Refresh prerequisites after fix
                document.getElementById('hs-check-btn').click();
            } catch (e) {
                logEl.innerHTML = '<div style="color:#f87171;">❌ Fix failed: ' + e.message + '</div>';
            }
            this.disabled = false;
            this.textContent = '🔧 Fix All';
        });

        // Start server
        document.getElementById('hs-start-btn').addEventListener('click', async function () {
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
        document.getElementById('hs-stop-btn').addEventListener('click', async function () {
            this.disabled = true;
            try {
                await authFetch('/api/homeserver/stop', { method: 'POST' });
            } catch (e) { /* ignore */ }
            this.disabled = false;
            loadHsStatus();
        });

        // Generate signup token
        document.getElementById('hs-gen-token-btn').addEventListener('click', async function () {
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
                }
            } catch (e) {
                document.getElementById('hs-invite-badge').textContent = 'Error';
                document.getElementById('hs-invite-badge').className = 'badge badge-error';
            }
            this.textContent = 'Generate Token';
        });

        // Copy token
        document.getElementById('hs-token-copy').addEventListener('click', function () {
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
        document.getElementById('hs-save-config-btn').addEventListener('click', async function () {
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

        document.getElementById('ring-export-close').addEventListener('click', function () {
            document.getElementById('ring-export-modal').classList.remove('active');
            document.getElementById('export-qr-container').innerHTML = '';
        });

        // Close on overlay click
        document.getElementById('ring-export-modal').addEventListener('click', function (e) {
            if (e.target === this) {
                this.classList.remove('active');
                document.getElementById('export-qr-container').innerHTML = '';
            }
        });

        document.getElementById('export-copy-hex').addEventListener('click', function () {
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

    } // end initEventListeners
})();
