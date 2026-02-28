// Pubky Node Dashboard
(function () {
    'use strict';

    const POLL_INTERVAL = 3000;
    const HISTORY_KEY = 'pubky_explorer_history';
    const MAX_HISTORY = 10;

    // ========== Tab Navigation ==========

    function initTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(function (tab) {
            tab.addEventListener('click', function () {
                const target = tab.dataset.tab;
                // Update tab buttons
                tabs.forEach(function (t) { t.classList.remove('active'); });
                tab.classList.add('active');
                // Update content panels
                document.querySelectorAll('.tab-content').forEach(function (panel) {
                    panel.classList.remove('active');
                });
                var targetPanel = document.getElementById('tab-' + target);
                if (targetPanel) {
                    targetPanel.classList.add('active');
                }
            });
        });
    }

    // ========== Status Polling ==========

    async function fetchStatus() {
        try {
            const res = await fetch('/api/status');
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

    function setStatus(online) {
        var el = document.getElementById('connection-status');
        el.className = 'status-indicator ' + (online ? 'online' : 'offline');
        el.querySelector('.status-label').textContent = online ? 'Connected' : 'Disconnected';
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
        document.getElementById('uptime').textContent = formatUptime(data.uptime_secs);
        var dhtSize = data.dht ? data.dht.dht_size_estimate : 0;
        document.getElementById('routing-table-size').textContent = formatNumber(dhtSize);
        document.getElementById('watchlist-count').textContent = data.watchlist.key_count;

        // DHT Panel
        if (data.dht) {
            var dht = data.dht;
            document.getElementById('node-id').textContent = truncateId(dht.id, 18);
            document.getElementById('node-id').title = dht.id;
            document.getElementById('listen-addr').textContent = dht.local_addr;
            document.getElementById('dht-mode').textContent =
                dht.server_mode ? '● Server' : '● Client';
            document.getElementById('dht-mode').style.color =
                dht.server_mode ? 'var(--green)' : 'var(--amber)';
            document.getElementById('firewalled').textContent =
                dht.firewalled ? '● Yes' : '● No';
            document.getElementById('firewalled').style.color =
                dht.firewalled ? 'var(--red)' : 'var(--green)';
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

            document.getElementById('upnp-status').textContent =
                isActive ? '● Active' : isFailed ? '● Failed' : '● ' + upnp.status;
            document.getElementById('upnp-status').style.color =
                isActive ? 'var(--green)' : isFailed ? 'var(--red)' : 'var(--amber)';

            document.getElementById('upnp-external-ip').textContent =
                upnp.external_ip || '--';
            document.getElementById('upnp-port').textContent =
                upnp.port ? 'UDP ' + upnp.port : '--';

            document.getElementById('upnp-badge').textContent =
                isActive ? 'Mapped' : upnp.status;
            document.getElementById('upnp-badge').className =
                'badge' + (isActive ? ' badge-active' : isFailed ? ' badge-warning' : '');
        }

        // Watchlist Panel
        var wl = data.watchlist;
        document.getElementById('watchlist-status').textContent =
            wl.enabled ? '● Active' : '○ Disabled';
        document.getElementById('watchlist-status').style.color =
            wl.enabled ? 'var(--green)' : 'var(--text-muted)';
        document.getElementById('watchlist-badge').textContent =
            wl.enabled ? wl.key_count + ' keys' : 'Off';
        document.getElementById('watchlist-badge').className =
            'badge' + (wl.enabled ? (wl.key_count > 0 ? ' badge-active' : ' badge-warning') : '');
        document.getElementById('republish-interval').textContent =
            formatInterval(wl.republish_interval_secs);

        // Watchlist keys (count only — keys redacted for privacy)
        var keysContainer = document.getElementById('watchlist-keys');
        keysContainer.innerHTML = '';
        if (wl.key_count === 0) {
            keysContainer.innerHTML = '<div class="empty-state">No keys configured</div>';
        } else {
            keysContainer.innerHTML = '<div class="empty-state">' + wl.key_count + ' key(s) monitored</div>';
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
            document.getElementById(id).style.display = 'none';
        });
        if (state) {
            document.getElementById(state).style.display = '';
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
            row.innerHTML =
                '<span class="dns-name">' + escapeHtml(rec.name) + '</span>' +
                '<span><span class="' + badgeClass + '">' + rec.record_type + '</span></span>' +
                '<span class="dns-value" title="' + escapeHtml(rec.value) + '">' + escapeHtml(rec.value) + '</span>' +
                '<span class="dns-ttl">' + rec.ttl + '</span>';
            body.appendChild(row);
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

        errorEl.style.display = 'none';

        var raw = input.value;
        var result = validateKey(raw);
        if (!result.valid) {
            errorEl.textContent = result.error;
            errorEl.style.display = '';
            return;
        }

        var key = result.key;
        btn.disabled = true;
        btn.querySelector('span').textContent = 'Resolving…';
        showExplorer('explorer-loading');

        try {
            var res = await fetch('/api/resolve/' + encodeURIComponent(key));
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
            errorEl.style.display = '';
            showExplorer('explorer-error');
        } finally {
            btn.disabled = false;
            btn.querySelector('span').textContent = 'Resolve';
        }
    };

    // ========== Init ==========

    initTabs();
    poll();
    setInterval(poll, POLL_INTERVAL);

    // Explorer: Enter key
    document.getElementById('explorer-input').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            resolveKey();
        }
    });

    renderHistory();
})();
