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
            var res = await fetch('/api/watchlist');
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
            var res = await fetch('/api/watchlist', {
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
            var res = await fetch('/api/watchlist/' + encodeURIComponent(key), {
                method: 'DELETE',
            });
            if (!res.ok) return;
            var data = await res.json();
            renderWatchlistKeys(data.keys);
        } catch (e) { /* ignore */ }
    }

    // ========== Init ==========

    initTabs();
    poll();
    setInterval(poll, POLL_INTERVAL);
    fetchWatchlistKeys();

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
            var res = await fetch('/api/dns/toggle', {
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
            var res = await fetch('/api/dns/' + endpoint, { method: 'POST' });
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
            fetch('/api/node/restart', { method: 'POST' });
            document.getElementById('connection-status').querySelector('.status-label').textContent = 'Restarting...';
        }
    });
    document.getElementById('node-shutdown-btn').addEventListener('click', function () {
        if (confirm('Shutdown Pubky Node? You will need to start it again manually.')) {
            fetch('/api/node/shutdown', { method: 'POST' });
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
            var res = await fetch('/api/proxy/setup-hosts', { method: 'POST' });
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
            var res = await fetch('/api/proxy/reset-hosts', { method: 'POST' });
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
        fetch('/api/proxy/hosts-status').then(function (r) { return r.json(); }).then(function (d) {
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
            await fetch('/api/keys/vanity/start', {
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
        await fetch('/api/keys/vanity/stop', { method: 'POST' });
        vanityStartBtn.style.display = 'inline-flex';
        vanityStopBtn.style.display = 'none';
        document.getElementById('vanity-progress').style.display = 'none';
        document.getElementById('vanity-badge').textContent = 'Stopped';
        document.getElementById('vanity-badge').className = 'badge';
    });

    async function pollVanity() {
        try {
            var res = await fetch('/api/keys/vanity/status');
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

    renderHistory();
})();
