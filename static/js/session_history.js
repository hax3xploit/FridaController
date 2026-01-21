// static/js/session_history.js
if (!window.__sessionHistoryLoaded) {
  window.__sessionHistoryLoaded = true;

  // Session History Management
  const MAX_HISTORY_ITEMS = 10;
  const STORAGE_KEY = 'frida_session_history';

  // Session history structure:
  // {
  //   sessions: [
  //     {
  //       id: 'uuid',
  //       identifier: 'com.example.app',
  //       name: 'Example App',
  //       timestamp: 1234567890,
  //       scripts: ['SSL Pinning Bypass', 'Root Detection'],
  //       pid: 12345,
  //       device: 'device_serial'
  //     }
  //   ]
  // }

  function loadSessionHistory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return { sessions: [] };
      return JSON.parse(stored);
    } catch (e) {
      console.error('Failed to load session history:', e);
      return { sessions: [] };
    }
  }

  function saveSessionHistory(history) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch (e) {
      console.error('Failed to save session history:', e);
    }
  }

  function addToHistory(target, scriptsUsed = []) {
    const history = loadSessionHistory();

    // Create new session entry
    const session = {
      id: generateSessionId(),
      identifier: target.identifier || target.name,
      name: target.name || target.identifier,
      timestamp: Date.now(),
      scripts: scriptsUsed,
      pid: target.pid || null,
      device: target.device || getCurrentDevice()
    };

    // Remove duplicate entries (same identifier)
    history.sessions = history.sessions.filter(s => s.identifier !== session.identifier);

    // Add to beginning
    history.sessions.unshift(session);

    // Limit to MAX_HISTORY_ITEMS
    if (history.sessions.length > MAX_HISTORY_ITEMS) {
      history.sessions = history.sessions.slice(0, MAX_HISTORY_ITEMS);
    }

    saveSessionHistory(history);
    renderHistoryDropdown();
  }

  function getCurrentDevice() {
    try {
      const deviceSelect = document.getElementById('deviceSelect');
      return deviceSelect ? deviceSelect.value : null;
    } catch {
      return null;
    }
  }

  function generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  function toggleHistoryDropdown() {
    const dropdown = document.getElementById('historyDropdown');
    if (!dropdown) return;

    const isHidden = dropdown.classList.contains('hidden');

    if (isHidden) {
      renderHistoryDropdown();
      dropdown.classList.remove('hidden');

      // Close when clicking outside
      setTimeout(() => {
        document.addEventListener('click', closeHistoryOnClickOutside);
      }, 100);
    } else {
      dropdown.classList.add('hidden');
      document.removeEventListener('click', closeHistoryOnClickOutside);
    }
  }

  function closeHistoryOnClickOutside(event) {
    const dropdown = document.getElementById('historyDropdown');
    const button = document.getElementById('historyDropdownBtn');

    if (dropdown && button &&
        !dropdown.contains(event.target) &&
        !button.contains(event.target)) {
      dropdown.classList.add('hidden');
      document.removeEventListener('click', closeHistoryOnClickOutside);
    }
  }

  function renderHistoryDropdown() {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    const history = loadSessionHistory();

    if (history.sessions.length === 0) {
      historyList.innerHTML = `
        <div class="text-center text-slate-400 py-4 text-sm">
          <svg class="w-8 h-8 mx-auto mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
          </svg>
          <p>No recent targets</p>
          <p class="text-xs mt-1">Your session history will appear here</p>
        </div>
      `;
      return;
    }

    const now = Date.now();
    let html = '<div class="max-h-96 overflow-y-auto custom-scrollbar">';

    history.sessions.forEach((session, index) => {
      const timeAgo = formatTimeAgo(now - session.timestamp);
      const scriptCount = session.scripts.length;

      html += `
        <div class="p-3 hover:bg-slate-700/50 transition-colors border-b border-slate-700 last:border-b-0">
          <div class="flex items-start justify-between gap-3">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <h4 class="text-sm font-medium text-white truncate" title="${session.name}">
                  ${session.name}
                </h4>
                ${session.pid ? `<span class="text-xs text-slate-400">PID ${session.pid}</span>` : ''}
              </div>

              <p class="text-xs text-slate-400 mb-2">
                ${timeAgo}
                ${scriptCount > 0 ? `• ${scriptCount} script${scriptCount > 1 ? 's' : ''}` : ''}
              </p>

              ${scriptCount > 0 ? `
                <div class="flex flex-wrap gap-1 mb-2">
                  ${session.scripts.slice(0, 3).map(script => `
                    <span class="inline-block px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      ${script}
                    </span>
                  `).join('')}
                  ${scriptCount > 3 ? `<span class="text-xs text-slate-400">+${scriptCount - 3} more</span>` : ''}
                </div>
              ` : ''}
            </div>

            <div class="flex flex-col gap-1">
              <button onclick="selectFromHistory('${session.identifier}')"
                      class="px-3 py-1 rounded text-xs bg-emerald-600 hover:bg-emerald-700 text-white transition-colors"
                      title="Reconnect to this target">
                <svg class="w-3 h-3 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Reconnect
              </button>
              ${scriptCount > 0 ? `
                <button onclick="replaySession('${session.id}')"
                        class="px-3 py-1 rounded text-xs bg-blue-600 hover:bg-blue-700 text-white transition-colors"
                        title="Replay this session with same scripts">
                  <svg class="w-3 h-3 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Replay
                </button>
              ` : ''}
              <button onclick="removeFromHistory('${session.identifier}')"
                      class="px-3 py-1 rounded text-xs bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white transition-colors"
                      title="Remove from history">
                <svg class="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
              </button>
            </div>
          </div>
        </div>
      `;
    });

    html += '</div>';

    // Add clear all button at bottom
    html += `
      <div class="p-3 border-t border-slate-700">
        <button onclick="clearHistory()"
                class="w-full px-3 py-2 rounded text-sm bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-colors">
          Clear All History
        </button>
      </div>
    `;

    historyList.innerHTML = html;
  }

  function formatTimeAgo(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'Just now';
  }

  async function selectFromHistory(identifier) {
    try {
      // Close dropdown
      const dropdown = document.getElementById('historyDropdown');
      if (dropdown) dropdown.classList.add('hidden');

      if (typeof showToast === 'function') {
        showToast(`Reconnecting to ${identifier}...`, 'info');
      }

      // Attempt to attach
      const response = await fetch(`/api/attach/${identifier}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: identifier })
      });

      const result = await response.json();

      if (!response.ok || result.status === 'error') {
        throw new Error(result.message || 'Failed to reconnect');
      }

      // Update UI state
      if (typeof window.setAttachedState === 'function') {
        window.setAttachedState(
          true,
          result.name || identifier,
          result.session_id,
          result.pid,
          false,
          identifier
        );
      }

      if (typeof showToast === 'function') {
        showToast(`✅ Reconnected to ${result.name || identifier}`, 'success');
      }

      if (typeof appendConsole === 'function') {
        appendConsole(`Reconnected to ${result.name || identifier} (PID ${result.pid})`, 'success');
      }

    } catch (e) {
      console.error('Failed to select from history:', e);
      if (typeof showToast === 'function') {
        showToast(`❌ Reconnect failed: ${e.message}`, 'error');
      }
    }
  }

  async function replaySession(sessionId) {
    try {
      const history = loadSessionHistory();
      const session = history.sessions.find(s => s.id === sessionId);

      if (!session) {
        throw new Error('Session not found');
      }

      // Close dropdown
      const dropdown = document.getElementById('historyDropdown');
      if (dropdown) dropdown.classList.add('hidden');

      if (typeof showToast === 'function') {
        showToast(`Replaying session: ${session.name}...`, 'info');
      }

      // First, reconnect to target
      await selectFromHistory(session.identifier);

      // Wait a bit for connection to establish
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Load each script in order
      if (session.scripts.length > 0 && typeof window.loadScriptFromLibrary === 'function') {
        // Find script IDs by name
        const scriptLibrary = window.scriptLibrary || [];
        const scriptIds = [];

        for (const scriptName of session.scripts) {
          const script = scriptLibrary.find(s => s.name === scriptName);
          if (script) {
            scriptIds.push(script.id);
          }
        }

        if (scriptIds.length > 0) {
          // Inject all scripts
          if (typeof window.injectSelectedScripts === 'function') {
            window.selectedScriptIds = new Set(scriptIds);
            await window.injectSelectedScripts();
          }

          if (typeof showToast === 'function') {
            showToast(`✅ Replayed ${scriptIds.length} script(s)`, 'success');
          }
        }
      }

    } catch (e) {
      console.error('Failed to replay session:', e);
      if (typeof showToast === 'function') {
        showToast(`❌ Replay failed: ${e.message}`, 'error');
      }
    }
  }

  function removeFromHistory(identifier) {
    const history = loadSessionHistory();
    history.sessions = history.sessions.filter(s => s.identifier !== identifier);
    saveSessionHistory(history);
    renderHistoryDropdown();

    if (typeof showToast === 'function') {
      showToast('Removed from history', 'info');
    }
  }

  function clearHistory() {
    if (confirm('Clear all session history?')) {
      saveSessionHistory({ sessions: [] });
      renderHistoryDropdown();

      if (typeof showToast === 'function') {
        showToast('History cleared', 'info');
      }
    }
  }

  // Track current session when connecting
  function trackCurrentSession() {
    // This will be called from scripts.js when a connection is established
    // Get current target and scripts
    fetch('/api/target')
      .then(res => res.ok ? res.json() : null)
      .then(target => {
        if (target && target.identifier) {
          // Get currently loaded scripts (if any)
          const scriptsUsed = []; // Could track this better in the future
          addToHistory(target, scriptsUsed);
        }
      })
      .catch(e => console.error('Failed to track session:', e));
  }

  // Initialize on page load
  document.addEventListener('DOMContentLoaded', () => {
    console.log('[SessionHistory] Initializing...');
    renderHistoryDropdown();
  });

  // Export functions for global access
  window.toggleHistoryDropdown = toggleHistoryDropdown;
  window.selectFromHistory = selectFromHistory;
  window.replaySession = replaySession;
  window.removeFromHistory = removeFromHistory;
  window.clearHistory = clearHistory;
  window.addToHistory = addToHistory;
  window.trackCurrentSession = trackCurrentSession;
  window.renderHistoryDropdown = renderHistoryDropdown;
}
