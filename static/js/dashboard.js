
if (typeof window.attached === 'undefined') {
  window.deviceConnected = false;
  window.selectedName = null;
  window.selectedIdentifier = null;
  window.attached = false;
  window.targetSaved = false;
  window.lastToastMessage = null;
  window.lastDeviceCount = null;
  window.lastDisconnectedTarget = null; // Store last disconnected target for reconnect
}




function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function setButtonLoading(loading, label = 'Working...') {
  const btn = document.getElementById('attachBtn');
  if (!btn) return;

  btn.disabled = !!loading;

  if (loading) {
    btn.classList.remove('bg-primary-600','hover:bg-primary-700','bg-red-600','hover:bg-red-700');
    btn.classList.add('bg-slate-600','cursor-wait','opacity-80');

    btn.innerHTML = `
      <span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <circle cx="12" cy="12" r="10" stroke-width="2" class="opacity-25"></circle>
          <path d="M4 12a8 8 0 018-8" stroke-width="2" stroke-linecap="round" class="opacity-75"></path>
        </svg>
        <span>${label}</span>
      </span>
    `;
  } else {
    btn.classList.remove('bg-slate-600','cursor-wait','opacity-80');
    updateAttachButton(); // restore normal look
  }
}

// Process attachment persistence functions
function saveAttachmentState() {
  if (selectedIdentifier && selectedName) {
    const attachmentData = {
      identifier: selectedIdentifier,
      name: selectedName,
      attached: attached, // This will be false for saved targets
      timestamp: Date.now()
    };
    sessionStorage.setItem('fridaAttachment', JSON.stringify(attachmentData));
  } else {
    sessionStorage.removeItem('fridaAttachment');
  }
}


// Also update the updateStats function to properly reflect attachment state
function updateStats() {
  // Update device count
  const deviceSelect = document.getElementById('deviceSelect');
  const deviceCount = document.getElementById('deviceCount');
  if (deviceSelect && deviceCount) {
    const count = deviceSelect.options.length;
    let validOptions = 0;
    for (let i = 0; i < count; i++) {
      if (!deviceSelect.options[i].disabled) validOptions++;
    }
    deviceCount.textContent = Math.max(0, validOptions);
  }

  // Active = attached OR saved target
  const activeSessions = document.getElementById('activeSessions');
  if (activeSessions) {
    const isActive = !!window.attached || !!window.targetSaved;
    activeSessions.textContent = isActive ? '1' : '0';
  }
}


function clearConsole() {
  const consoleBox = document.getElementById('consoleBox');
  if (consoleBox) {
    consoleBox.innerHTML = `
      <div class="text-slate-500 text-xs mb-2">
        Console cleared - Waiting for instrumentation session...
        <br>
        Ready to intercept function calls, modify behavior, and monitor application state.
      </div>
    `;
    showToast('Console cleared', 'info');
  }
}

function exportLogs() {
  const consoleBox = document.getElementById('consoleBox');
  if (!consoleBox) return;

  const logs = consoleBox.innerText;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `frida-logs-${timestamp}.txt`;

  const blob = new Blob([logs], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Logs exported as ${filename}`, 'success');
}

// Initialize Socket.IO if available
if (typeof io !== 'undefined') {
  // Connect to the DEFAULT namespace (/) for dashboard messages
  const dashboardSocket = io('/');

  // Track seen messages to prevent duplicates
  const seenMessages = new Set();

  // Helper to add console message
  function addConsoleMessage(data) {
    const box = document.getElementById('consoleBox');
    if (!box) return;

    const message = data.message || data.payload || '';

    // Filter out overly verbose/noisy messages only
    const internalPatterns = [
      /WebSocket connected/i,
      /Dashboard loaded/i,
    ];

    const isInternalMessage = internalPatterns.some(pattern => pattern.test(message));
    if (isInternalMessage) {
      console.log('[Dashboard Console] Filtered noisy message:', message);
      return;
    }

    // Create unique key for deduplication
    const msgKey = `${data.type}:${message}`;
    if (seenMessages.has(msgKey)) return;
    seenMessages.add(msgKey);

    // Keep set from growing too large
    if (seenMessages.size > 200) {
      const firstKey = seenMessages.values().next().value;
      seenMessages.delete(firstKey);
    }

    const time = new Date().toLocaleTimeString();

    // Create colored output based on type
    const colors = {
      info: 'text-emerald-400',
      log: 'text-emerald-400',
      warn: 'text-amber-400',
      warning: 'text-amber-400',
      error: 'text-red-400',
      debug: 'text-blue-400',
      success: 'text-green-400'
    };

    const color = colors[data.type] || 'text-emerald-400';
    const iconMap = {
      error: '❌',
      warn: '⚠️',
      warning: '⚠️',
      success: '✅',
      info: '📝',
      log: '📝',
      debug: '🔍'
    };
    const icon = iconMap[data.type] || '📝';

    const msgElement = document.createElement('div');
    msgElement.className = `${color} mb-1`;
    msgElement.innerHTML = `
      <span class="text-slate-500">[${time}]</span>
      <span class="font-medium">${icon} [${(data.type || 'log').toUpperCase()}]</span>
      ${message}
    `;

    box.appendChild(msgElement);
    box.scrollTop = box.scrollHeight;

    // Limit console history to prevent memory issues
    if (box.children.length > 500) {
      box.removeChild(box.firstChild);
    }
  }

  // Listen for console_output events (dashboard messages from backend)
  dashboardSocket.on('console_output', data => {
    console.log('[Dashboard] Received console_output:', data);
    addConsoleMessage(data);
  });

  // Listen for Frida disconnect events (when process is killed/crashed)
  dashboardSocket.on('frida_disconnected', (data) => {
    console.log('[Socket.IO] Received frida_disconnected:', data);

    // Store last target for reconnect option (before clearing)
    if (window.selectedIdentifier && window.selectedName) {
      window.lastDisconnectedTarget = {
        identifier: window.selectedIdentifier,
        name: window.selectedName,
        timestamp: Date.now()
      };
    }

    // Show toast with reconnect button
    showDisconnectToastWithReconnect(data.reason || 'Process terminated');

    // Reset UI state
    window.attached = false;
    window.targetSaved = false;
    window.selectedIdentifier = null;
    window.selectedName = null;

    // Clear session storage
    sessionStorage.removeItem('fridaAttachment');

    // Update UI
    updateAttachmentBadges();
    updateAttachButton();
    highlightSelectedRow();
    updateStats();
  });

  // Update WebSocket connection indicator based on socket state
  updateWebSocketIndicator(true);

  dashboardSocket.on('connect', async () => {
    console.log('[Socket.IO] Connected to Dashboard');
    updateWebSocketIndicator(true);

    // Add a welcome message to console
    addConsoleMessage({
      type: 'success',
      message: '🟢 Dashboard connected - Ready to monitor Frida operations'
    });

    try {
      const res = await fetch('/api/frida/status');
      const data = await res.json();
      if (data.running) {
        addConsoleMessage({
          type: 'success',
          message: `✅ Frida server is running (PID: ${data.pid})`
        });
      } else {
        addConsoleMessage({
          type: 'warn',
          message: '⚠️ Frida server is not running on device'
        });
      }
    } catch (e) {
      console.warn('Could not verify Frida status:', e);
    }
  });

  dashboardSocket.on('disconnect', () => {
    updateWebSocketIndicator(false);
    if (typeof showToast === 'function') {
      showToast('Disconnected from server', 'error');
    }
  });

  dashboardSocket.on('reconnecting', () => {
    updateWebSocketIndicator('reconnecting');
  });

} else {
  console.warn('Socket.IO not available - real-time console updates disabled');
}

// WebSocket connection health indicator update function (for Live Console)
function updateWebSocketIndicator(status) {
  const indicator = document.getElementById('wsConnectionIndicator');
  const statusText = document.getElementById('wsConnectionStatus');

  if (!indicator) return;

  // Remove all state classes
  indicator.classList.remove('bg-emerald-400', 'bg-amber-400', 'bg-red-400', 'animate-pulse');

  if (status === true || status === 'connected') {
    indicator.classList.add('bg-emerald-400');
    if (statusText) statusText.textContent = 'Connected';
  } else if (status === 'reconnecting') {
    indicator.classList.add('bg-amber-400', 'animate-pulse');
    if (statusText) statusText.textContent = 'Reconnecting...';
  } else {
    indicator.classList.add('bg-red-400');
    if (statusText) statusText.textContent = 'Disconnected';
  }
}

// Show disconnect toast with reconnect button
function showDisconnectToastWithReconnect(reason) {
  const target = window.lastDisconnectedTarget;

  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'fixed top-4 right-4 z-50 space-y-2';
    container.style.cssText = 'pointer-events: none;';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'disconnect-toast';
  toast.setAttribute('role', 'alert');
  toast.style.cssText = `
    pointer-events: auto;
    background: rgba(30, 41, 59, 0.95);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 16px;
    color: white;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
    max-width: 420px;
    transform: translateX(100%);
    transition: all 0.3s ease-out;
    opacity: 0;
  `;

  const hasTarget = target && target.identifier && (Date.now() - target.timestamp < 300000); // 5 min expiry

  toast.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 12px;">
      <div style="display: flex; align-items: flex-start; gap: 10px;">
        <span style="flex-shrink: 0; color: #ef4444;">
          <svg viewBox="0 0 24 24" style="width: 20px; height: 20px;" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M12 9v4m0 4h.01M10.29 3.86l-8.48 14.7A1.7 1.7 0 003.3 21h17.4a1.7 1.7 0 001.49-2.44l-8.48-14.7a1.7 1.7 0 00-2.95 0z" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        <div style="flex: 1;">
          <div style="font-weight: 600; margin-bottom: 4px;">Process Disconnected</div>
          <div style="font-size: 13px; color: rgba(255,255,255,0.7);">
            ${reason}${hasTarget ? ` - ${target.name}` : ''}
          </div>
        </div>
        <button class="toast-close-btn" style="flex-shrink: 0; background: none; border: none; color: rgba(255,255,255,0.5); cursor: pointer; padding: 4px;">
          <svg viewBox="0 0 24 24" style="width: 16px; height: 16px;" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
      ${hasTarget ? `
      <div style="display: flex; gap: 8px; justify-content: flex-end;">
        <button class="reconnect-btn" style="
          background: linear-gradient(135deg, #10b981, #059669);
          border: none;
          color: white;
          padding: 8px 16px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 6px;
          transition: all 0.2s;
        ">
          <svg viewBox="0 0 24 24" style="width: 14px; height: 14px;" stroke="currentColor" stroke-width="2" fill="none">
            <path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Reconnect
        </button>
      </div>
      ` : ''}
    </div>
  `;

  // Event handlers
  const closeBtn = toast.querySelector('.toast-close-btn');
  const reconnectBtn = toast.querySelector('.reconnect-btn');

  const removeToast = () => {
    toast.style.transform = 'translateX(100%)';
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  };

  if (closeBtn) {
    closeBtn.addEventListener('click', removeToast);
  }

  if (reconnectBtn && hasTarget) {
    reconnectBtn.addEventListener('click', async () => {
      reconnectBtn.innerHTML = '<span class="animate-pulse">Reconnecting...</span>';
      reconnectBtn.disabled = true;

      try {
        // Re-save the target
        await fetch(`/api/set-target/${encodeURIComponent(target.identifier)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: target.name })
        });

        // Update state
        window.selectedIdentifier = target.identifier;
        window.selectedName = target.name;
        window.targetSaved = true;
        window.lastDisconnectedTarget = null;

        // Update UI
        updateAttachmentBadges();
        updateAttachButton();
        highlightSelectedRow();
        updateStats();

        showToast(`Target restored: ${target.name}. Go to Scripts to Spawn & Inject.`, 'success');
        removeToast();

      } catch (e) {
        reconnectBtn.innerHTML = 'Reconnect';
        reconnectBtn.disabled = false;
        showToast(`Reconnect failed: ${e.message}`, 'error');
      }
    });
  }

  container.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => {
    toast.style.transform = 'translateX(0)';
    toast.style.opacity = '1';
  });

  // Auto-dismiss after 15 seconds (longer for reconnect toast)
  setTimeout(removeToast, 15000);
}

// dashboard.js
function setSavedTargetUI(name) {
  const badge = document.getElementById('attachedBadge');
  const label = document.getElementById('attachedProcessLabel');

  window.attached = false;               // important: NOT attached
  // keep window.selectedIdentifier / window.selectedName as-is

  if (badge) {
    badge.textContent = 'Target Saved';
    badge.classList.remove('bg-emerald-600', 'bg-slate-700');
    badge.classList.add('bg-yellow-600');
  }
  if (label) label.textContent = name || '—';

  updateAttachButton(); // will render "Clear saved target" (see step 2)
  highlightSelectedRow();
}


function updateAttachmentBadges() {
  const badge = document.getElementById('attachedBadge');
  const label = document.getElementById('attachedProcessLabel');
  if (!badge || !label) return;

  if (window.attached === true) {
    // ✅ real session
    badge.textContent = 'Attached';
    badge.classList.remove('bg-slate-700', 'bg-yellow-600');
    badge.classList.add('bg-emerald-600');
    label.textContent = window.selectedName || '—';
    return;
  }

  if (window.selectedIdentifier) {
    // 🟡 saved target only
    badge.textContent = 'Target Saved';
    badge.classList.remove('bg-slate-700', 'bg-emerald-600');
    badge.classList.add('bg-yellow-600');
    label.textContent = window.selectedName || window.selectedIdentifier || '—';
    return;
  }

  // ⚫ nothing
  badge.textContent = 'Not Attached';
  badge.classList.remove('bg-emerald-600', 'bg-yellow-600');
  badge.classList.add('bg-slate-700');
  label.textContent = '—';
}



function loadAttachmentState() {
  const stored = sessionStorage.getItem('fridaAttachment');
  if (stored) {
    try {
      const data = JSON.parse(stored);
      // Check if attachment is recent (within last 5 minutes)
      if (Date.now() - data.timestamp < 300000) {
        selectedIdentifier = data.identifier;
        selectedName = data.name;
        attached = data.attached;
        updateAttachmentBadges(); // Update UI badges
        return data;
      }
    } catch (e) {
      console.error('Error loading attachment state:', e);
    }
  }
  return null;
}


// Updated verifyAttachmentWithBackend to set targetSaved flag
async function verifyAttachmentWithBackend() {
  try {
    // Always check backend for active session - don't skip even if local state is empty
    // This ensures we sync properly when navigating between pages

    // 1) Ask for an active Frida session first (never 404s)
    const sessionRes = await fetch('/api/attached-process');
    const sessionData = await sessionRes.json().catch(() => ({}));

    if (sessionData && sessionData.session_active) {
      // Try to keep package identifier from backend target
      try {
        const targetRes = await fetch('/api/target');
        if (targetRes.ok) {
          const target = await targetRes.json();
          window.targetSaved = true;
          window.attached = true;
          // ✅ keep package/bundle id (do NOT replace with PID)
          window.selectedIdentifier = target.identifier || window.selectedIdentifier || null;
          window.selectedName = target.name || sessionData.name || 'Connected Process';
        } else {
          // Active session but no saved target
          window.targetSaved = false;
          window.attached = true;
          // Keep whatever selection we had; DO NOT set to PID
          window.selectedName = sessionData.name || window.selectedName || 'Connected Process';
        }
      } catch {
        // Session exists, target lookup failed → still attached
        window.attached = true;
        window.selectedName = sessionData.name || window.selectedName || 'Connected Process';
      }

    } else {
      // 2) No active session → only try /api/target if we *think* one is saved or we still have a selection
      if (window.targetSaved || window.selectedIdentifier) {
        try {
          const targetRes = await fetch('/api/target');
          if (targetRes.ok) {
            const target = await targetRes.json();
            window.targetSaved = true;
            window.attached = false;
            window.selectedIdentifier = target.identifier || window.selectedIdentifier;
            window.selectedName = target.name || window.selectedName || target.identifier;
          } else if (targetRes.status === 404) {
            // Target truly cleared → stop future fetches
            window.targetSaved = false;
            window.attached = false;
            window.selectedIdentifier = null;
            window.selectedName = null;
          }
        } catch (e) {
          // Network hiccup → keep current UI; don't thrash
          console.warn('Could not verify saved target:', e);
        }
      } else {
        // We already know there's nothing saved and no session
        window.targetSaved = false;
        window.attached = false;
      }
    }

    updateAttachButton();
    updateAttachmentBadges();
    highlightSelectedRow();
    updateStats();

  } catch (error) {
    console.warn('Error verifying attachment (non-critical):', error);
    // Keep current UI state on verifier error
  }
}


// Toast notification utility (shared globally for all pages)
function showToast(message, type = 'info', opts = {}) {
  const {
    duration = 4500,
    closeOnClick = true,
    withIcon = true,
    showProgress = true,
  } = opts;

   if (window.lastToastMessage === message) {
    return; // skip duplicate consecutive toasts
    }
    window.lastToastMessage = message;

  setTimeout(() => { lastToastMessage = null; }, 2000); // reset after 2s

  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'fixed top-4 right-4 z-50 space-y-2';
    container.style.cssText = `
      pointer-events: none;
    `;
    document.body.appendChild(container);
  }

  const iconMap = {
    info:    '<svg viewBox="0 0 24 24" class="toast-icon-svg"><path d="M12 9h.01M11 12h1v6h1m-1-16a9 9 0 110 18 9 9 0 010-18z" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    success: '<svg viewBox="0 0 24 24" class="toast-icon-svg"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    error:   '<svg viewBox="0 0 24 24" class="toast-icon-svg"><path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warn:    '<svg viewBox="0 0 24 24" class="toast-icon-svg"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.48 14.7A1.7 1.7 0 003.3 21h17.4a1.7 1.7 0 001.49-2.44l-8.48-14.7a1.7 1.7 0 00-2.95 0z" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warning: '<svg viewBox="0 0 24 24" class="toast-icon-svg"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.48 14.7A1.7 1.7 0 003.3 21h17.4a1.7 1.7 0 001.49-2.44l-8.48-14.7a1.7 1.7 0 00-2.95 0z" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  };

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.style.cssText = `
    pointer-events: auto;
    background: rgba(30, 41, 59, 0.95);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 8px;
    padding: 12px 16px;
    color: white;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
    max-width: 400px;
    transform: translateX(100%);
    transition: all 0.3s ease-out;
    opacity: 0;
  `;

  const typeColors = {
    success: 'border-left: 4px solid #10b981;',
    error: 'border-left: 4px solid #ef4444;',
    warn: 'border-left: 4px solid #f59e0b;',
    warning: 'border-left: 4px solid #f59e0b;',
    info: 'border-left: 4px solid #3b82f6;'
  };

  if (typeColors[type]) {
    toast.style.cssText += typeColors[type];
  }

  toast.innerHTML = `
    <div class="toast-body" style="display: flex; align-items: center; gap: 8px;">
      ${withIcon ? `<span class="toast-icon" style="flex-shrink: 0; width: 16px; height: 16px;">${iconMap[type] || iconMap.info}</span>` : ''}
      <span class="toast-message" style="flex: 1; font-size: 14px; line-height: 1.4;">${message}</span>
      <button class="toast-close" aria-label="Close" style="flex-shrink: 0; background: none; border: none; color: rgba(255,255,255,0.7); cursor: pointer; padding: 4px; border-radius: 4px; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center;">
        <svg class="toast-close-svg" viewBox="0 0 24 24" style="width: 12px; height: 12px;" stroke="currentColor" stroke-width="2" fill="none">
          <path d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
    ${showProgress ? `<div class="toast-bar" style="position: absolute; bottom: 0; left: 0; height: 2px; background: rgba(255,255,255,0.3); width: 100%; transition: width ${duration}ms linear;"></div>` : ''}
  `;

  // Close behaviors
  const remove = () => {
    toast.style.transform = 'translateX(100%)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, 300);
  };

  const closeBtn = toast.querySelector('.toast-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', remove);
  }

  if (closeOnClick) {
    toast.addEventListener('click', (e) => {
      if (!e.target.closest('.toast-close')) {
        remove();
      }
    });
  }

  // Auto-dismiss with pause on hover
  let remaining = duration;
  let start = Date.now();
  let timer = setTimeout(remove, remaining);

  toast.addEventListener('mouseenter', () => {
    clearTimeout(timer);
    remaining -= Date.now() - start;
    const bar = toast.querySelector('.toast-bar');
    if (bar) {
      bar.style.animationPlayState = 'paused';
    }
  });

  toast.addEventListener('mouseleave', () => {
    start = Date.now();
    timer = setTimeout(remove, remaining);
    const bar = toast.querySelector('.toast-bar');
    if (bar) {
      bar.style.animationPlayState = 'running';
    }
  });

  container.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => {
    toast.style.transform = 'translateX(0)';
    toast.style.opacity = '1';

    // Start progress bar animation
    if (showProgress) {
      const bar = toast.querySelector('.toast-bar');
      if (bar) {
        setTimeout(() => {
          bar.style.width = '0%';
        }, 100);
      }
    }
  });
}

// Load running processes for the selected device
async function loadProcesses() {
  if (!deviceConnected) return;
  const table = document.getElementById("processTable");
  const countLabel = document.getElementById("processCount");
  const search = document.getElementById("search");
  if (!table || !countLabel) return;

  table.innerHTML = `<tr><td colspan="3" class="p-3 text-slate-400">
    <div class="flex items-center justify-center space-x-2">
      <svg class="w-5 h-5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <circle cx="12" cy="12" r="10" stroke-width="2" class="opacity-25"></circle>
        <path d="M4 12a8 8 0 018-8" stroke-width="2" stroke-linecap="round" class="opacity-75"></path>
      </svg>
      <span>Loading processes...</span>
    </div>
  </td></tr>`;
  countLabel.textContent = "0";

  try {
    const res = await fetch("/api/processes");
    const data = await res.json();

    if (!data.processes || data.processes.length === 0) {
      table.innerHTML = `<tr><td colspan="3" class="p-3 text-slate-400">No processes found.</td></tr>`;
      return;
    }

    const renderProcesses = (filter = "") => {
      const filtered = data.processes.filter(p =>
        p.name.toLowerCase().includes(filter.toLowerCase()) ||
        p.identifier.toLowerCase().includes(filter.toLowerCase())
      );

      table.innerHTML = filtered.map((proc, i) => {
        const isSelected = proc.identifier === selectedIdentifier;
        const rowClass = isSelected ? "bg-emerald-900 ring-1 ring-emerald-400" : "";

        return `
          <tr 
            title="Double-click to attach or detach"
            class="${rowClass} transition duration-150 hover:bg-slate-700 hover:scale-[101%] hover:ring-1 ring-primary-500/50 cursor-pointer"
            ondblclick="handleDoubleClick('${proc.identifier}', '${proc.name.replace(/'/g, "\\'")}')"
            onclick="selectProcess('${proc.identifier}', '${proc.name.replace(/'/g, "\\'")}')">

            <td class="border border-slate-700 px-2 py-1 text-center w-6 text-slate-400 font-mono">${i + 1}</td>
            <td class="border border-slate-700 px-2 py-1">${proc.name}</td>
            <td class="border border-slate-700 px-2 py-1">${proc.identifier}</td>
          </tr>
        `;
      }).join("") || `<tr><td colspan='3' class='p-3 text-slate-400 text-center'>No match found</td></tr>`;

      countLabel.textContent = filtered.length;
    };

    renderProcesses();

    if (!search.dataset.listenerAttached) {
      search.addEventListener("input", e => renderProcesses(e.target.value));
      search.dataset.listenerAttached = true;
    }

    // After loading processes, highlight any previously selected row
    highlightSelectedRow();

  } catch (err) {
    console.error("Failed to load processes", err);
    table.innerHTML = `<tr><td colspan='3' class='p-3 text-red-400'>
      <div class="text-center py-4">
        <svg class="w-12 h-12 mx-auto mb-2 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
        </svg>
        <p class="font-semibold mb-1">Unable to Load Processes</p>
        <p class="text-sm text-slate-400">Make sure your device is connected and ADB is working</p>
        <button onclick="loadProcesses()" class="mt-3 px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded text-sm">
          Try Again
        </button>
      </div>
    </td></tr>`;
    showToast("Could not load processes. Is your device connected?", "error");
  }
}

function updateAttachButtonUI(state = 'idle') {
  const attachBtn = document.getElementById('attachBtn');
  if (!attachBtn) return;

  attachBtn.disabled = (state === 'saving');

  if (state === 'saving') {
    attachBtn.innerHTML = '<span class="animate-pulse">Saving...</span>';
  } else {
    updateAttachButton(); 
  }
}

async function saveTargetOnly(identifier, name) {
  try {
    updateAttachButtonUI('saving');

    const res = await fetch(`/api/set-target/${encodeURIComponent(identifier)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || `Failed to save target (${res.status})`);
    }

    updateAttachButtonUI('idle');
    showToast(`Target saved: ${data.name || identifier}`, 'success');

  } catch (e) {
    updateAttachButtonUI('idle');
    showToast(`Error: ${e.message}`, 'error');
  }
}

// Update the attachBtnHandler function to call updateAttachmentBadges
async function attachBtnHandler() {
  if (!window.selectedIdentifier) {
    showToast('Pick a process first', 'warn');
    return;
  }

  if (window.attached || targetSaved) {
    // Clear saved target
    setButtonLoading(true, `Clearing target...`);
    try {
      await clearTarget(true);
      window.attached = false;
      window.targetSaved =false;
      // Keep selectedIdentifier and selectedName so row stays highlighted
      sessionStorage.removeItem('fridaAttachment');

      setButtonLoading(false);
      updateAttachButton();
      updateAttachmentBadges();
      highlightSelectedRow();
      showToast('Target cleared', 'info');
    } catch (e) {
      console.error(e);
      showToast(`Error: ${e.message}`, 'error');
      setButtonLoading(false);
    }
    return;
  }

  // Save target (button click now saves!)
  setButtonLoading(true, `Saving ${window.selectedName || window.selectedIdentifier}...`);
  try {
    await saveTargetOnly(window.selectedIdentifier, window.selectedName);
    
    // Mark as saved
    window.targetSaved =true;
    updateStats();
    window.attached = false; // Not actually attached, just saved
    saveAttachmentState();

    setButtonLoading(false);
    updateAttachButton();
    updateAttachmentBadges();
    highlightSelectedRow();
    showToast(`Target saved: ${window.selectedName}`, 'success');
  } catch (e) {
    console.error(e);
    showToast(`Error: ${e.message}`, 'error');
    setButtonLoading(false);
  }
}



async function selectProcess(identifier, name) {
  if (attached && identifier !== selectedIdentifier) {
    showToast("⚠️ Detach before selecting another process", "warning");
    return;
  }

  selectedIdentifier = identifier;
  selectedName = name;

  highlightSelectedRow();
  updateAttachButton();
}


// Updated handleDoubleClick to also use targetSaved flag
async function handleDoubleClick(identifier, name) {
  if (targetSaved && identifier !== window.selectedIdentifier) {
    showToast("Clear current target first or select a different process", "warning");
    return;
  }
  
  window.selectedIdentifier = identifier;
  window.selectedName = name;

  setButtonLoading(true, `Saving ${name}...`);
  
  try {
    await saveTargetOnly(identifier, name);
    
    // Mark as saved
    window.targetSaved =true;
    updateStats();
    window.attached = false;
    saveAttachmentState();
    
    setButtonLoading(false);
    updateAttachButton();
    updateAttachmentBadges();
    highlightSelectedRow();
    showToast(`Target saved: ${name}`, 'success');
    
  } catch (e) {
    console.error(e);
    showToast(`Error: ${e.message}`, 'error');
    setButtonLoading(false);
    
    window.targetSaved =false;
    updateAttachButton();
    updateAttachmentBadges();
  }
}



// Update the detachProcess function to call updateAttachmentBadges
async function detachProcess() {
  try {
    const res = await fetch(`/api/detach/${selectedIdentifier}`, {
      method: 'POST'
    });

    const result = await res.json();

    if (res.ok) {
      showToast(`Detached from ${selectedName} (${selectedIdentifier})`, "warn");
    } else {
      showToast("Failed to detach", "error");
      console.error("Detach failed:", result);
    }

  } catch (err) {
    showToast("Error during detach", "error");
    console.error("Detach error:", err);
  }

  selectedIdentifier = null;
  selectedName = null;
  attached = false;
  sessionStorage.removeItem('fridaAttachment'); // Clear from sessionStorage
  updateAttachmentBadges(); // Update UI badges

  // Update active sessions counter
  const activeSessionsEl = document.getElementById('activeSessions');
  if (activeSessionsEl) {
    activeSessionsEl.textContent = '0';
  }

  highlightSelectedRow();
  updateAttachButton();
}



function updateAttachButton() {
  const attachBtn = document.getElementById('attachBtn');
  const quickActionsPanel = document.getElementById('quickActionsPanel');
  const quickActionTargetName = document.getElementById('quickActionTargetName');

  if (!attachBtn) return;

  const name = window.selectedName || window.selectedIdentifier || 'Process';

  attachBtn.classList.remove(
    'bg-red-600','hover:bg-red-700',
    'bg-primary-600','hover:bg-primary-700',
    'bg-slate-600','cursor-wait','opacity-80'
  );

  if (!window.selectedIdentifier) {
    // No selection → blue but disabled
    attachBtn.disabled = true;
    attachBtn.innerHTML = `
      <span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
        </svg>
        <span>Select as Target</span>
      </span>`;
    attachBtn.classList.add('bg-primary-600','hover:bg-primary-700','opacity-50','cursor-not-allowed');

    // Hide quick actions panel
    if (quickActionsPanel) quickActionsPanel.classList.add('hidden');
    return;
  }

  attachBtn.disabled = false;
  attachBtn.classList.remove('cursor-not-allowed', 'opacity-50');

  if (window.attached) {
    // RED — Currently attached (has active Frida session)
    attachBtn.innerHTML = `
      <span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M6 18L18 6M6 6l12 12"></path>
        </svg>
        <span>Clear Target</span>
      </span>`;
    attachBtn.classList.add('bg-red-600','hover:bg-red-700');

    // Show quick actions for attached target
    if (quickActionsPanel) {
      quickActionsPanel.classList.remove('hidden');
      if (quickActionTargetName) quickActionTargetName.textContent = name;
    }
  } else if (targetSaved) {
    // RED — Target is saved, offer to clear
    attachBtn.innerHTML = `
      <span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M6 18L18 6M6 6l12 12"></path>
        </svg>
        <span>Clear Target</span>
      </span>`;
    attachBtn.classList.add('bg-red-600','hover:bg-red-700');

    // Show quick actions for saved target
    if (quickActionsPanel) {
      quickActionsPanel.classList.remove('hidden');
      if (quickActionTargetName) quickActionTargetName.textContent = name;
    }
  } else {
    // BLUE — Process selected but not saved yet
    attachBtn.innerHTML = `
      <span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M5 13l4 4L19 7"></path>
        </svg>
        <span>Select as Target</span>
      </span>`;
    attachBtn.classList.add('bg-primary-600','hover:bg-primary-700');

    // Hide quick actions until target is saved
    if (quickActionsPanel) quickActionsPanel.classList.add('hidden');
  }
}

function highlightSelectedRow() {
  const rows = document.querySelectorAll("#processTable tr");
  rows.forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length < 3) return;
    
    const identifier = cells[2].innerText.trim();
    if (identifier === selectedIdentifier) {
      row.classList.add("bg-emerald-900", "ring-1", "ring-emerald-400");
    } else {
      row.classList.remove("bg-emerald-900", "ring-1", "ring-emerald-400");
    }
  });
}


// Updated clearTarget to reset targetSaved flag
async function clearTarget(skipToast = false) {
  try {
    const res = await fetch('/api/target', { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.ok) {
      throw new Error(data.message || `Failed to clear target (${res.status})`);
    }

    // Reset flags
    window.targetSaved = false;
    window.attached = false;
    window.selectedIdentifier = null;
    window.selectedName = null;
    // Keep selectedIdentifier and selectedName so user can still see their selection

    // Clear session storage
    sessionStorage.removeItem('fridaAttachment');

    // Update badges/labels/buttons
    updateAttachmentBadges();
    updateAttachButton();
    highlightSelectedRow();
    updateStats(); // Update active sessions counter

    if (!skipToast) {
      showToast('Saved target cleared', 'info');
    }
  } catch (e) {
    console.error(e);
    if (!skipToast) {
      showToast(`Error: ${e.message}`, 'error');
    }
  }
}


// Load connected ADB devices into dropdown
async function loadDevices() {
  const select = document.getElementById('deviceSelect');
  if (!select) return;

  select.innerHTML = `<option disabled selected>🔍 Scanning for devices...</option>`;
  select.classList.remove('border-red-500'); // Clean up previous state
  select.classList.add('animate-pulse'); // Add pulsing effect while loading

  try {
    const res = await fetch('/api/adb/devices');
    const data = await res.json();

    select.innerHTML = ''; // Clear first
    select.classList.remove('animate-pulse'); // Remove loading animation

    // Track last known count globally
if (typeof window.lastDeviceCount === 'undefined') {
  window.lastDeviceCount = null;
}

    if (data.devices && data.devices.length > 0) {
      deviceConnected = true;
      data.devices.forEach(dev => {
        const opt = document.createElement('option');
        opt.value = dev.id;
        opt.textContent = dev.name;
        select.appendChild(opt);
      });

      if (window.lastDeviceCount !== data.devices.length) {
        showToast(`${data.devices.length} device(s) connected`, 'success');
        window.lastDeviceCount = data.devices.length;
      }
    } else {
      deviceConnected = false;
      const opt = document.createElement('option');
      opt.disabled = true;
      opt.textContent = 'No devices found';
      select.appendChild(opt);

      select.classList.add('border-red-500');

      if (window.lastDeviceCount !== 0) {
        showToast('No devices found', 'warn');
        window.lastDeviceCount = 0;
      }
    }

    // Restore previous selection if still valid
    const savedDevice = localStorage.getItem('selectedDeviceId');
    if (savedDevice && [...select.options].some(opt => opt.value === savedDevice)) {
      select.value = savedDevice;

      // Send to backend
      fetch('/api/adb/select-device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: savedDevice })
      }).catch(e => console.error('Failed to restore device selection:', e));
    } else if (select.options.length > 0) {
      select.selectedIndex = 0;
      const deviceId = select.value;
      localStorage.setItem('selectedDeviceId', deviceId);

      // Send to backend
      fetch('/api/adb/select-device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId })
      }).catch(e => console.error('Failed to set initial device:', e));
    }

    // Prevent double event listener
    if (!select.dataset.listenerAttached) {
      select.addEventListener('change', async () => {
        const deviceId = select.value;
        localStorage.setItem('selectedDeviceId', deviceId);

        // Send selected device to backend
        try {
          const res = await fetch('/api/adb/select-device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: deviceId })
          });

          const data = await res.json();

          if (data.ok) {
            const deviceName = select.options[select.selectedIndex].text;
            showToast(`Using device: ${deviceName}`, 'success');
          }
        } catch (e) {
          console.error('Failed to set device:', e);
        }
      });
      select.dataset.listenerAttached = 'true';
    }

  } catch (err) {
    console.error('Failed to load devices', err);

    select.innerHTML = '';
    select.classList.remove('animate-pulse'); // Remove loading animation on error
    const opt = document.createElement('option');
    opt.disabled = true;
    opt.textContent = '⚠️ Cannot detect devices - Check ADB';
    select.appendChild(opt);

    select.classList.add('border-red-500');
    showToast('Cannot connect to ADB. Make sure Android Debug Bridge is running.', 'error');
  }
}

// Global functions for other pages to access attachment state
window.getAttachmentState = function() {
  return {
    attached: attached,
    identifier: selectedIdentifier,
    name: selectedName
  };
};

window.isProcessAttached = function() {
  return attached && selectedIdentifier;
};


// Quick action functions for streamlined workflow
async function quickSpawnWithScripts() {
  if (!window.selectedIdentifier) {
    showToast('No target selected', 'warn');
    return;
  }

  // Navigate to Scripts page which will show spawn & inject options
  window.location.href = '/scripts';
}

async function quickSpawnOnly(event) {
  if (!window.selectedIdentifier) {
    showToast('No target selected', 'warn');
    return;
  }

  const btn = event ? event.target.closest('button') : null;
  const originalHTML = btn ? btn.innerHTML : null;

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="animate-pulse flex items-center justify-center space-x-2"><svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10" stroke-width="2" class="opacity-25"></circle><path d="M4 12a8 8 0 018-8" stroke-width="2" stroke-linecap="round" class="opacity-75"></path></svg><span>Spawning...</span></span>';
  }

  try {
    // Spawn with empty code (no script injection)
    const response = await fetch('/api/spawn-and-inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: window.selectedIdentifier,
        code: '// No script - just spawn\nsend({type: "info", message: "Process spawned without script injection"});'
      })
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok || (result.ok !== true && result.status !== 'ok')) {
      throw new Error(result.message || `HTTP ${response.status}`);
    }

    const displayName = result.name || window.selectedName || window.selectedIdentifier;

    showToast(`Process spawned: ${displayName}`, 'success');
    window.attached = true;
    window.targetSaved = true;
    updateAttachButton();
    updateAttachmentBadges();
    updateStats();

  } catch (e) {
    let friendlyMessage = 'Failed to spawn process';

    // Provide user-friendly error messages based on common errors
    if (e.message.includes('device not found') || e.message.includes('no devices')) {
      friendlyMessage = 'Device not found. Please check your USB connection.';
    } else if (e.message.includes('unauthorized')) {
      friendlyMessage = 'Device unauthorized. Please allow USB debugging on your device.';
    } else if (e.message.includes('Frida')) {
      friendlyMessage = 'Frida server error. Make sure Frida server is running on your device.';
    } else if (e.message.includes('timeout')) {
      friendlyMessage = 'Connection timeout. Device may be offline.';
    } else if (e.message) {
      friendlyMessage = e.message;
    }

    showToast(friendlyMessage, 'error');
  } finally {
    if (btn && originalHTML) {
      btn.innerHTML = originalHTML;
      btn.disabled = false;
    }
  }
}

// Make functions globally available
window.quickSpawnWithScripts = quickSpawnWithScripts;
window.quickSpawnOnly = quickSpawnOnly;

// Initialize when DOM is loaded
// Update the initialization to call updateAttachmentBadges
document.addEventListener('DOMContentLoaded', () => {
  window.attachBtn = document.getElementById('attachBtn');
  
  // Set up attach button event listener
  if (window.attachBtn) {
    window.attachBtn.addEventListener('click', attachBtnHandler);
  }
  
  try { 
    loadAttachmentState(); 
    updateAttachButton();
    updateAttachmentBadges(); // Update UI badges
    updateStats();
    highlightSelectedRow();
  } catch (e) { 
    console.warn('Attachment state restore failed:', e); 
  }
  
  // Verify attachment with backend immediately and after a short delay
  verifyAttachmentWithBackend(); // Run immediately
  setTimeout(verifyAttachmentWithBackend, 500); // And again after 500ms for safety

  // Set up periodic verification
  setInterval(verifyAttachmentWithBackend, 15000); // Every 15 seconds (more frequent)
  
  loadDevices();
  loadProcesses();
  checkStatus(); // from status.js
  setInterval(checkStatus, 5000);
});