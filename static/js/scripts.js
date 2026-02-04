/* static/js/scripts.js */

if (window.__fridaScriptsJsLoaded) {
  console.warn('[scripts.js] already loaded, skipping duplicate execution');
    checkStatus(); // from status.js
} else {
  window.__fridaScriptsJsLoaded = true;

  function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) {
      console.warn('Toast container not found');
      return;
    }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    toast.innerHTML = `
      <div class="flex items-center justify-between space-x-3">
        <div class="flex items-center space-x-3 flex-1">
          <span class="toast-message">${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.parentElement.remove()">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
    `;

    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      toast.classList.add('toast-exit');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, 5000);
  }

  // Make it globally available
  window.showToast = showToast;

  let editor;
  let currentSessionId = null;
  let lastAttachedPid = null;
  let hasBeenConnected = false; // Track if we've ever been connected in this session
  let pollingInterval = null;
  let lastMessageId = 0;
  let seenMessages = new Set(); // Track seen messages to prevent duplicates
  let intentionalDisconnect = false; // Flag to suppress disconnect notification when user clicks Disconnect

  const consoleOut = document.getElementById('consoleOutput');

  function ensureEditorInteractive() {
    const el = document.getElementById('editor');
    if (!el) return;

    // Keep the editor at the top of its local stacking context
    el.style.position = 'relative';
    el.style.zIndex = '100';
    el.style.pointerEvents = 'auto';

    // Make sure children accept input
    el.querySelectorAll('*').forEach(n => { n.style.pointerEvents = 'auto'; });

    const ed = window.__monacoEditorInstance || editor;
    if (window.monaco && ed) {
      ed.updateOptions({
        readOnly: false,
        contextmenu: true,
        selectOnLineNumbers: true,
        wordWrap: 'on',
        cursorBlinking: 'smooth'
      });

      // Nudge layout/focus after any late reflow
      setTimeout(() => {
        try {
          ed.layout();
          ed.focus();
          ed.setPosition({ lineNumber: 1, column: 1 });
          const ro = ed.getOption(monaco.editor.EditorOption.readOnly);
          console.log('[Monaco] reactivated. readOnly:', ro);
        } catch (e) {
          console.debug('ensureEditorInteractive: layout/focus skipped', e);
        }
      }, 50);
    }
  }

  function retryEnsureEditorInteractive(times = 10, delayMs = 200) {
    let n = 0;
    const tick = () => {
      ensureEditorInteractive();
      n += 1;
      if (n < times) setTimeout(tick, delayMs);
    };
    tick();
  }

  // ---------------------------------------------
  // Socket.IO for Real-Time Console + Polling Fallback
  // ---------------------------------------------
  let fridaSocket = null;

  function initFridaSocket() {
    if (typeof io === 'undefined') {
      console.warn('[Socket.IO] io not available, using polling only');
      return;
    }

    // Connect to /frida namespace for real-time Frida output
    fridaSocket = io('/frida', {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    fridaSocket.on('connect', () => {
      console.log('[Socket.IO] Connected to /frida namespace');
      // Join the session room if we have one
      if (currentSessionId) {
        fridaSocket.emit('join', { session_id: currentSessionId });
        console.log('[Socket.IO] Joined room:', currentSessionId);
      }
    });

    fridaSocket.on('disconnect', () => {
      console.log('[Socket.IO] Disconnected from /frida namespace');
    });

    // Listen for real-time Frida output
    fridaSocket.on('frida_output', (data) => {
      console.log('[Socket.IO] Received frida_output:', data);
      if (data && data.message) {
        appendConsole(data.message, data.type || 'log');
      }
    });

    // Also listen for console_output (legacy support)
    fridaSocket.on('console_output', (data) => {
      console.log('[Socket.IO] Received console_output:', data);
      if (data && (data.message || data.payload)) {
        appendConsole(data.message || data.payload, data.type || 'log');
      }
    });

    fridaSocket.on('joined', (data) => {
      console.log('[Socket.IO] Successfully joined room:', data);
      appendConsole(`Connected to session: ${data.session_id}`, 'success');
    });

    fridaSocket.on('error', (err) => {
      console.error('[Socket.IO] Error:', err);
    });

    // Listen for Frida disconnect events (when process is killed/crashed)
    fridaSocket.on('frida_disconnected', (data) => {
      console.log('[Socket.IO] ===== DISCONNECT EVENT RECEIVED =====');
      console.log('[Socket.IO] Disconnect data:', data);
      console.log('[Socket.IO] intentionalDisconnect flag:', intentionalDisconnect);
      console.log('[Socket.IO] hasBeenConnected flag:', hasBeenConnected);

      // Only show popup notification if this was NOT an intentional disconnect (user clicked Disconnect button)
      if (!intentionalDisconnect) {
        appendConsole(`⚠️ Process disconnected: ${data.reason || 'unknown'}`, 'error');

        // Store last target for reconnect (get from process info panel before reset)
        const pidEl = document.getElementById('processInfoPid');
        const packageEl = document.getElementById('processInfoPackage');
        const labelEl = document.getElementById('attachedProcessLabel');

        const lastTarget = {
          identifier: packageEl ? packageEl.textContent : null,
          name: labelEl ? labelEl.textContent : null,
          pid: pidEl ? pidEl.textContent : null,
          timestamp: Date.now()
        };

        // Show reconnect toast if we have target info
        if (lastTarget.identifier && lastTarget.identifier !== '—') {
          showDisconnectToastWithReconnect(data.reason || 'Process terminated', lastTarget);
        } else {
          showToast(`Process disconnected: ${data.reason || 'Process terminated'}`, 'error');
        }

        // Ensure reconnect button appears after crash
        setTimeout(() => {
          const reconnectBtn = document.getElementById('reconnectBtn');
          if (reconnectBtn) {
            // Check if target is still saved
            fetch('/api/target')
              .then(res => res.ok ? res.json() : null)
              .then(target => {
                if (target && target.identifier) {
                  reconnectBtn.classList.remove('hidden');
                  console.log('[Crash] Showing reconnect button for target:', target.identifier);
                }
              })
              .catch(err => console.warn('[Crash] Failed to check target:', err));
          }
        }, 500);
      } else {
        console.log('[Socket.IO] Suppressing disconnect notification (intentional disconnect)');
      }

      // Reset UI state regardless (but keep hasBeenConnected flag for reconnect)
      setAttachedState(false);
      currentSessionId = null;
      lastAttachedPid = null;

      // DON'T reset hasBeenConnected here - keep it true so reconnect button appears
      console.log('[Crash] hasBeenConnected remains:', hasBeenConnected);
    });
  }

  // Show disconnect toast with reconnect button (Scripts page version)
  function showDisconnectToastWithReconnect(reason, target) {
    const container = document.getElementById('toastContainer') || createToastContainer();

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

    const hasTarget = target && target.identifier && target.identifier !== '—';

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
              ${reason}${hasTarget ? ` - ${target.name || target.identifier}` : ''}
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
            Respawn & Inject
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
        reconnectBtn.innerHTML = '<span class="animate-pulse">Respawning...</span>';
        reconnectBtn.disabled = true;

        try {
          // Re-save target first
          await fetch(`/api/set-target/${encodeURIComponent(target.identifier)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: target.name || target.identifier })
          });

          // Get the current editor code
          const editorInstance = window.__monacoEditorInstance;
          const code = editorInstance ? editorInstance.getValue() : '';

          if (!code.trim()) {
            showToast('No script in editor. Target saved - use Spawn & Inject button.', 'warn');
            setAttachedState(false, target.name || target.identifier, null, null, true, target.identifier);
            removeToast();
            return;
          }

          // Spawn and inject
          const response = await fetch('/api/spawn-and-inject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier: target.identifier, code })
          });

          const result = await response.json().catch(() => ({}));

          if (!response.ok || (result.ok !== true && result.status !== 'ok')) {
            throw new Error(result.message || `Respawn failed (${response.status})`);
          }

          const displayName = result.name || target.name || target.identifier;
          showToast(`✅ Respawned & injected into ${displayName}`, 'success');
          appendConsole(`Respawned and injected successfully into ${displayName} (PID ${result.pid})`, 'success');
          setAttachedState(true, displayName, result.session_id, result.pid, false, target.identifier);
          removeToast();

        } catch (e) {
          reconnectBtn.innerHTML = 'Respawn & Inject';
          reconnectBtn.disabled = false;
          showToast(`Respawn failed: ${e.message}`, 'error');
          appendConsole(`Respawn error: ${e.message}`, 'error');
        }
      });
    }

    container.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
      toast.style.transform = 'translateX(0)';
      toast.style.opacity = '1';
    });

    // Auto-dismiss after 20 seconds (longer for action toast)
    setTimeout(removeToast, 20000);
  }

  function createToastContainer() {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'fixed top-4 right-4 z-50 space-y-2';
      container.style.cssText = 'pointer-events: none;';
      document.body.appendChild(container);
    }
    return container;
  }

  function joinSessionRoom(sessionId) {
    if (fridaSocket && fridaSocket.connected) {
      fridaSocket.emit('join', { session_id: sessionId });
      console.log('[Socket.IO] Joining room:', sessionId);
    }
  }

  function leaveSessionRoom(sessionId) {
    if (fridaSocket && fridaSocket.connected && sessionId) {
      fridaSocket.emit('leave', { session_id: sessionId });
      console.log('[Socket.IO] Leaving room:', sessionId);
    }
  }

  // Initialize Socket.IO on load
  initFridaSocket();

  // Polling as fallback (less frequent since we have Socket.IO)
  function startConsolePolling(sessionId) {
    console.log('[Console] Starting polling for session:', sessionId);
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }

    // Join Socket.IO room
    joinSessionRoom(sessionId);

    // Don't reset lastMessageId if we're continuing the same session
    if (currentSessionId !== sessionId) {
        lastMessageId = 0; // Only reset for new sessions
    }

    // Polling as backup (every 3 seconds since Socket.IO handles real-time)
    pollingInterval = setInterval(async () => {
        if (!currentSessionId) {
            console.log('[Console] No session ID, stopping polling');
            stopConsolePolling();
            return;
        }

        try {
            const response = await fetch(`/api/console-messages/${currentSessionId}?since=${lastMessageId}`);
            if (!response.ok) {
                console.warn('[Console] Polling response not OK:', response.status);
                return;
            }

            const data = await response.json();

            if (data.messages && data.messages.length > 0) {
                console.log(`[Console] Polling received ${data.messages.length} new messages`);

                data.messages.forEach(msg => {
                    // Only append if not already shown (dedup by ID)
                    if (msg.id > lastMessageId) {
                        appendConsole(msg.message, msg.type);
                    }
                    lastMessageId = Math.max(lastMessageId, msg.id);
                });
            }
        } catch (e) {
            console.error('[Console] Polling error:', e);
        }
    }, 3000); // 3 seconds since Socket.IO handles real-time
  }

  function stopConsolePolling() {
    console.log('[Console] Stopping polling');
    if (pollingInterval) {
      clearInterval(pollingInterval);
      pollingInterval = null;
    }
    // Leave Socket.IO room
    if (currentSessionId) {
      leaveSessionRoom(currentSessionId);
    }
  }

  // ---------------------------------------------
  // Monaco Editor Setup
  // ---------------------------------------------
  // First, check if Monaco is already fully loaded
  if (window.monaco && window.monaco.editor) {
    // Monaco already loaded, just create editor
    setTimeout(createMonacoEditor, 100);
  } else {
    // Load Monaco safely
    loadMonacoEditor();
  }

  function loadMonacoEditor() {
    // Check if require.js is already available
    if (typeof window.require === 'undefined') {
      // Load require.js first
      const requireScript = document.createElement('script');
      requireScript.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.34.1/min/vs/loader.js';
      requireScript.onload = initializeMonacoWithLoader;
      requireScript.onerror = () => console.error('Failed to load Monaco loader');
      document.head.appendChild(requireScript);
    } else {
      // require exists, configure and load
      initializeMonacoWithLoader();
    }
  }

  function initializeMonacoWithLoader() {
    // Safe configuration - check if require.config exists
    if (window.require && typeof window.require.config === 'function') {
      window.require.config({
        paths: { 
          vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.34.1/min/vs'
        }
      });
      
      window.require(['vs/editor/editor.main'], function() {
        createMonacoEditor();
      });
    } else {
      // Fallback: load Monaco directly
      loadMonacoFallback();
    }
  }

  function loadMonacoFallback() {
    console.log('Using fallback Monaco loading');
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.34.1/min/vs/editor/editor.main.js';
    script.onload = () => {
      // Wait a bit for Monaco to initialize
      setTimeout(createMonacoEditor, 300);
    };
    script.onerror = () => console.error('Fallback Monaco loading failed');
    document.head.appendChild(script);
  }

  function createMonacoEditor() {
    const container = document.getElementById('editor');
    if (!container) {
      console.error('Editor container not found');
      return;
    }

    // Check if Monaco is actually available
    if (typeof monaco === 'undefined' || !monaco.editor) {
      console.error('Monaco editor not available');
      return;
    }

    // Dispose previous instance if exists
    if (window.__monacoEditorInstance) {
      try {
        window.__monacoEditorInstance.dispose();
      } catch (e) {
        console.debug('Could not dispose previous editor', e);
      }
    }

    // Set container styles
    if (!container.style.height) container.style.height = '500px';
    container.style.position = 'relative';
    container.style.zIndex = '100';
    container.style.pointerEvents = 'auto';

    try {
      editor = monaco.editor.create(container, {
        value: `// Improved Native Hook Template
if (typeof Java !== 'undefined') {
    // Android Java hooks
    Java.perform(function() {
        send({type: "info", message: "Java runtime detected - Android app process"});
        send({type: "info", message: "Process ID: " + Process.id});
        
        try {
            var Log = Java.use("android.util.Log");
            Log.d.implementation = function(tag, msg) {
                send({type: "info", message: "Log.d: [" + tag + "] " + msg});
                return this.d(tag, msg);
            };
            send({type: "success", message: "Android Log.d hook installed"});
        } catch(e) {
            send({type: "error", message: "Android hook failed: " + e});
        }
    });
} else {
    // Native process hooks
    send({type: "info", message: "Native process detected"});
    send({type: "info", message: "Process ID: " + Process.id});
    send({type: "info", message: "Platform: " + Process.platform + " (" + Process.arch + ")"});
    
    var modules = Process.enumerateModules();
    send({type: "info", message: "Loaded modules: " + modules.length});
    
    // Show first 3 modules
    modules.slice(0, 3).forEach(function(module) {
        send({type: "info", message: "Module: " + module.name + " @ " + module.base});
    });
    
    // Try different malloc variations for Android
    var mallocPtr = null;
    var mallocNames = ["malloc", "__libc_malloc", "je_malloc"];
    
    for (var i = 0; i < mallocNames.length; i++) {
        mallocPtr = Module.findExportByName(null, mallocNames[i]);
        if (mallocPtr) {
            send({type: "success", message: "Found " + mallocNames[i] + " at " + mallocPtr});
            break;
        }
    }
    
    if (mallocPtr) {
        try {
            Interceptor.attach(mallocPtr, {
                onEnter: function(args) {
                    this.size = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (this.size > 10240) {
                        send({type: "info", message: "Large malloc(" + this.size + ") = " + retval});
                    }
                }
            });
            send({type: "success", message: "Native malloc hook installed"});
        } catch(e) {
            send({type: "error", message: "Hook installation failed: " + e});
        }
    } else {
        send({type: "warn", message: "No malloc variant found - trying alternative native hook"});
        
        // Alternative: Hook a more common function
        try {
            var openPtr = Module.findExportByName(null, "open");
            if (openPtr) {
                Interceptor.attach(openPtr, {
                    onEnter: function(args) {
                        var path = args[0].readCString();
                        if (path && path.length < 100) { // Avoid huge paths
                            send({type: "info", message: "File opened: " + path});
                        }
                    }
                });
                send({type: "success", message: "Native open() hook installed as alternative"});
            }
        } catch(e) {
            send({type: "error", message: "Alternative hook failed: " + e});
        }
    }
}`,
        language: 'javascript',
        theme: 'vs-dark',
        fontSize: 14,
        automaticLayout: true,
        minimap: { enabled: true },
        scrollBeyondLastLine: false,
        wordWrap: 'on',
        lineNumbers: 'on',
        folding: true,
        renderWhitespace: 'boundary',
        cursorBlinking: 'smooth',
        formatOnPaste: true,
        formatOnType: true,
        readOnly: false,
        contextmenu: true,
        selectOnLineNumbers: true
      });

      window.__monacoEditorInstance = editor;

      // First paint nudge + a brief retry loop to beat late overlays/reflows
      setTimeout(() => { 
        if (editor) {
          editor.layout(); 
          editor.focus(); 
        }
      }, 30);
      
      retryEnsureEditorInteractive(10, 200);
      window.addEventListener('resize', () => editor && editor.layout());
      
      editor.onDidFocusEditorText(() => console.log('[Monaco] text focused'));
      editor.onDidBlurEditorText(() => console.log('[Monaco] text blurred'));

      const lc = document.getElementById('lineCount');
      editor.onDidChangeCursorPosition((e) => {
        if (lc) lc.textContent = `${e.position.lineNumber}:${e.position.column}`;
      });

      // Auto-save to localStorage
      const AUTO_SAVE_KEY = 'frida_gui_editor_autosave';
      let autoSaveTimeout;
      let lastSavedContent = '';

      editor.onDidChangeModelContent(() => {
        clearTimeout(autoSaveTimeout);
        autoSaveTimeout = setTimeout(() => {
          const content = editor.getValue();
          if (content && content !== lastSavedContent) {
            try {
              localStorage.setItem(AUTO_SAVE_KEY, JSON.stringify({
                content: content,
                timestamp: Date.now()
              }));
              lastSavedContent = content;
              updateAutoSaveIndicator('saved');
              console.log('[Auto-save] Script saved to localStorage');
            } catch (e) {
              console.error('[Auto-save] Failed to save:', e);
              updateAutoSaveIndicator('error');
            }
          }
        }, 2000); // Save after 2 seconds of inactivity
        updateAutoSaveIndicator('pending');
      });

      // Restore auto-saved content on load (silently, no confirmation)
      try {
        const saved = localStorage.getItem(AUTO_SAVE_KEY);
        if (saved) {
          const data = JSON.parse(saved);
          // Only restore if saved within last 24 hours and content exists
          if (data.content && data.timestamp && (Date.now() - data.timestamp < 86400000)) {
            // Check if current editor has default template content
            const currentContent = editor.getValue();
            const isDefaultTemplate = currentContent.includes('// Improved Native Hook Template');

            if (isDefaultTemplate && data.content !== currentContent) {
              // Auto-restore without asking
              editor.setValue(data.content);
              lastSavedContent = data.content;
              console.log('[Auto-save] Restored saved script');
            }
          }
        }
      } catch (e) {
        console.warn('[Auto-save] Could not restore saved content:', e);
      }

    } catch (error) {
      console.error('Failed to create Monaco editor:', error);
    }
  }

  // ---------------------------------------------
  // Console
  // ---------------------------------------------
  function appendConsole(line, type = 'log') {
    const container = document.getElementById('consoleOutput');
    if (!container) return;

    // Deduplication: Create a hash of the message to prevent duplicates
    const msgHash = `${type}:${line}`;
    if (seenMessages.has(msgHash)) {
      console.log('[Console] Skipping duplicate message:', line.substring(0, 50));
      return;
    }
    seenMessages.add(msgHash);

    // Keep seenMessages from growing too large (last 500 unique messages)
    if (seenMessages.size > 500) {
      const arr = Array.from(seenMessages);
      seenMessages = new Set(arr.slice(-300));
    }

    console.log("Appending line to console:", { line, type });

    const time = new Date().toLocaleTimeString();
    const icon = {
        log: '📝', success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️'
    }[type] || '📝';

    const color = {
        log: 'text-green-400',
        success: 'text-green-500',
        error: 'text-red-500',
        warn: 'text-yellow-500',
        info: 'text-blue-400'
    }[type] || 'text-slate-300';

    const div = document.createElement('div');
    div.dataset.type = type; // Store type for filtering
    div.className = `mb-1 ${color}`;
    div.innerHTML = `<span class="text-slate-500">[${time}]</span> <span class="font-medium">${icon} [${type.toUpperCase()}]</span> ${line}`;

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;

    // Limit max lines to avoid overflow
    if (container.children.length > 500) container.removeChild(container.firstChild);
  }

  function clearConsole() {
    if (consoleOut) consoleOut.innerHTML = '';
    lastMessageId = 0; // Reset message counter
    seenMessages.clear(); // Clear deduplication set
    // Reset search
    const searchInput = document.getElementById('consoleSearch');
    const typeFilter = document.getElementById('consoleTypeFilter');
    const matchCount = document.getElementById('consoleMatchCount');
    if (searchInput) searchInput.value = '';
    if (typeFilter) typeFilter.value = 'all';
    if (matchCount) matchCount.classList.add('hidden');
  }
  window.clearConsole = clearConsole;
  window.appendConsole = appendConsole;

  // Auto-save indicator update function
  function updateAutoSaveIndicator(status) {
    const indicator = document.getElementById('autoSaveIndicator');
    if (!indicator) return;

    indicator.classList.remove('hidden', 'text-slate-500', 'text-emerald-400', 'text-amber-400', 'text-red-400');

    if (status === 'saved') {
      indicator.innerHTML = `
        <span class="inline-flex items-center">
          <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
          Saved
        </span>
      `;
      indicator.classList.add('text-emerald-400');
      indicator.classList.remove('hidden');
      // Hide after 3 seconds
      setTimeout(() => indicator.classList.add('hidden'), 3000);
    } else if (status === 'pending') {
      indicator.innerHTML = `
        <span class="inline-flex items-center">
          <svg class="w-3 h-3 mr-1 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          Saving...
        </span>
      `;
      indicator.classList.add('text-amber-400');
      indicator.classList.remove('hidden');
    } else if (status === 'error') {
      indicator.innerHTML = `
        <span class="inline-flex items-center">
          <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          Save failed
        </span>
      `;
      indicator.classList.add('text-red-400');
      indicator.classList.remove('hidden');
    }
  }
  window.updateAutoSaveIndicator = updateAutoSaveIndicator;

  // Console search/filter functionality
  function filterConsole(searchText) {
    const container = document.getElementById('consoleOutput');
    const typeFilter = document.getElementById('consoleTypeFilter');
    const matchCount = document.getElementById('consoleMatchCount');
    if (!container) return;

    const filterType = typeFilter ? typeFilter.value : 'all';
    const searchLower = (searchText || '').toLowerCase().trim();
    const lines = container.querySelectorAll('div');
    let matches = 0;

    lines.forEach(line => {
      const text = line.textContent.toLowerCase();
      const lineType = line.dataset.type || 'log';

      // Check type filter
      const typeMatch = filterType === 'all' || lineType === filterType;

      // Check search text
      const textMatch = !searchLower || text.includes(searchLower);

      if (typeMatch && textMatch) {
        line.style.display = '';
        matches++;

        // Highlight search matches - only in text nodes, not HTML attributes
        if (searchLower) {
          // First restore original content from data attribute if exists
          if (line.dataset.originalHtml) {
            line.innerHTML = line.dataset.originalHtml;
          } else {
            // Store original HTML for later restoration
            line.dataset.originalHtml = line.innerHTML;
          }

          // Now highlight only text content using TreeWalker
          highlightTextInElement(line, searchLower);
        } else if (line.dataset.originalHtml) {
          // No search - restore original
          line.innerHTML = line.dataset.originalHtml;
        }
      } else {
        line.style.display = 'none';
      }
    });

    // Update match count
    if (matchCount) {
      if (searchLower || filterType !== 'all') {
        matchCount.textContent = `${matches} match${matches !== 1 ? 'es' : ''}`;
        matchCount.classList.remove('hidden');
      } else {
        matchCount.classList.add('hidden');
      }
    }
  }

  // Helper function to highlight text only in text nodes (not HTML attributes)
  function highlightTextInElement(element, searchText) {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null, false);
    const textNodes = [];

    while (walker.nextNode()) {
      textNodes.push(walker.currentNode);
    }

    const regex = new RegExp(`(${searchText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');

    textNodes.forEach(node => {
      const text = node.nodeValue;
      if (regex.test(text)) {
        const span = document.createElement('span');
        span.innerHTML = text.replace(regex, '<mark class="bg-yellow-500/50 text-white rounded px-0.5">$1</mark>');
        node.parentNode.replaceChild(span, node);
      }
    });
  }

  window.filterConsole = filterConsole;

  // ---------------------------------------------
  // Attachment State
  // ---------------------------------------------
  function updateDisconnectButton(show) {
    // Get fresh reference each time to avoid stale element issues
    const disconnectBtn = document.getElementById('disconnectBtn');
    const reconnectBtn = document.getElementById('reconnectBtn');

    if (disconnectBtn) {
      if (show) {
        disconnectBtn.classList.remove('hidden');
      } else {
        disconnectBtn.classList.add('hidden');
      }
    }

    // Reconnect button should ONLY show when:
    // 1. We're disconnected (show = false)
    // 2. We've been connected before (hasBeenConnected = true)
    // 3. A target is still saved
    if (reconnectBtn) {
      if (!show && hasBeenConnected) {
        // Check if there's a saved target
        fetch('/api/target')
          .then(res => res.ok ? res.json() : null)
          .then(target => {
            if (target && target.identifier) {
              reconnectBtn.classList.remove('hidden');
            } else {
              reconnectBtn.classList.add('hidden');
            }
          })
          .catch(() => reconnectBtn.classList.add('hidden'));
      } else {
        reconnectBtn.classList.add('hidden');
      }
    }
  }

  // Update detailed process info panel
  function updateProcessInfoPanel(show, pid = null, packageId = null) {
    const panel = document.getElementById('processInfoPanel');
    const pidEl = document.getElementById('processInfoPid');
    const packageEl = document.getElementById('processInfoPackage');

    if (!panel) return;

    if (show && (pid || packageId)) {
      panel.classList.remove('hidden');
      if (pidEl) pidEl.textContent = pid || '—';
      if (packageEl) packageEl.textContent = packageId || '—';
    } else {
      panel.classList.add('hidden');
      if (pidEl) pidEl.textContent = '—';
      if (packageEl) packageEl.textContent = '—';
    }
  }

  async function disconnectFromProcess() {
    try {
      // Set flag to suppress the "frida_disconnected" notification since this is intentional
      intentionalDisconnect = true;

      // Detach from process
      const detachResponse = await fetch('/api/detach', { method: 'POST' });
      await detachResponse.json();

      // Also clear the saved target
      try {
        await fetch('/api/target', { method: 'DELETE' });
      } catch (_) {}

      appendConsole('Disconnected from process', 'warn');
      showToast('Disconnected from process', 'success');
      setAttachedState(false);
      currentSessionId = null;
      lastAttachedPid = null;
      hasBeenConnected = false; // Reset since user intentionally disconnected and target is deleted
    } catch (e) {
      showToast(`Disconnect error: ${e.message}`, 'error');
    } finally {
      // Reset the flag after a short delay to handle any late disconnect events
      setTimeout(() => { intentionalDisconnect = false; }, 1000);
    }
  }
  window.disconnectFromProcess = disconnectFromProcess;

  async function reconnectToTarget() {
    try {
      // Get saved target
      const tRes = await fetch('/api/target');
      if (!tRes.ok) {
        showToast('No saved target. Please select a process from Dashboard first.', 'warn');
        return;
      }

      const target = await tRes.json();
      const identifier = target.identifier;
      const displayName = target.name || identifier || 'Process';

      showToast(`Reconnecting to ${displayName}...`, 'info');
      appendConsole(`Attempting to reconnect to ${displayName}...`, 'info');

      // Use attach-only endpoint to avoid launching the app
      const response = await fetch(`/api/attach-only/${identifier}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: displayName })
      });

      const result = await response.json();

      if (!response.ok || result.status === 'error') {
        // If app is not running, show helpful message
        if (response.status === 404 || result.message.includes('not running')) {
          showToast(`App is not running. Please launch "${displayName}" manually first.`, 'warn');
          appendConsole(`Cannot reconnect: App "${displayName}" is not running. Launch it first.`, 'warn');
        } else {
          throw new Error(result.message || 'Failed to reconnect');
        }
        return;
      }

      // Successfully reconnected
      showToast(`✅ Reconnected to ${displayName}`, 'success');
      appendConsole(`Reconnected to ${displayName} (PID ${result.pid})`, 'success');
      setAttachedState(true, displayName, result.session_id, result.pid, false, identifier);

      // Track reconnection in history (without scripts since we're just attaching)
      if (typeof window.addToHistory === 'function') {
        window.addToHistory({
          identifier: identifier,
          name: displayName,
          pid: result.pid
        }, []);
      }

    } catch (e) {
      appendConsole(`Reconnect failed: ${e.message}`, 'error');
      showToast(`❌ Reconnect failed: ${e.message}`, 'error');
    }
  }
  window.reconnectToTarget = reconnectToTarget;

  function setAttachedState(attached, name = '—', sessionId = null, pid = null, savedTargetOnly = false, packageId = null) {
    console.log(`[State] setAttachedState: attached=${attached}, sessionId=${sessionId}, pid=${pid}, packageId=${packageId}, savedTargetOnly=${savedTargetOnly}`);

    window.setAttachedState = setAttachedState;

    // Get fresh references to DOM elements to avoid stale references
    const badgeEl = document.getElementById('attachedBadge');
    const labelEl = document.getElementById('attachedProcessLabel');
    const runBtnEl = document.getElementById('runScript');

    const isNewSession = currentSessionId !== sessionId;
    currentSessionId = sessionId;

    if (savedTargetOnly && !attached) {
      // Saved target, NOT attached yet
      if (badgeEl) {
        badgeEl.textContent = 'Target Saved';
        badgeEl.classList.remove('bg-emerald-600', 'bg-slate-700');
        badgeEl.classList.add('bg-yellow-600');
      }
      if (labelEl) labelEl.textContent = name || '—';

      if (runBtnEl) {
        runBtnEl.disabled = true;
        runBtnEl.classList.add('opacity-50', 'cursor-not-allowed');
      }

      updateDisconnectButton(false); // Hide disconnect when not attached
      updateProcessInfoPanel(false); // Hide process info when not attached
      stopConsolePolling();
      lastAttachedPid = null;
      return;
    }

    if (attached) {
      // Truly attached (has a valid session_id from backend)
      hasBeenConnected = true; // Mark that we've been connected

      if (badgeEl) {
        badgeEl.textContent = 'Attached';
        badgeEl.classList.remove('bg-slate-700', 'bg-yellow-600');
        badgeEl.classList.add('bg-emerald-600');
      }
      if (labelEl) labelEl.textContent = name || '—';

      if (runBtnEl) {
        runBtnEl.disabled = false;
        runBtnEl.classList.remove('opacity-50', 'cursor-not-allowed');
      }

      updateDisconnectButton(true); // Show disconnect when attached
      updateProcessInfoPanel(true, pid, packageId || name); // Show process info with PID and package

      if (sessionId && isNewSession) {
        appendConsole(`Connected to ${name || 'process'}${pid ? ` (PID: ${pid})` : ''}`, 'success');
        startConsolePolling(sessionId);
        console.log(`[State] Started new session: ${sessionId}`);
      }

      if (pid && lastAttachedPid !== pid) {
        if (typeof showToast === 'function') showToast(`Connected to ${name || ('PID ' + pid)}`, 'success');
        lastAttachedPid = pid;
      }
      return;
    }

    // Fallback: not attached and no saved target
    if (badgeEl) {
      badgeEl.textContent = 'Not Attached';
      badgeEl.classList.remove('bg-emerald-600', 'bg-yellow-600');
      badgeEl.classList.add('bg-slate-700');
    }
    if (labelEl) labelEl.textContent = '—';

    if (runBtnEl) {
      runBtnEl.disabled = true;
      runBtnEl.classList.add('opacity-50', 'cursor-not-allowed');
    }

    updateDisconnectButton(false); // Hide disconnect when not attached
    updateProcessInfoPanel(false); // Hide process info when not attached
    stopConsolePolling();
    if (lastAttachedPid !== null) {
      if (typeof showToast === 'function') showToast('No process attached. Go to Dashboard first.', 'warn');
      lastAttachedPid = null;
    }
  }


  async function refreshAttachmentFromBackend() {
    try {
      const res = await fetch('/api/attached-process');
      const data = await res.json();

      if (data && data.session_active) {
        // Build a reliable display name and get package identifier:
        let displayName = data.name;
        let packageId = data.identifier || null;

        // Try to get more info from saved target
        try {
          const tRes = await fetch('/api/target');
          if (tRes.ok) {
            const t = await tRes.json();
            if (t.ok && t.identifier) {
              packageId = t.identifier;
              if (!displayName) {
                displayName = t.name || t.identifier;
              }
            }
          }
        } catch (_) {}

        if (!displayName) {
          displayName = data.identifier || (data.pid ? `PID ${data.pid}` : 'Process');
        }

        setAttachedState(true, displayName, data.session_id, data.pid, false, packageId);
      } else {
        // No active session → see if a target was saved on Dashboard
        try {
          const tRes = await fetch('/api/target');
          if (tRes.ok) {
            const target = await tRes.json();
            // Check if target actually has valid data (ok: true and has identifier)
            if (target.ok && target.identifier) {
              setAttachedState(false, target.name || target.identifier || '—', null, null, true, target.identifier);
            } else {
              // No valid target saved
              setAttachedState(false);
            }
          } else {
            // 404 or error - no target saved
            setAttachedState(false);
          }
        } catch (_) {
          setAttachedState(false);
        }
      }
    } catch (e) {
      console.warn('refreshAttachmentFromBackend error:', e);
      setAttachedState(false);
    } finally {
      ensureEditorInteractive();
    }
  }


  // ---------------------------------------------
  // Load Script
  // ---------------------------------------------

  

async function onClickSpawnAndInject() {
  const editorInstance = window.__monacoEditorInstance;
  const code = editorInstance ? editorInstance.getValue() : '';
  if (!code.trim()) {
    showToast('Please enter some JavaScript code first', 'warn');
    return;
  }

  const btn = document.getElementById('spawnInject');
  const originalHTML = btn ? btn.innerHTML : null;
  if (btn) { btn.innerHTML = '<span class="animate-pulse">⏳ Spawning...</span>'; btn.disabled = true; }

  try {
    // Saved target is the source of truth for the display name
    const tRes = await fetch('/api/target');
    if (!tRes.ok) {
      showToast('No target selected. Go to Dashboard and pick a process first.', 'warn');
      return;
    }
    const target = await tRes.json();
    const identifier = target.identifier;
    let displayName = target.name || identifier || 'Process';

    // Clean spawn: detach if already attached
    try {
      const sess = await fetch('/api/attached-process').then(r => r.json());
      if (sess?.session_active) await fetch('/api/detach', { method: 'POST' });
    } catch (_) {}

    // Spawn & inject the editor code
    const response = await fetch('/api/spawn-and-inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier, code })
    });
    const result = await response.json().catch(() => ({}));

    if (!response.ok || (result.ok !== true && result.status !== 'ok')) {
      const msg = result.message || `HTTP ${response.status}`;
      throw new Error(msg);
    }

    // If backend includes name, prefer it; else keep our displayName
    displayName = result.name || displayName || (result.pid ? `PID ${result.pid}` : 'Process');

    showToast(`✅ Spawned & injected into ${displayName}`, 'success');
    appendConsole(`Spawned and injected successfully into ${displayName} (PID ${result.pid})`, 'success');
    setAttachedState(true, displayName, result.session_id, result.pid, false, identifier);

    // Track this session in history
    if (typeof window.addToHistory === 'function') {
      window.addToHistory({
        identifier: identifier,
        name: displayName,
        pid: result.pid
      }, ['Custom Script']);
    }

  } catch (e) {
    appendConsole(`Error: ${e.message}`, 'error');
    showToast(`❌ ${e.message}`, 'error');
  } finally {
    if (btn && originalHTML) { btn.innerHTML = originalHTML; btn.disabled = false; }
  }
}





  
  const spawnBtn = document.getElementById('spawnInject');
  if (spawnBtn) spawnBtn.addEventListener('click', onClickSpawnAndInject);


  function formatEditorScript() {
  if (!window.__monacoEditorInstance) return;

  try {
    // Use Monaco's built-in formatting action
    window.__monacoEditorInstance.getAction('editor.action.formatDocument').run()
      .then(() => {
        showToast('Script formatted', 'success');
      })
      .catch((err) => {
        // Fallback to basic formatting if Monaco formatter fails
        console.warn('Monaco formatter failed, using fallback:', err);
        basicFormat();
      });
  } catch (e) {
    // Fallback for older Monaco versions or errors
    basicFormat();
  }

  function basicFormat() {
    try {
      const code = window.__monacoEditorInstance.getValue();
      // Improved basic JS formatting using js-beautify style logic
      let formatted = code;
      let indent = 0;
      const lines = [];

      // Split into tokens for better formatting
      const tokens = code.split(/(\{|\}|;|\n)/);
      let currentLine = '';

      for (const token of tokens) {
        if (token === '{') {
          currentLine += token;
          lines.push('  '.repeat(indent) + currentLine.trim());
          currentLine = '';
          indent++;
        } else if (token === '}') {
          if (currentLine.trim()) {
            lines.push('  '.repeat(indent) + currentLine.trim());
            currentLine = '';
          }
          indent = Math.max(0, indent - 1);
          lines.push('  '.repeat(indent) + token);
        } else if (token === ';') {
          currentLine += token;
          lines.push('  '.repeat(indent) + currentLine.trim());
          currentLine = '';
        } else if (token === '\n') {
          if (currentLine.trim()) {
            lines.push('  '.repeat(indent) + currentLine.trim());
            currentLine = '';
          }
        } else {
          currentLine += token;
        }
      }

      if (currentLine.trim()) {
        lines.push('  '.repeat(indent) + currentLine.trim());
      }

      formatted = lines
        .filter(line => line.trim() !== '')
        .join('\n')
        .replace(/\n\s*\n\s*\n/g, '\n\n'); // Remove excessive empty lines

      window.__monacoEditorInstance.setValue(formatted);
      showToast('Script formatted', 'success');
    } catch (e) {
      showToast('Format failed: ' + e.message, 'error');
    }
  }
}


function validateEditorScript() {
  if (!window.__monacoEditorInstance) return;

  try {
    const code = window.__monacoEditorInstance.getValue();
    if (!code.trim()) {
      showToast('Editor is empty', 'warn');
      return;
    }

    // Basic syntax validation
    new Function(code);
    showToast('✅ Script syntax is valid', 'success');
  } catch (e) {
    showToast('❌ Syntax error: ' + e.message, 'error');
    appendConsole('Syntax validation failed: ' + e.message, 'error');
  }
}

  // Make format and validate globally available for onclick handlers
  window.formatEditorScript = formatEditorScript;
  window.validateEditorScript = validateEditorScript;

  // ---------------------------------------------
  // Frida Version Display
  // ---------------------------------------------
  async function loadFridaVersions() {
    try {
      const response = await fetch('/api/frida-version');
      const data = await response.json();

      const clientVersionEl = document.getElementById('fridaClientVersionScripts');
      const serverVersionEl = document.getElementById('fridaServerVersionScripts');

      if (data.status === 'ok') {
        if (clientVersionEl) clientVersionEl.textContent = data.client_version;

        if (serverVersionEl) {
          serverVersionEl.textContent = data.server_version;

          // Update color based on server status
          serverVersionEl.classList.remove('text-emerald-400', 'text-amber-400', 'text-red-400', 'text-slate-400');
          if (data.server_status === 'connected') {
            serverVersionEl.classList.add('text-emerald-400'); // Green if connected and running
          } else if (data.server_status === 'not_running') {
            serverVersionEl.classList.add('text-red-400'); // Red if not running
          } else {
            serverVersionEl.classList.add('text-slate-400'); // Gray if not connected
          }
        }
      } else {
        if (clientVersionEl) clientVersionEl.textContent = 'Unknown';
        if (serverVersionEl) serverVersionEl.textContent = 'Unknown';
      }
    } catch (error) {
      console.error('Failed to load Frida versions:', error);
      const clientVersionEl = document.getElementById('fridaClientVersionScripts');
      const serverVersionEl = document.getElementById('fridaServerVersionScripts');
      if (clientVersionEl) clientVersionEl.textContent = 'Error';
      if (serverVersionEl) serverVersionEl.textContent = 'Error';
    }
  }

  // ---------------------------------------------
  // Lifecycle
  // ---------------------------------------------
  function kick() {
    refreshAttachmentFromBackend();
    loadFridaVersions();
    // brief retries to beat late reflows after nav
    retryEnsureEditorInteractive(8, 150);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', kick);
  } else {
    // DOM already parsed (common when scripts at end of body)
    kick();
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) setTimeout(kick, 300);
  });

  window.addEventListener('focus', () => {
    setTimeout(kick, 300);
  });

  window.addEventListener('pageshow', () => {
    // handles bfcache restores
    setTimeout(kick, 100);
  });

  // Tutorial banner close function
  function closeTutorial() {
    const banner = document.getElementById('tutorialBanner');
    if (banner) {
      banner.style.opacity = '0';
      banner.style.transform = 'translateY(-10px)';
      banner.style.transition = 'all 0.3s ease';

      setTimeout(() => {
        banner.style.display = 'none';
      }, 300);

      // Remember user dismissed it
      try {
        localStorage.setItem('frida_tutorial_dismissed', 'true');
      } catch (e) {
        console.warn('Failed to save tutorial preference:', e);
      }
    }
  }
  window.closeTutorial = closeTutorial;

  // Check if tutorial should be hidden on load
  function checkTutorialVisibility() {
    try {
      const dismissed = localStorage.getItem('frida_tutorial_dismissed');
      if (dismissed === 'true') {
        const banner = document.getElementById('tutorialBanner');
        if (banner) {
          banner.style.display = 'none';
        }
      }
    } catch (e) {
      console.warn('Failed to check tutorial preference:', e);
    }
  }

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    stopConsolePolling();
  });

  // Check tutorial visibility after page loads
  setTimeout(checkTutorialVisibility, 100);
}
