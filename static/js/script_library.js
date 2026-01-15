// static/js/script_library.js
if (!window.__scriptLibraryLoaded) {
  window.__scriptLibraryLoaded = true;

  // Script Library Management
  let scriptLibrary = [];
  let filteredScripts = [];
  let pendingDeleteScriptId = null;
  window.selectedScriptIds = new Set();

  // Search and filter state
  let currentFilters = {
    search: '',
    platform: 'all',
    category: 'All',
    tags: new Set()
  };

  function showDeleteModal(scriptId) {
    pendingDeleteScriptId = scriptId;
    document.getElementById('deleteModal').classList.remove('hidden');
    document.getElementById('deleteModal').classList.add('flex');
  }

  function hideDeleteModal() {
    pendingDeleteScriptId = null;
    document.getElementById('deleteModal').classList.add('hidden');
    document.getElementById('deleteModal').classList.remove('flex');
  }

  async function confirmDeleteScript() {
    if (!pendingDeleteScriptId) return;

    try {
      const res = await fetch(`/api/scripts/${pendingDeleteScriptId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Delete failed');
      
      const result = await res.json();
      if (result.status === 'ok') {
        if (typeof showToast === 'function') showToast('Script deleted successfully', 'success');
        await forceRefreshScriptLibrary();
      } else {
        if (typeof showToast === 'function') showToast('Delete failed: ' + result.message, 'error');
      }
    } catch (e) {
      console.error('Delete error:', e);
      if (typeof showToast === 'function') showToast('Failed to delete script: ' + e.message, 'error');
    } finally {
      hideDeleteModal();
    }
  }

  function ensureLibraryToolbar() {
    const host = document.getElementById('libraryToolbar');
    const list = document.getElementById('scriptList');
    if (host || !list) return;

    const toolbar = document.createElement('div');
    toolbar.id = 'libraryToolbar';
    toolbar.className = 'mb-3 space-y-3';

    toolbar.innerHTML = `
      <!-- Search and Filters -->
      <div class="glass-effect rounded-lg p-4 border border-slate-700/50">
        <div class="flex items-center gap-2 mb-3">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
          </svg>
          <span class="text-sm font-medium text-white">Search & Filter</span>
        </div>

        <!-- Search Input -->
        <div class="mb-3">
          <input type="text" id="scriptSearch" 
                 class="w-full bg-dark-800 text-white px-3 py-2 rounded-lg border border-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200 text-sm"
                 placeholder="Search by name, description..."
                 autocomplete="off">
        </div>

        <!-- Filter Row -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
          <!-- Platform Filter -->
          <div>
            <label class="block text-xs font-medium text-slate-300 mb-1">Platform</label>
            <select id="platformFilter" class="w-full bg-dark-800 text-white px-3 py-2 rounded-lg border border-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200 text-sm">
              <option value="all">All Platforms</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
            </select>
          </div>

          <!-- Category Filter -->
          <div>
            <label class="block text-xs font-medium text-slate-300 mb-1">Category</label>
            <select id="categoryFilter" class="w-full bg-dark-800 text-white px-3 py-2 rounded-lg border border-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200 text-sm">
              <option value="All">All Categories</option>
              <option value="Crypto">Cryptography</option>
              <option value="Network">Networking</option>
              <option value="Memory">Memory Analysis</option>
              <option value="API">API Hooking</option>
              <option value="Android">Android</option>
              <option value="iOS">iOS</option>
              <option value="Bypass">Bypass</option>
              <option value="Hooking">Hooking</option>
              <option value="Custom">Custom</option>
            </select>
          </div>
        </div>

        <!-- Tag Filter -->
        <div class="mb-3">
          <label class="block text-xs font-medium text-slate-300 mb-2">Tags</label>
          <div id="tagContainer" class="flex flex-wrap gap-1 mb-2 min-h-[24px]">
            <!-- Available tags will be populated here -->
          </div>
          <input type="text" id="tagInput" 
                 class="w-full bg-dark-800 text-white px-3 py-2 rounded-lg border border-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200 text-sm"
                 placeholder="Filter by tags (ssl, root, network, etc.)"
                 autocomplete="off">
        </div>

        <!-- Filter Stats & Clear -->
        <div class="flex items-center justify-between">
          <div class="text-xs text-slate-400">
            <span id="filteredCount">0</span> of <span id="totalCount">0</span> scripts
          </div>
          <button id="clearFiltersBtn" 
                  class="px-3 py-1 rounded text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-all duration-200">
            Clear All
          </button>
        </div>
      </div>

      <!-- Action Toolbar -->
      <div class="flex flex-col gap-2">
        <div class="flex gap-2">
          <button id="injectSelectedBtn"
                  class="px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-sm disabled:opacity-50 disabled:cursor-not-allowed">
            Inject Selected (<span id="selectedCount">0</span>)
          </button>
          <button id="selectAllBtn"
                  class="px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm">
            Select All
          </button>
          <button id="clearSelectionBtn"
                  class="px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm">
            Clear
          </button>
        </div>
        <div class="text-xs text-slate-400">
          Select scripts to inject directly.
        </div>
      </div>
    `;

    list.parentNode.insertBefore(toolbar, list);
    setupSearchAndFilterListeners();
    setupToolbarListeners();
  }

// Update the button text in setupToolbarListeners():
function setupToolbarListeners() {
  document.getElementById('injectSelectedBtn')?.addEventListener('click', injectSelectedScripts);
  
  // Update button text to be clearer
  const injectBtn = document.getElementById('injectSelectedBtn');
  if (injectBtn) {
    injectBtn.innerHTML = 'Spawn & Inject Selected (<span id="selectedCount">0</span>)';
  }
  
  document.getElementById('selectAllBtn')?.addEventListener('click', () => {
    const boxes = document.querySelectorAll('.script-select');
    boxes.forEach(cb => { 
      cb.checked = true; 
      selectedScriptIds.add(Number(cb.dataset.scriptId)); 
    });
    updateSelectedCount();
  });
  document.getElementById('clearSelectionBtn')?.addEventListener('click', () => {
    selectedScriptIds.clear();
    const boxes = document.querySelectorAll('.script-select');
    boxes.forEach(cb => { cb.checked = false; });
    updateSelectedCount();
  });
}

  function setupSearchAndFilterListeners() {
    const searchInput = document.getElementById('scriptSearch');
    const platformFilter = document.getElementById('platformFilter');
    const categoryFilter = document.getElementById('categoryFilter');
    const tagInput = document.getElementById('tagInput');
    const clearFiltersBtn = document.getElementById('clearFiltersBtn');

    if (searchInput) {
      searchInput.addEventListener('input', debounce((e) => {
        currentFilters.search = e.target.value.toLowerCase().trim();
        applyFilters();
      }, 300));
    }

    if (platformFilter) {
      platformFilter.addEventListener('change', (e) => {
        currentFilters.platform = e.target.value;
        applyFilters();
      });
    }

    if (categoryFilter) {
      categoryFilter.addEventListener('change', (e) => {
        currentFilters.category = e.target.value;
        applyFilters();
      });
    }

    if (tagInput) {
      tagInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
          e.preventDefault();
          const tag = e.target.value.trim().toLowerCase();
          if (tag && !currentFilters.tags.has(tag)) {
            currentFilters.tags.add(tag);
            updateTagDisplay();
            applyFilters();
          }
          e.target.value = '';
        }
      });
    }

    if (clearFiltersBtn) {
      clearFiltersBtn.addEventListener('click', clearAllFilters);
    }
  }

  function applyFilters() {
    if (!scriptLibrary.length) {
      filteredScripts = [];
      renderScriptLibrary(filteredScripts);
      return;
    }

    filteredScripts = scriptLibrary.filter(script => {
      // Search filter
      if (currentFilters.search) {
        const searchMatch = 
          (script.name || '').toLowerCase().includes(currentFilters.search) ||
          (script.description || '').toLowerCase().includes(currentFilters.search);
        if (!searchMatch) return false;
      }

      // Platform filter
      if (currentFilters.platform !== 'all' && script.platform !== currentFilters.platform) {
        return false;
      }

      // Category filter
      if (currentFilters.category !== 'All' && script.category !== currentFilters.category) {
        return false;
      }

      // Tag filter
      if (currentFilters.tags.size > 0) {
        const scriptTags = getScriptTags(script);
        const hasMatchingTag = Array.from(currentFilters.tags).some(tag => 
          scriptTags.some(scriptTag => scriptTag.toLowerCase().includes(tag))
        );
        if (!hasMatchingTag) return false;
      }

      return true;
    });

    renderScriptLibrary(filteredScripts);
    updateFilterStats();
  }

  function getScriptTags(script) {
    const tags = [];
    const text = `${script.name || ''} ${script.description || ''}`.toLowerCase();
    
    const tagPatterns = [
      /\b(ssl|tls|certificate|cert|pinning)\b/g,
      /\b(root|su|superuser|admin)\b/g,
      /\b(network|http|https|tcp|udp|socket)\b/g,
      /\b(crypto|encryption|decrypt|aes|rsa)\b/g,
      /\b(bypass|disable|patch|hook)\b/g,
      /\b(memory|heap|malloc|alloc)\b/g,
      /\b(api|function|method|call)\b/g,
      /\b(android|java|jni|dalvik)\b/g,
      /\b(ios|objective-c|swift|cocoa)\b/g,
      /\b(debug|log|trace|monitor)\b/g,
      /\b(anti|protection|detection|evasion)\b/g
    ];

    tagPatterns.forEach(pattern => {
      const matches = text.match(pattern);
      if (matches) {
        tags.push(...matches);
      }
    });

    if (script.tags && Array.isArray(script.tags)) {
      tags.push(...script.tags);
    }

    return [...new Set(tags)];
  }

  function updateTagDisplay() {
    const container = document.getElementById('tagContainer');
    if (!container) return;

    container.innerHTML = '';
    
    currentFilters.tags.forEach(tag => {
      const tagElement = document.createElement('span');
      tagElement.className = 'inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
      tagElement.innerHTML = `
        ${tag}
        <button onclick="removeTag('${tag}')" class="hover:text-emerald-200">×</button>
      `;
      container.appendChild(tagElement);
    });

    if (currentFilters.tags.size === 0 && scriptLibrary.length > 0) {
      const allTags = new Set();
      scriptLibrary.forEach(script => {
        getScriptTags(script).forEach(tag => allTags.add(tag));
      });

      const popularTags = Array.from(allTags).slice(0, 8);
      popularTags.forEach(tag => {
        const tagElement = document.createElement('button');
        tagElement.className = 'inline-flex items-center px-2 py-1 rounded text-xs bg-slate-700 hover:bg-emerald-600 text-slate-300 hover:text-white transition-all duration-200';
        tagElement.textContent = tag;
        tagElement.onclick = () => addTag(tag);
        container.appendChild(tagElement);
      });
    }
  }

  function addTag(tag) {
    if (!currentFilters.tags.has(tag.toLowerCase())) {
      currentFilters.tags.add(tag.toLowerCase());
      updateTagDisplay();
      applyFilters();
    }
  }

  function removeTag(tag) {
    currentFilters.tags.delete(tag);
    updateTagDisplay();
    applyFilters();
  }

  function clearAllFilters() {
    currentFilters = {
      search: '',
      platform: 'all',
      category: 'All',
      tags: new Set()
    };

    const searchInput = document.getElementById('scriptSearch');
    const platformFilter = document.getElementById('platformFilter');
    const categoryFilter = document.getElementById('categoryFilter');
    const tagInput = document.getElementById('tagInput');

    if (searchInput) searchInput.value = '';
    if (platformFilter) platformFilter.value = 'all';
    if (categoryFilter) categoryFilter.value = 'All';
    if (tagInput) tagInput.value = '';

    updateTagDisplay();
    applyFilters();
  }

  function updateFilterStats() {
    const totalCount = document.getElementById('totalCount');
    const filteredCount = document.getElementById('filteredCount');
    
    if (totalCount) totalCount.textContent = scriptLibrary.length;
    if (filteredCount) filteredCount.textContent = filteredScripts.length;
  }

  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  function updateSelectedCount() {
    const el = document.getElementById('selectedCount');
    const btn = document.getElementById('injectSelectedBtn');
    if (el) el.textContent = String(selectedScriptIds.size);
    if (btn) btn.disabled = selectedScriptIds.size === 0;
  }

  function renderScriptLibrary(scripts) {
    ensureLibraryToolbar();
    selectedScriptIds.clear();
    updateSelectedCount();
    updateFilterStats();

    const scriptList = document.getElementById('scriptList');
    if (!scriptList) return;

    const scriptsToRender = scripts || filteredScripts || scriptLibrary;

    if (scriptsToRender.length === 0) {
      const hasActiveFilters = currentFilters.search || 
                              currentFilters.platform !== 'all' || 
                              currentFilters.category !== 'All' || 
                              currentFilters.tags.size > 0;
      
      const message = hasActiveFilters ? 
        'No scripts match your filters' : 
        'No scripts found';
      
      scriptList.innerHTML = `<div class="text-center text-slate-400 py-4">${message}</div>`;
      return;
    }

    const categories = {};
    scriptsToRender.forEach(s => {
      categories[s.category] = categories[s.category] || [];
      categories[s.category].push(s);
    });

    let html = '';
    for (const [category, categoryScripts] of Object.entries(categories)) {
      html += `
        <div class="category-section mb-4">
          <h4 class="text-xs font-semibold text-slate-400 uppercase mb-2 flex items-center justify-between">
            <span>${category}</span>
            <span class="text-xs text-slate-500">(${categoryScripts.length})</span>
          </h4>
          <div class="space-y-2">`;

      categoryScripts.forEach(script => {
        const platformColor = {
          'android': 'bg-green-500/20 text-green-400',
          'ios': 'bg-blue-500/20 text-blue-400',
          'linux': 'bg-yellow-500/20 text-yellow-400',
          'windows': 'bg-purple-500/20 text-purple-400',
          'all': 'bg-gray-500/20 text-gray-400'
        }[script.platform] || 'bg-gray-500/20 text-gray-400';

        const difficultyColor = {
          'beginner': 'text-green-400',
          'intermediate': 'text-yellow-400',
          'advanced': 'text-red-400'
        }[script.difficulty] || 'text-gray-400';

        const scriptTags = getScriptTags(script);
        const tagsHtml = scriptTags.slice(0, 3).map(tag => 
          `<span class="inline-block px-1 py-0.5 rounded text-xs bg-slate-600/50 text-slate-300">#${tag}</span>`
        ).join(' ');

        html += `
          <div class="script-item p-3 bg-dark-800 rounded-lg border border-slate-600 hover:border-slate-500 transition-all duration-200 group">
            <div class="flex items-start justify-between gap-3">
              <label class="pt-1 flex-shrink-0">
                <input type="checkbox" class="script-select accent-emerald-500"
                       data-script-id="${script.id}"
                       onchange="handleScriptCheckbox(this, ${script.id})">
              </label>

              <div class="flex-1 min-w-0 cursor-pointer" 
                   onclick="loadScriptFromLibrary(${script.id})">
                <h3 class="text-sm font-medium text-white group-hover:text-primary-400 transition-colors duration-200 truncate" title="${script.name}">
                  ${script.name}
                </h3>
                <p class="text-xs text-slate-400 mt-1 line-clamp-2" title="${script.description || ''}">
                  ${script.description || 'No description'}
                </p>
                <div class="flex items-center space-x-2 mt-2 flex-wrap gap-1">
                  <span class="inline-flex items-center px-2 py-1 rounded text-xs ${platformColor}">
                    ${script.platform}
                  </span>
                  <span class="text-xs ${difficultyColor}">
                    ${script.difficulty}
                  </span>
                  ${script.filename ? '<span class="text-xs text-slate-500">📁</span>' : ''}
                </div>
                ${tagsHtml ? `<div class="mt-2 flex flex-wrap gap-1">${tagsHtml}</div>` : ''}
              </div>

              <div class="flex flex-col items-center justify-start space-y-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200 ml-2 flex-shrink-0">
                <button onclick="event.stopPropagation(); showDeleteModal(${script.id})" 
                        title="Delete script">
                  <svg class="w-4 h-4 text-red-400 hover:text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>`;
      });

      html += '</div></div>';
    }

    scriptList.innerHTML = html;
    updateTagDisplay();
  }

  function handleScriptCheckbox(checkbox, scriptId) {
    if (checkbox.checked) {
      selectedScriptIds.add(scriptId);
    } else {
      selectedScriptIds.delete(scriptId);
    }
    updateSelectedCount();
  }

  async function injectSelectedScripts() {
    if (selectedScriptIds.size === 0) {
      showToast('Select at least one script', 'warn');
      return;
    }

    // Sort IDs in ascending order to ensure consistent loading order
    // This matches CLI behavior where scripts load in the order specified
    const ids = Array.from(selectedScriptIds).sort((a, b) => a - b);
    const btn = document.getElementById('injectSelectedBtn');
    const originalHTML = btn ? btn.innerHTML : null;
    if (btn) {
      btn.innerHTML = `<span class="flex items-center justify-center space-x-2">
        <svg class="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <circle cx="12" cy="12" r="10" stroke-width="2" class="opacity-25"></circle>
          <path d="M4 12a8 8 0 018-8" stroke-width="2" stroke-linecap="round" class="opacity-75"></path>
        </svg>
        <span>Spawning & Injecting...</span>
      </span>`;
      btn.disabled = true;
    }

    try {
      // saved target
      const tRes = await fetch('/api/target');
      if (!tRes.ok) throw new Error('No saved target. Pick a process on Dashboard.');
      const t = await tRes.json();
      const displayName = t.name || t.identifier;

      // clean spawn (detach if needed)
      try {
        const s = await fetch('/api/attached-process').then(r => r.json());
        if (s?.session_active) await fetch('/api/detach', { method: 'POST' });
      } catch {}

      // spawn & inject multiple scripts
      const res = await fetch('/api/spawn-and-inject-library', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script_ids: ids })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok !== true) {
        throw new Error(data.message || `Spawn + inject failed (${res.status})`);
      }

      // flip UI on Scripts page
      if (typeof window.setAttachedState === 'function') {
        window.setAttachedState(true, data.name || displayName, data.session_id, data.pid, false, t.identifier || displayName);
      }
      showToast(`✅ Spawned & injected ${data.loaded_count || ids.length} script(s) into ${data.name || displayName}`, 'success');
      appendConsole(`Spawned & injected into ${data.name || displayName} (PID ${data.pid})`, 'success');

    } catch (e) {
      let friendlyMessage = 'Failed to spawn and inject scripts';

      // Provide user-friendly error messages
      if (e.message.includes('No saved target')) {
        friendlyMessage = 'No target selected. Please go to Dashboard and select a process first.';
      } else if (e.message.includes('device not found') || e.message.includes('no devices')) {
        friendlyMessage = 'Device disconnected. Please check your USB connection and try again.';
      } else if (e.message.includes('Frida')) {
        friendlyMessage = 'Frida error. Make sure Frida server is running on your device.';
      } else if (e.message.includes('unauthorized')) {
        friendlyMessage = 'Device not authorized. Please allow USB debugging on your device.';
      } else if (e.message) {
        friendlyMessage = e.message;
      }

      showToast(friendlyMessage, 'error');
      appendConsole(friendlyMessage, 'error');
    } finally {
      if (btn && originalHTML) { btn.innerHTML = originalHTML; btn.disabled = selectedScriptIds.size === 0; }
    }
  }


  async function deleteScript(scriptId) {
    showDeleteModal(scriptId);
  }

  
  async function loadScriptLibrary(category = 'All') {
    const scriptList = document.getElementById('scriptLibraryList');

    // Show loading state
    if (scriptList) {
      scriptList.innerHTML = `
        <div class="flex items-center justify-center py-12">
          <div class="text-center">
            <svg class="w-8 h-8 animate-spin mx-auto mb-3 text-primary-500" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <circle cx="12" cy="12" r="10" stroke-width="2" class="opacity-25"></circle>
              <path d="M4 12a8 8 0 018-8" stroke-width="2" stroke-linecap="round" class="opacity-75"></path>
            </svg>
            <p class="text-slate-400">Loading script library...</p>
          </div>
        </div>
      `;
    }

    try {
      console.log(`[Library] Loading all scripts...`);

      const response = await fetch('/api/scripts');
      if (!response.ok) throw new Error('Failed to fetch scripts');

      const scripts = await response.json();
      scriptLibrary = scripts;
      
      currentFilters.category = category;
      applyFilters();

      console.log(`[Library] Loaded ${scripts.length} scripts, filtered for category "${category}"`);
    } catch (e) {
      console.error('Failed to load script library:', e);
      if (typeof showToast === 'function') showToast('Failed to load script library', 'error');
    }
  }

  async function forceRefreshScriptLibrary() {
    try {
      console.log('[Library] Force refreshing script library...');
      
      const response = await fetch('/api/scripts');
      if (!response.ok) throw new Error('Failed to fetch scripts');

      const scripts = await response.json();
      scriptLibrary = scripts;
      
      const categoryFilter = document.getElementById('categoryFilter');
      if (categoryFilter) {
        currentFilters.category = categoryFilter.value || 'All';
      }
      
      applyFilters();

      console.log(`[Library] Force refresh complete - loaded ${scripts.length} scripts`);
      return scripts;
    } catch (e) {
      console.error('Failed to force refresh script library:', e);
      if (typeof showToast === 'function') showToast('Failed to refresh script library', 'error');
      return [];
    }
  }

  async function loadScriptFromLibrary(scriptId) {
    try {
      const response = await fetch(`/api/scripts/${scriptId}`);
      if (!response.ok) throw new Error('Script not found');

      const script = await response.json();
      await waitForMonacoEditor();

      const editorInstance = window.__monacoEditorInstance;

      if (editorInstance && typeof editorInstance.setValue === 'function' && script.code) {
        try {
          editorInstance.setValue(script.code);
          if (typeof showToast === 'function') showToast(`Loaded: ${script.name}`, 'success');
          if (typeof appendConsole === 'function') appendConsole(`Loaded script: ${script.name}`, 'info');
        } catch (err) {
          console.error('Monaco setValue failed:', err);
          if (typeof showToast === 'function') showToast('Editor error: failed to set script', 'error');

          const fallback = document.getElementById('editor');
          if (fallback) fallback.innerText = script.code;
        }
      } else {
        console.warn('Editor not ready or script empty');
        if (typeof showToast === 'function') showToast('Editor not ready or script empty', 'error');
      }
    } catch (e) {
      console.error('Failed to load script:', e);
      if (typeof showToast === 'function') showToast('Failed to load script', 'error');
    }
  }

  async function waitForMonacoEditor(retries = 40, delay = 150) {
    while (
      !(window.__monacoEditorInstance && typeof window.__monacoEditorInstance.setValue === 'function') &&
      retries-- > 0
    ) {
      await new Promise(r => setTimeout(r, delay));
    }
    if (!(window.__monacoEditorInstance && typeof window.__monacoEditorInstance.setValue === 'function')) {
      throw new Error('Monaco editor not ready');
    }
  }

  function refreshScriptLibrary() {
    const category = document.getElementById('categoryFilter')?.value || 'All';
    console.log(`[Library] Manual refresh requested for category: "${category}"`);
    loadScriptLibrary(category);
  }

  async function importExistingScripts() {
    try {
      const response = await fetch('/api/scripts/import-folder', {
        method: 'POST'
      });

      if (!response.ok) throw new Error('Import request failed');
      const result = await response.json();

      if (result.status === 'ok') {
        if (typeof showToast === 'function') showToast(`${result.message}. Errors: ${result.errors.length}`, 'success');
        await forceRefreshScriptLibrary();

        if (result.errors.length > 0) {
          console.warn('Import errors:', result.errors);
        }
      } else {
        if (typeof showToast === 'function') showToast('Import failed: ' + (result.message || 'Unknown error'), 'error');
      }
    } catch (e) {
      console.error('Import failed:', e);
      if (typeof showToast === 'function') showToast('Import failed: ' + e.message, 'error');
    }
  }




  async function handleScriptUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.js')) {
      if (typeof showToast === 'function') showToast('Only .js files are allowed', 'error');
      event.target.value = '';
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('category', 'Custom');
    formData.append('description', `Uploaded script: ${file.name}`);
    formData.append('platform', 'all');
    formData.append('difficulty', 'beginner');

    try {
      const response = await fetch('/api/scripts/upload', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();

      if (result.status === 'ok') {
        if (typeof showToast === 'function') showToast(result.message, 'success');
        await forceRefreshScriptLibrary();
      } else {
        if (typeof showToast === 'function') showToast('Upload failed: ' + result.error, 'error');
      }
    } catch (e) {
      console.error('Upload failed:', e);
      if (typeof showToast === 'function') showToast('Upload failed: ' + e.message, 'error');
    }

    event.target.value = '';
  }

  // Initialize on page load
  document.addEventListener('DOMContentLoaded', () => {
    const scriptUpload = document.getElementById('scriptUpload');
    if (scriptUpload) {
      scriptUpload.addEventListener('change', handleScriptUpload);
    }

    const confirmBtn = document.getElementById('confirmDeleteBtn');
    if (confirmBtn) {
      confirmBtn.addEventListener('click', confirmDeleteScript);
    }
    
    setTimeout(() => {
      console.log('[Library] Initial load starting...');
      forceRefreshScriptLibrary();
    }, 1000);
  });

  // Export functions for global access
  window.loadScriptFromLibrary = loadScriptFromLibrary;
  window.refreshScriptLibrary = refreshScriptLibrary;
  window.forceRefreshScriptLibrary = forceRefreshScriptLibrary;
  window.importExistingScripts = importExistingScripts;
  window.injectSelectedScripts = injectSelectedScripts;
  window.updateSelectedCount = updateSelectedCount;
  window.deleteScript = deleteScript;
  window.showDeleteModal = showDeleteModal;
  window.hideDeleteModal = hideDeleteModal;
  window.confirmDeleteScript = confirmDeleteScript;
  window.handleScriptCheckbox = handleScriptCheckbox;
  window.addTag = addTag;
  window.removeTag = removeTag;
  window.clearAllFilters = clearAllFilters;
  window.applyFilters = applyFilters;
}