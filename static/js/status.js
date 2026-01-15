window.lastFridaRunning = window.lastFridaRunning || null;

/**
 * Show toast alert with type-based coloring
 */


/**
 * Check Frida + ADB status, update UI
 */
// Global flag to track if we already loaded processes
let processesLoadedOnce = false;

async function checkStatus() {
  const statusLabel = document.querySelector('#fridaStatus');

  try {
    const adbRes = await fetch('/api/adb/devices');
    const adbData = await adbRes.json();
    const devices = adbData.devices || [];

    window.deviceConnected = devices.length > 0;

    const deviceCountEl = document.getElementById('deviceCount');
    if (deviceCountEl) {
      deviceCountEl.textContent = devices.length;
    }

    // 🛑 No device connected
    if (!window.deviceConnected) {
      if (statusLabel) {
        statusLabel.textContent = '📴 No device';
        statusLabel.classList.remove('text-green-400', 'text-amber-400');
        statusLabel.classList.add('text-red-400');
      }

      updateConnectionIndicator({
        hasDevice: false,
        fridaRunning: false,
      });

      processesLoadedOnce = false; // Reset
      return;
    }

    // ✅ If device connected and processes not loaded yet
    if (!processesLoadedOnce) {
      if (typeof loadProcesses === 'function') {
        await loadProcesses();
        processesLoadedOnce = true;
      } else {
        console.warn('[status.js] Skipping loadProcesses — function not available on this page');
      }
    }


    // Continue checking Frida
    const fridaRes = await fetch('/api/frida/status');
    const fridaData = await fridaRes.json();
    const fridaRunning = fridaData.running;

    if (statusLabel) {
      statusLabel.classList.remove('text-green-400', 'text-red-400', 'text-amber-400');
      if (fridaRunning) {
        statusLabel.textContent = `🟢 Running (${fridaData.process})`;
        statusLabel.classList.add('text-green-400');
      } else {
        statusLabel.textContent = '🔴 Not Running';
        statusLabel.classList.add('text-red-400');
      }
    }

    updateConnectionIndicator({
      hasDevice: true,
      fridaRunning: fridaRunning,
    });

    if (window.lastFridaRunning !== null && window.lastFridaRunning !== fridaRunning) {
      const msg = fridaRunning
        ? 'Frida server is running and responsive 🎉'
        : 'Frida server is not running or failed to respond';
      showToast(msg, fridaRunning ? 'success' : 'error');
    }

    window.lastFridaRunning = fridaRunning;

  } catch (err) {
    console.error('❌ Failed to check status:', err);

    // Update status label to show error state instead of staying on "Checking..."
    if (statusLabel) {
      statusLabel.textContent = '⚠️ Check failed';
      statusLabel.classList.remove('text-green-400', 'text-amber-400');
      statusLabel.classList.add('text-red-400');
    }

    // Only show toast if it's not a repeated failure
    if (window.lastFridaRunning !== 'error') {
      showToast('Error fetching device or Frida status', 'error');
      window.lastFridaRunning = 'error';
    }
  }
}



/**
 * Update the navbar connection badge
 */
function updateConnectionIndicator({ hasDevice, fridaRunning }) {
  const dot = document.getElementById('connectionDot');
  const text = document.getElementById('connectionText');
  const container = document.getElementById('connectionIndicator');

  if (!dot || !text || !container) return;

  dot.className = 'w-2 h-2 rounded-full';
  container.className = 'flex items-center space-x-2 px-3 py-1 rounded-full border transition-all duration-300';
  text.className = 'text-xs font-medium';

  if (hasDevice && fridaRunning) {
    dot.classList.add('bg-emerald-400');
    container.classList.add('bg-emerald-500/10', 'border-emerald-500/20');
    text.classList.add('text-emerald-400');
    text.textContent = 'Connected';
  } else if (hasDevice) {
    dot.classList.add('bg-yellow-400');
    container.classList.add('bg-yellow-500/10', 'border-yellow-500/20');
    text.classList.add('text-yellow-400');
    text.textContent = 'Device Only';
  } else {
    dot.classList.add('bg-red-400');
    container.classList.add('bg-red-500/10', 'border-red-500/20');
    text.classList.add('text-red-400');
    text.textContent = 'Disconnected';
  }
}
