// Initialize global variables if they don't exist
window.deviceConnected = window.deviceConnected || false;
window.processesLoadedOnce = window.processesLoadedOnce || false;
window.lastFridaRunning = window.lastFridaRunning || null;

/**
 * Update the navbar connection badge
 */
function updateConnectionIndicator({ hasDevice, fridaRunning }) {
  const dot = document.getElementById('connectionDot');
  const text = document.getElementById('connectionText');
  const container = document.getElementById('connectionIndicator');

  if (!dot || !text || !container) {
    console.log('Connection indicator elements not found');
    return;
  }

  // Reset classes
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

/**
 * Check Frida + ADB status, update UI
 */
async function checkStatus() {
  console.log('checkStatus() called');
  
  try {
    // Check ADB devices
    const adbRes = await fetch('/api/adb/devices');
    if (!adbRes.ok) throw new Error(`ADB API error: ${adbRes.status}`);
    
    const adbData = await adbRes.json();
    const devices = adbData.devices || [];
    window.deviceConnected = devices.length > 0;

    // Update device count if element exists
    const deviceCountEl = document.getElementById('deviceCount');
    if (deviceCountEl) {
      deviceCountEl.textContent = devices.length;
    }

    // Check Frida status
    const fridaRes = await fetch('/api/frida/status');
    if (!fridaRes.ok) throw new Error(`Frida API error: ${fridaRes.status}`);
    
    const fridaData = await fridaRes.json();
    const fridaRunning = fridaData.running;

    // Update Frida status if element exists
    const statusLabel = document.querySelector('#fridaStatus');
    if (statusLabel) {
      statusLabel.classList.remove('text-green-400', 'text-red-400');
      if (fridaRunning) {
        statusLabel.textContent = `🟢 Running (${fridaData.process})`;
        statusLabel.classList.add('text-green-400');
      } else {
        statusLabel.textContent = '🔴 Not Running';
        statusLabel.classList.add('text-red-400');
      }
    }

    // Update connection indicator
    updateConnectionIndicator({
      hasDevice: window.deviceConnected,
      fridaRunning: fridaRunning,
    });

    // Load processes if device is connected and not loaded yet
    if (window.deviceConnected && !window.processesLoadedOnce && typeof loadProcesses === 'function') {
      await loadProcesses();
      window.processesLoadedOnce = true;
    }

    // Show toast on status change
    if (window.lastFridaRunning !== null && window.lastFridaRunning !== fridaRunning) {
      const msg = fridaRunning
        ? 'Frida server is running and responsive 🎉'
        : 'Frida server is not running or failed to respond';
      showToast(msg, fridaRunning ? 'success' : 'error');
    }

    window.lastFridaRunning = fridaRunning;
    console.log('Status check completed successfully');

  } catch (err) {
    console.error('❌ Failed to check status:', err);
    
    // Update connection indicator to show error state
    updateConnectionIndicator({
      hasDevice: false,
      fridaRunning: false,
    });
    
    // Only show toast for network errors, not for expected API errors
    if (err.message.includes('Failed to fetch')) {
      showToast('❌ Network error checking status', 'error');
    }
  }
}

// Make checkStatus available globally
window.checkStatus = checkStatus;

// Start checking status when the page loads
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, starting status checking');
  
  // Initial status check with a small delay to ensure DOM is fully ready
  setTimeout(() => {
    checkStatus();
  }, 100);
  
  // Continue checking every 5 seconds
  setInterval(checkStatus, 5000);
});