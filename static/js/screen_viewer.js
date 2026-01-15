// Screen Viewer JavaScript
let streamInterval = null;
let isStreaming = false;
let fps = 10;
let lastFrameTime = 0;
let frameCount = 0;
let fpsUpdateInterval = null;
let lastCaptureTime = 0;
let actualInterval = 0;

const canvas = document.getElementById('screenCanvas');
const ctx = canvas ? canvas.getContext('2d') : null;
const loadingOverlay = document.getElementById('loadingOverlay');

// Touch/Click handling
let touchStartX = 0;
let touchStartY = 0;
let touchStartTime = 0;

// Async version for streaming (returns promise)
function refreshScreenAsync() {
  if (!canvas || !ctx) return Promise.reject('No canvas');

  const captureStart = Date.now();
  const quality = 'fast';

  return fetch(`/api/screen/capture?quality=${quality}`)
    .then(response => {
      if (!response.ok) throw new Error('Failed to capture screen');
      return response.blob();
    })
    .then(blob => {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = function() {
          // Set canvas to actual device resolution
          canvas.width = img.width;
          canvas.height = img.height;

          // Draw image
          ctx.drawImage(img, 0, 0);

          // Auto-fit canvas to container width while maintaining aspect ratio
          const container = document.getElementById('screenContainer');
          if (container) {
            const containerWidth = container.clientWidth;
            const aspectRatio = img.height / img.width;
            const maxHeight = 700;

            let displayWidth = Math.min(containerWidth - 40, img.width);
            let displayHeight = displayWidth * aspectRatio;

            if (displayHeight > maxHeight) {
              displayHeight = maxHeight;
              displayWidth = displayHeight / aspectRatio;
            }

            canvas.style.width = displayWidth + 'px';
            canvas.style.height = displayHeight + 'px';
          }

          // Update frame counter
          frameCount++;
          const now = Date.now();
          if (now - lastFrameTime >= 1000) {
            updateFPS(frameCount);
            frameCount = 0;
            lastFrameTime = now;
          }

          // Clean up blob URL
          URL.revokeObjectURL(img.src);
          resolve();
        };
        img.onerror = function() {
          reject(new Error('Failed to load image'));
        };
        img.src = URL.createObjectURL(blob);
      });
    });
}

// Sync version for manual refresh
function refreshScreen() {
  if (!canvas || !ctx) return;

  showLoading(true);

  const quality = isStreaming ? 'fast' : 'high';

  fetch(`/api/screen/capture?quality=${quality}`)
    .then(response => {
      if (!response.ok) throw new Error('Failed to capture screen');
      return response.blob();
    })
    .then(blob => {
      const img = new Image();
      img.onload = function() {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);

        const container = document.getElementById('screenContainer');
        if (container) {
          const containerWidth = container.clientWidth;
          const aspectRatio = img.height / img.width;
          const maxHeight = 700;

          let displayWidth = Math.min(containerWidth - 40, img.width);
          let displayHeight = displayWidth * aspectRatio;

          if (displayHeight > maxHeight) {
            displayHeight = maxHeight;
            displayWidth = displayHeight / aspectRatio;
          }

          canvas.style.width = displayWidth + 'px';
          canvas.style.height = displayHeight + 'px';
        }

        showLoading(false);
        URL.revokeObjectURL(img.src);
      };
      img.onerror = function() {
        showLoading(false);
        showToast('Failed to load screen image', 'error');
      };
      img.src = URL.createObjectURL(blob);
    })
    .catch(err => {
      console.error('Screen capture error:', err);
      showToast('Failed to capture screen. Is device connected?', 'error');
      showLoading(false);
    });
}

function toggleStream() {
  if (isStreaming) {
    stopStream();
  } else {
    startStream();
  }
}

function startStream() {
  const fpsSelect = document.getElementById('fpsSelect');
  fps = parseInt(fpsSelect.value) || 10;
  const targetInterval = 1000 / fps;

  isStreaming = true;

  // Update button
  const btn = document.getElementById('toggleStreamBtn');
  btn.textContent = '⏸️ Stop Stream';
  btn.classList.remove('bg-emerald-600', 'hover:bg-emerald-700');
  btn.classList.add('bg-red-600', 'hover:bg-red-700');

  // Update status indicator
  updateStreamStatus(true);

  // Start FPS counter
  lastFrameTime = Date.now();
  frameCount = 0;

  // Use adaptive streaming - call refreshScreen in a loop
  // This prevents frames from piling up if capture is slow
  function streamLoop() {
    if (!isStreaming) return;

    const loopStart = Date.now();

    // Capture one frame
    refreshScreenAsync().then(() => {
      if (!isStreaming) return;

      // Calculate how long to wait before next frame
      const elapsed = Date.now() - loopStart;
      const wait = Math.max(0, targetInterval - elapsed);

      // Schedule next frame
      streamInterval = setTimeout(streamLoop, wait);
    }).catch(err => {
      console.error('Stream error:', err);
      if (isStreaming) {
        stopStream();
      }
    });
  }

  // Start the loop
  streamLoop();

  showToast(`Screen streaming started (target: ${fps} FPS)`, 'success');
}

function stopStream() {
  isStreaming = false;

  if (streamInterval) {
    clearTimeout(streamInterval);
    streamInterval = null;
  }

  // Update button
  const btn = document.getElementById('toggleStreamBtn');
  btn.textContent = '▶️ Start Stream';
  btn.classList.remove('bg-red-600', 'hover:bg-red-700');
  btn.classList.add('bg-emerald-600', 'hover:bg-emerald-700');

  // Update status indicator
  updateStreamStatus(false);

  updateFPS(0);

  showToast('Screen streaming stopped', 'info');
}

function updateStreamStatus(active) {
  const status = document.getElementById('streamStatus');
  if (!status) return;

  const dot = status.querySelector('div');
  const text = status.querySelector('span');

  if (active) {
    dot.classList.remove('bg-slate-400');
    dot.classList.add('bg-emerald-400', 'animate-pulse');
    text.textContent = 'Streaming';
    text.classList.remove('text-slate-400');
    text.classList.add('text-emerald-400');
  } else {
    dot.classList.remove('bg-emerald-400', 'animate-pulse');
    dot.classList.add('bg-slate-400');
    text.textContent = 'Stopped';
    text.classList.remove('text-emerald-400');
    text.classList.add('text-slate-400');
  }
}

function updateFPS(count) {
  const fpsCounter = document.getElementById('fpsCounter');
  if (fpsCounter) {
    fpsCounter.textContent = count;
  }
}

function showLoading(show) {
  if (loadingOverlay) {
    loadingOverlay.style.display = show ? 'flex' : 'none';
  }
}

function updateScale() {
  const scaleSelect = document.getElementById('scaleSelect');
  const scale = parseFloat(scaleSelect.value);

  if (canvas) {
    // Apply scale on top of existing auto-fit dimensions
    canvas.style.transform = `scale(${scale})`;
    canvas.style.transformOrigin = 'top center';
  }
}

// Touch/Click handling
if (canvas) {
  canvas.addEventListener('mousedown', (e) => {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;

    touchStartX = (e.clientX - rect.left) * scaleX;
    touchStartY = (e.clientY - rect.top) * scaleY;
    touchStartTime = Date.now();
  });

  canvas.addEventListener('mouseup', (e) => {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;

    const touchEndX = (e.clientX - rect.left) * scaleX;
    const touchEndY = (e.clientY - rect.top) * scaleY;
    const touchEndTime = Date.now();

    const duration = touchEndTime - touchStartTime;
    const distance = Math.sqrt(
      Math.pow(touchEndX - touchStartX, 2) + Math.pow(touchEndY - touchStartY, 2)
    );

    // If duration < 200ms and distance < 10px, it's a tap
    if (duration < 200 && distance < 10) {
      sendTap(Math.round(touchStartX), Math.round(touchStartY));
    }
    // Otherwise it's a swipe
    else if (distance > 10) {
      sendSwipe(
        Math.round(touchStartX),
        Math.round(touchStartY),
        Math.round(touchEndX),
        Math.round(touchEndY),
        duration
      );
    }
  });
}

function sendTap(x, y) {
  fetch('/api/screen/input', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'tap', x, y })
  })
  .then(response => response.json())
  .then(data => {
    if (data.ok) {
      console.log(`Tap sent: (${x}, ${y})`);
    }
  })
  .catch(err => console.error('Tap error:', err));
}

function sendSwipe(x1, y1, x2, y2, duration) {
  fetch('/api/screen/input', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'swipe', x1, y1, x2, y2, duration })
  })
  .then(response => response.json())
  .then(data => {
    if (data.ok) {
      console.log(`Swipe sent: (${x1}, ${y1}) → (${x2}, ${y2})`);
    }
  })
  .catch(err => console.error('Swipe error:', err));
}

function sendKey(keycode) {
  fetch('/api/screen/input', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'key', keycode })
  })
  .then(response => response.json())
  .then(data => {
    if (data.ok) {
      console.log(`Key sent: ${keycode}`);
    }
  })
  .catch(err => console.error('Key error:', err));
}

function takeScreenshot() {
  if (!canvas) return;

  // Capture high-quality screenshot directly from server
  showToast('Capturing screenshot...', 'info');

  fetch('/api/screen/capture?quality=high')
    .then(response => response.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      link.download = `android-screen-${timestamp}.png`;
      link.href = url;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      showToast('Screenshot saved', 'success');
    })
    .catch(err => {
      console.error('Screenshot error:', err);
      showToast('Failed to capture screenshot', 'error');
    });
}

function toggleFullscreen() {
  const container = document.getElementById('screenContainer');
  if (!container) return;

  if (!document.fullscreenElement) {
    container.requestFullscreen().catch(err => {
      showToast('Fullscreen not supported', 'error');
    });
  } else {
    document.exitFullscreen();
  }
}

let rotated = false;
function rotateScreen() {
  rotated = !rotated;
  if (canvas) {
    const scaleSelect = document.getElementById('scaleSelect');
    const scale = parseFloat(scaleSelect.value);

    if (rotated) {
      canvas.style.transform = `rotate(90deg) scale(${scale})`;
    } else {
      canvas.style.transform = `scale(${scale})`;
    }
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  // Show initial loading state
  showLoading(true);

  // Load first frame
  refreshScreen();

  // Hide loading after first frame
  setTimeout(() => showLoading(false), 2000);
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  if (isStreaming) {
    stopStream();
  }
});
