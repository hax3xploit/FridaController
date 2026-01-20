// ADB Console JavaScript
let commandHistory = [];
let historyIndex = -1;
let currentDevice = null;

// Shell state
let shellHistory = [];
let shellHistoryIndex = -1;
let shellSessionId = null;
let shellConnected = false;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDevices();
    setupEventListeners();
    focusInput();
});

function setupEventListeners() {
    const input = document.getElementById('commandInput');
    const shellInput = document.getElementById('shellInput');

    // Command tab - Enter key to execute
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            executeCommand();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            navigateHistory('up', 'cmd');
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            navigateHistory('down', 'cmd');
        }
    });

    // Shell tab - Enter key to execute
    shellInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            executeShellCommand();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            navigateHistory('up', 'shell');
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            navigateHistory('down', 'shell');
        }
    });

    // Device selection for commands tab
    document.getElementById('deviceSelect').addEventListener('change', function(e) {
        currentDevice = e.target.value || null;
        addOutput(`Switched to device: ${currentDevice || 'default'}`, 'info', 'cmd');
    });

    // Device selection for shell tab
    document.getElementById('shellDeviceSelect').addEventListener('change', function(e) {
        if (shellConnected) {
            addOutput('Disconnect current session before changing device', 'error', 'shell');
            // Reset to current device
            e.target.value = currentDevice || '';
        } else {
            currentDevice = e.target.value || null;
        }
    });
}

function loadDevices() {
    fetch('/api/adb/devices')
        .then(res => res.json())
        .then(data => {
            const select = document.getElementById('deviceSelect');
            const shellSelect = document.getElementById('shellDeviceSelect');

            select.innerHTML = '<option value="">Default Device</option>';
            shellSelect.innerHTML = '<option value="">Default Device</option>';

            if (data.devices && data.devices.length > 0) {
                data.devices.forEach(device => {
                    const option = document.createElement('option');
                    option.value = device.id;
                    option.textContent = device.name;
                    if (device.id === data.selected) {
                        option.selected = true;
                        currentDevice = device.id;
                    }
                    select.appendChild(option.cloneNode(true));
                    shellSelect.appendChild(option);
                });
            }
        })
        .catch(err => {
            console.error('Failed to load devices:', err);
        });
}

// Tab switching
function switchTab(tab) {
    if (tab === 'commands') {
        document.getElementById('cmdTab').classList.add('active');
        document.getElementById('shellTab').classList.remove('active');
        document.getElementById('commandsPanel').classList.remove('hidden');
        document.getElementById('shellPanel').classList.add('hidden');
        focusInput();
    } else if (tab === 'shell') {
        document.getElementById('cmdTab').classList.remove('active');
        document.getElementById('shellTab').classList.add('active');
        document.getElementById('commandsPanel').classList.add('hidden');
        document.getElementById('shellPanel').classList.remove('hidden');
        if (shellConnected) {
            document.getElementById('shellInput').focus();
        }
    }
}

// Commands tab functions
function executeCommand() {
    const input = document.getElementById('commandInput');
    const command = input.value.trim();

    if (!command) return;

    // Add to history
    commandHistory.push(command);
    historyIndex = commandHistory.length;

    // Show command in terminal
    addOutput(`$ adb ${command}`, 'command', 'cmd');

    // Clear input
    input.value = '';

    // Execute command
    fetch('/api/adb/execute', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            command: command,
            device_id: currentDevice
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.ok) {
            const output = data.output || '(no output)';
            addOutput(output, data.returncode === 0 ? 'output' : 'error', 'cmd');
        } else {
            addOutput(`Error: ${data.error}`, 'error', 'cmd');
        }
    })
    .catch(err => {
        addOutput(`Network error: ${err.message}`, 'error', 'cmd');
    })
    .finally(() => {
        focusInput();
    });
}

function quickCommand(cmd) {
    const input = document.getElementById('commandInput');
    input.value = cmd;
    executeCommand();
}

// Shell tab functions
function connectShell() {
    addOutput('Connecting to ADB shell...', 'info', 'shell');

    fetch('/api/adb/shell/connect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            device_id: currentDevice
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.ok) {
            shellSessionId = data.session_id;
            shellConnected = true;

            // Update UI
            document.getElementById('shellStatusText').textContent = 'Connected';
            document.getElementById('shellStatusText').className = 'text-green-400';
            document.getElementById('connectShellBtn').classList.add('hidden');
            document.getElementById('disconnectShellBtn').classList.remove('hidden');
            document.getElementById('shellInput').disabled = false;
            document.getElementById('shellInput').placeholder = 'Type shell command...';

            addOutput('Shell connected! You can now run commands.', 'success', 'shell');
            document.getElementById('shellInput').focus();
        } else {
            addOutput(`Failed to connect: ${data.error}`, 'error', 'shell');
        }
    })
    .catch(err => {
        addOutput(`Connection error: ${err.message}`, 'error', 'shell');
    });
}

function disconnectShell() {
    if (!shellSessionId) return;

    fetch('/api/adb/shell/disconnect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            session_id: shellSessionId
        })
    })
    .then(res => res.json())
    .then(data => {
        shellSessionId = null;
        shellConnected = false;

        // Update UI
        document.getElementById('shellStatusText').textContent = 'Disconnected';
        document.getElementById('shellStatusText').className = 'text-red-400';
        document.getElementById('connectShellBtn').classList.remove('hidden');
        document.getElementById('disconnectShellBtn').classList.add('hidden');
        document.getElementById('shellInput').disabled = true;
        document.getElementById('shellInput').placeholder = 'Connect to shell first...';

        addOutput('Shell disconnected.', 'info', 'shell');
    })
    .catch(err => {
        console.error('Disconnect error:', err);
    });
}

function executeShellCommand() {
    const input = document.getElementById('shellInput');
    const command = input.value.trim();

    if (!command || !shellConnected) return;

    // Add to history
    shellHistory.push(command);
    shellHistoryIndex = shellHistory.length;

    // Show command in terminal
    const prompt = document.getElementById('shellPrompt').textContent;
    addOutput(`${prompt} ${command}`, 'command', 'shell');

    // Clear input
    input.value = '';

    // Execute in shell
    fetch('/api/adb/shell/execute', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            session_id: shellSessionId,
            command: command
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.ok) {
            const output = data.output || '';
            if (output) {
                addOutput(output, 'output', 'shell');
            }
            // Update prompt if provided
            if (data.prompt) {
                document.getElementById('shellPrompt').textContent = data.prompt;
            }
        } else {
            addOutput(`Error: ${data.error}`, 'error', 'shell');
            if (data.error.includes('session')) {
                // Session expired, reset connection
                shellSessionId = null;
                shellConnected = false;
                document.getElementById('shellStatusText').textContent = 'Disconnected';
                document.getElementById('shellStatusText').className = 'text-red-400';
                document.getElementById('connectShellBtn').classList.remove('hidden');
                document.getElementById('disconnectShellBtn').classList.add('hidden');
                document.getElementById('shellInput').disabled = true;
            }
        }
    })
    .catch(err => {
        addOutput(`Network error: ${err.message}`, 'error', 'shell');
    });
}

function addOutput(text, type = 'output', terminal = 'cmd') {
    const outputId = terminal === 'shell' ? 'shellOutput' : 'terminalOutput';
    const terminalEl = document.getElementById(outputId);
    const line = document.createElement('div');
    line.className = 'terminal-line';

    // Apply styling based on type
    switch(type) {
        case 'command':
            line.className += ' text-white font-semibold';
            break;
        case 'error':
            line.className += ' text-red-400';
            break;
        case 'info':
            line.className += ' text-blue-400';
            break;
        case 'success':
            line.className += ' text-green-400';
            break;
        default:
            line.className += ' text-slate-300';
    }

    // Preserve formatting and handle long output
    line.style.whiteSpace = 'pre-wrap';
    line.style.wordBreak = 'break-word';
    line.textContent = text;

    terminalEl.appendChild(line);

    // Auto scroll to bottom
    terminalEl.scrollTop = terminalEl.scrollHeight;
}

function clearTerminal(type) {
    if (type === 'shell') {
        const terminal = document.getElementById('shellOutput');
        terminal.innerHTML = `
            <div class="text-green-400">Terminal cleared</div>
            <div class="mt-2"></div>
        `;
        if (shellConnected) {
            document.getElementById('shellInput').focus();
        }
    } else {
        const terminal = document.getElementById('terminalOutput');
        terminal.innerHTML = `
            <div class="text-green-400">Terminal cleared</div>
            <div class="mt-2"></div>
        `;
        focusInput();
    }
}

function navigateHistory(direction, type = 'cmd') {
    const history = type === 'shell' ? shellHistory : commandHistory;
    let histIdx = type === 'shell' ? shellHistoryIndex : historyIndex;
    const inputId = type === 'shell' ? 'shellInput' : 'commandInput';
    const input = document.getElementById(inputId);

    if (direction === 'up') {
        if (histIdx > 0) {
            histIdx--;
            input.value = history[histIdx];
        }
    } else if (direction === 'down') {
        if (histIdx < history.length - 1) {
            histIdx++;
            input.value = history[histIdx];
        } else {
            histIdx = history.length;
            input.value = '';
        }
    }

    // Update index
    if (type === 'shell') {
        shellHistoryIndex = histIdx;
    } else {
        historyIndex = histIdx;
    }
}

function focusInput() {
    const input = document.getElementById('commandInput');
    input.focus();
}
