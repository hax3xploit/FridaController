import eventlet
eventlet.monkey_patch()
from time import monotonic
import os
import subprocess
import socket
import shlex
import uuid
from script_library import script_library_bp
from database import init_script_db, seed_script_library, ScriptDatabase
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from frida_ops import inject_script, clear_saved_target, spawn_and_inject, spawn_and_inject_multiple, set_saved_target, get_saved_target, spawn_and_inject, add_console_message, get_console_messages_for_session, get_current_session_info, set_socketio_instance, attach_to_process, session_cache, detach as frida_detach, get_selected_device

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fridagui'
socketio = SocketIO(app, cors_allowed_origins="*")
set_socketio_instance(socketio)
# Register the blueprint (add after your existing routes)
app.register_blueprint(script_library_bp)

# Constants
FRIDA_NS = "/frida"

_LAST_STATE = {
    "frida_running": None,
    "device_count": None,
    "process_count": None,
}

_LAST_LOG_TS = {}  # key -> timestamp



def emit_console_dedup(msg, type="log", room=None, only_namespace=None, key=None, cooldown=5.0):
    """
    Emit at most once per `cooldown` seconds for the same key.
    Stores to polling buffer (scripts.html) as well.
    """
    k = key or f"{only_namespace}|{room}|{type}|{msg}"
    now = monotonic()
    last = _LAST_LOG_TS.get(k, 0.0)
    if now - last < cooldown:
        return False

    _LAST_LOG_TS[k] = now
    emit_console(msg, type=type, room=room, only_namespace=only_namespace)
    return True


def _is_silent():
    # Treat ALL GETs as silent unless verbose=1
    return (request.method == "GET") and (request.args.get("verbose") not in ("1", "true", "yes"))



def emit_dashboard_log(msg, type="log"):
    """
    Send log only to default namespace (dashboard.html).
    Adds 🧭 [Dashboard] prefix.
    """
    formatted_msg = f"🧭 [Dashboard] {msg}"
    evt = {"type": type, "payload": formatted_msg, "message": formatted_msg}
    
    try:
        socketio.emit("console_output", evt)
    except Exception as e:
        print(f"[emit_dashboard_log] Emit failed: {e}")



def emit_frida_log(msg, type="log", session_id=None):
    """
    Sends logs to the script page (/scripts.html):
    - Appends message to polling buffer (Live Console)
    - Optionally emits via Socket.IO (for legacy/future use)
    """
    # Add emoji + origin tag
    formatted_msg = f"📦 [FRIDA] {msg}"

    # Build event payload
    evt = {
        "type": type,
        "payload": formatted_msg,
        "message": formatted_msg
    }

    # Get session_id from cache if not explicitly passed
    sid = session_id or session_cache.get("session_id")

    # ✅ Store in console buffer for polling UI
    if sid:
        add_console_message(sid, formatted_msg, type)
        print(f"[emit_frida_log] Saved message to buffer for session {sid}")
    else:
        print("[emit_frida_log] No session_id found, skipping buffer save")

    # WebSocket emission - broadcast to ALL clients in namespace
    # NOTE: broadcast=True only works inside request context, so we just omit room parameter
    try:
        socketio.emit("frida_output", evt, namespace=FRIDA_NS)
        print(f"[emit_frida_log] Emitted frida_output to all clients: {msg[:50]}...")
    except Exception as e:
        print(f"[emit_frida_log] WebSocket emit failed: {e}")



def emit_console(msg, type="log", room=None, only_namespace=None):
    """
    Flexible console output with precise targeting.
    Automatically stores messages in polling buffer if in /frida namespace.
    Adds 🌀 [Core] prefix unless already tagged.
    """
    # Tag message if no prefix already
    if not any(msg.startswith(p) for p in ("📦", "🧭", "🌀")):
        formatted_msg = f"🌀 [Core] {msg}"
    else:
        formatted_msg = msg

    evt = {"type": type, "payload": formatted_msg, "message": formatted_msg}

    # 🔁 Save to scripts polling buffer
    sid = session_cache.get("session_id")
    if only_namespace in ("/frida", None) and sid:
        try:
            add_console_message(sid, formatted_msg, type)
            print(f"[emit_console] Saved to session buffer: {sid}")
        except Exception as e:
            print(f"[emit_console] Buffer write failed: {e}")

    # 🔁 Emit via WebSocket
    try:
        if only_namespace == FRIDA_NS:
            if room:
                socketio.emit("console_output", evt, namespace=FRIDA_NS, room=room)
            else:
                socketio.emit("console_output", evt, namespace=FRIDA_NS)
        elif only_namespace == "/":
            if room:
                socketio.emit("console_output", evt, room=room)
            else:
                socketio.emit("console_output", evt)
        else:
            # Emit to both by default
            if room:
                socketio.emit("console_output", evt, room=room)
                socketio.emit("console_output", evt, namespace=FRIDA_NS, room=room)
            else:
                socketio.emit("console_output", evt)
                socketio.emit("console_output", evt, namespace=FRIDA_NS)
    except Exception as e:
        print(f"[emit_console] WebSocket emit failed: {e}")


def get_frida_server_path():
    try:
        with open('settings/server_path.txt', 'r') as f:
            return f.read().strip()
    except Exception:
        return '/data/local/tmp/frida-server'

        
@app.route('/')
def index():
    emit_dashboard_log("Dashboard loaded", type="info")
    return render_template('dashboard.html')


@app.route('/screen')
def screen_viewer():
    """Android screen viewer page"""
    return render_template('screen_viewer.html')


@app.route('/adb-console')
def adb_console():
    """ADB console page"""
    return render_template('adb_console.html')


@app.route('/api/screen/capture')
def screen_capture():
    """Capture a single screenshot from Android device"""
    try:
        from frida_ops import session_cache
        device_id = session_cache.get("selected_device_id")

        # Get quality parameter (default to fast mode for streaming)
        quality = request.args.get('quality', 'fast')

        # Build ADB command
        cmd = ['adb']
        if device_id:
            cmd.extend(['-s', device_id])

        # Use PNG for both modes but with lower quality for fast mode
        # PNG is actually faster than raw because the device has hardware encoding
        if quality == 'fast':
            # Use PNG but lower quality (still faster than raw + conversion)
            cmd.extend(['exec-out', 'screencap', '-p'])
        else:
            # PNG encoding on device (high quality)
            cmd.extend(['exec-out', 'screencap', '-p'])

        # Capture screenshot with shorter timeout for streaming
        timeout = 2 if quality == 'fast' else 5
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return jsonify({"error": "Failed to capture screen"}), 500

        # Return image
        from flask import Response

        # For fast mode, convert PNG to JPEG for smaller file size
        if quality == 'fast':
            try:
                from PIL import Image
                import io

                # Load PNG from device
                img = Image.open(io.BytesIO(result.stdout))

                # Convert to JPEG with aggressive compression
                output = io.BytesIO()
                img.convert('RGB').save(output, format='JPEG', quality=50, optimize=False)
                output.seek(0)

                jpeg_data = output.getvalue()
                # print(f"[Screen] PNG->JPEG: {len(result.stdout)} -> {len(jpeg_data)} bytes")
                return Response(jpeg_data, mimetype='image/jpeg')

            except Exception as e:
                # If conversion fails, return PNG as-is
                print(f"[Screen] JPEG conversion failed: {e}")
                return Response(result.stdout, mimetype='image/png')
        else:
            # High quality mode - return PNG directly
            return Response(result.stdout, mimetype='image/png')

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Screen capture timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/screen/input', methods=['POST'])
def screen_input():
    """Send touch/key input to Android device"""
    try:
        from frida_ops import session_cache
        device_id = session_cache.get("selected_device_id")

        data = request.get_json()
        action = data.get('action')  # 'tap', 'swipe', 'key'

        cmd = ['adb']
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.append('shell')

        if action == 'tap':
            x = data.get('x')
            y = data.get('y')
            cmd.extend(['input', 'tap', str(x), str(y)])
        elif action == 'swipe':
            x1 = data.get('x1')
            y1 = data.get('y1')
            x2 = data.get('x2')
            y2 = data.get('y2')
            duration = data.get('duration', 100)
            cmd.extend(['input', 'swipe', str(x1), str(y1), str(x2), str(y2), str(duration)])
        elif action == 'key':
            keycode = data.get('keycode')
            cmd.extend(['input', 'keyevent', str(keycode)])
        elif action == 'text':
            text = data.get('text', '').replace(' ', '%s')
            cmd.extend(['input', 'text', text])
        else:
            return jsonify({"error": "Invalid action"}), 400

        subprocess.run(cmd, timeout=2, capture_output=True)
        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/adb/execute', methods=['POST'])
def execute_adb_command():
    """Execute ADB command and return output"""
    try:
        from frida_ops import session_cache
        data = request.get_json()
        command = data.get('command', '').strip()
        device_id = data.get('device_id') or session_cache.get("selected_device_id")

        if not command:
            return jsonify({"ok": False, "error": "No command provided"}), 400

        # Build ADB command
        cmd = ['adb']

        # Add device selector if specified
        if device_id:
            cmd.extend(['-s', device_id])

        # Parse and add the command parts
        # If command starts with 'adb', skip it
        if command.startswith('adb '):
            command = command[4:]

        # Split command into parts
        cmd.extend(command.split())

        # Execute with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        return jsonify({
            "ok": True,
            "output": result.stdout if result.stdout else result.stderr,
            "returncode": result.returncode,
            "command": ' '.join(cmd)
        })

    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Command timeout (30s)"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ADB Shell session management
shell_sessions = {}

@app.route('/api/adb/shell/connect', methods=['POST'])
def connect_adb_shell():
    """Start an interactive ADB shell session"""
    try:
        from frida_ops import session_cache
        data = request.get_json()
        device_id = data.get('device_id') or session_cache.get("selected_device_id")

        session_id = f"shell_{uuid.uuid4().hex[:12]}"

        # Build ADB shell command
        cmd = ['adb']
        if device_id:
            cmd.extend(['-s', device_id])
        cmd.append('shell')

        # Start interactive shell process
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Store session
        shell_sessions[session_id] = {
            'process': process,
            'device_id': device_id,
            'created_at': monotonic()
        }

        return jsonify({
            "ok": True,
            "session_id": session_id,
            "message": "Shell session started"
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/api/adb/shell/execute', methods=['POST'])
def execute_shell_command():
    """Execute command in interactive shell session"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        command = data.get('command', '').strip()

        if not session_id or session_id not in shell_sessions:
            return jsonify({"ok": False, "error": "Invalid or expired shell session"}), 400

        if not command:
            return jsonify({"ok": False, "error": "No command provided"}), 400

        session = shell_sessions[session_id]
        process = session['process']

        # Check if process is still alive
        if process.poll() is not None:
            del shell_sessions[session_id]
            return jsonify({"ok": False, "error": "Shell session terminated"}), 400

        # Add echo marker to detect end of output
        marker = f"__END_OF_COMMAND_{uuid.uuid4().hex[:8]}__"
        full_command = f"{command}; echo '{marker}'\n"

        # Send command to shell
        process.stdin.write(full_command)
        process.stdin.flush()

        # Read output until we see the marker
        import time
        output_lines = []
        start_time = time.time()
        timeout = 10  # 10 second timeout

        try:
            while time.time() - start_time < timeout:
                line = process.stdout.readline()
                if not line:
                    break

                line = line.rstrip()

                # Check if we hit the marker
                if marker in line:
                    # Remove the marker line from output
                    break

                # Skip the command echo if it appears
                if line.strip() == command.strip():
                    continue

                output_lines.append(line)

        except Exception as read_error:
            print(f"Error reading shell output: {read_error}")

        output = '\n'.join(output_lines) if output_lines else ''

        return jsonify({
            "ok": True,
            "output": output,
            "prompt": "shell@android:/ $"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/api/adb/shell/disconnect', methods=['POST'])
def disconnect_adb_shell():
    """Disconnect from shell session"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')

        if session_id and session_id in shell_sessions:
            session = shell_sessions[session_id]
            process = session['process']

            # Terminate process
            try:
                process.stdin.write('exit\n')
                process.stdin.flush()
                process.wait(timeout=2)
            except:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except:
                    process.kill()

            del shell_sessions[session_id]

        return jsonify({"ok": True, "message": "Shell session closed"})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/set-target/<path:identifier>")
def api_set_target(identifier):
    """
    Called from Dashboard after the user selects a running process.
    Saves target so Scripts page can spawn+inject without prompting.
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    try:
        set_saved_target(identifier, name)
        emit_dashboard_log(f"saved target {name}", type="info")
        return jsonify({"ok": True, "identifier": identifier, "name": name}), 200
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500



@app.route("/api/target", methods=["GET"])
def api_get_target():
    """
    Scripts page calls this to know the saved target.
    """
    try:
        target = get_saved_target()
        if not target or not target.get("identifier"):
            return jsonify({"ok": False, "message": "No target selected"}), 404
        return jsonify({"ok": True, **target}), 200
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500
    
    
    
@app.route("/api/target", methods=["DELETE"])
def api_clear_target():
    """
    Clears the saved target selection only.
    Does NOT touch any active Frida session.
    """
    try:
        prev = get_saved_target()
        clear_saved_target()

        # Optional: inform both dashboards (lightweight logs)
        emit_frida_log(f"Cleared saved target (was: {prev.get('name') or prev.get('identifier')})", type="info")
        emit_dashboard_log("Cleared saved target", type="info")

        return jsonify({"ok": True, "message": "Saved target cleared"})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500    



@app.post("/api/spawn-and-inject-library")
def api_spawn_and_inject_library():
    """
    Load MULTIPLE library scripts using the saved target, with CLI-style timing:
    spawn -> attach -> create_script/load ALL -> resume
    """
    data = request.get_json(force=True) or {}
    script_ids = data.get("script_ids") or []
    if not script_ids or not isinstance(script_ids, list):
        return jsonify({"ok": False, "message": "script_ids required"}), 400

    target = get_saved_target()
    if not target or not target.get("identifier"):
        return jsonify({"ok": False, "message": "No saved target. Select a process on Dashboard first."}), 400

    try:
        result = spawn_and_inject_multiple(target["identifier"], script_ids)
        # include friendly name if available
        result["name"] = target.get("name") or target["identifier"]
        return jsonify({"ok": True, **result}), 200
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500
    
    
    
@app.route('/api/console-messages/<session_id>')
def get_console_messages(session_id):
    """Get console messages for a session"""
    since = int(request.args.get('since', 0))
    new_messages = get_console_messages_for_session(session_id, since)
    
    print(f"[API] Console request for session {session_id}: {len(new_messages)} new messages since {since}")
    return jsonify({"messages": new_messages})


@app.route('/api/frida/get-path')
def get_frida_path():
    try:
        path = get_frida_server_path()
        return jsonify({"path": path})
    except Exception as e:
        return jsonify({"path": "/data/local/tmp/frida-server", "error": str(e)})

@app.route('/api/frida/save-path', methods=['POST'])
def save_frida_path():
    data = request.get_json()
    path = data.get('path', '').strip()

    if not path:
        return jsonify({"status": "error", "message": "Path is empty"}), 400

    try:
        os.makedirs('settings', exist_ok=True)
        with open('settings/server_path.txt', 'w') as f:
            f.write(path)
        emit_dashboard_log(f"Frida server path saved: {path}", type="success")
        return jsonify({"status": "ok", "message": "Frida path saved", "path": path})
    except Exception as e:
        emit_dashboard_log(f"Failed to save Frida path: {str(e)}", type="error")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/proxy/set', methods=['POST'])
def set_proxy():
    """Enable or disable HTTP proxy on Android device"""
    data = request.get_json()
    enable = data.get('enable', False)
    host = data.get('host', '').strip()
    port = data.get('port', '').strip()

    try:
        if enable:
            if not host or not port:
                return jsonify({"status": "error", "message": "Host and port required"}), 400

            # Validate port
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    raise ValueError("Invalid port range")
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid port number"}), 400

            # Enable proxy: adb shell settings put global http_proxy host:port
            proxy_value = f"{host}:{port}"
            subprocess.run(
                ['adb', 'shell', 'settings', 'put', 'global', 'http_proxy', proxy_value],
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            emit_dashboard_log(f"✅ Proxy enabled: {proxy_value}", type="success")
            return jsonify({
                "status": "ok",
                "message": f"Proxy enabled: {proxy_value}",
                "proxy": proxy_value,
                "enabled": True
            })
        else:
            # Disable proxy: adb shell settings put global http_proxy :0
            subprocess.run(
                ['adb', 'shell', 'settings', 'put', 'global', 'http_proxy', ':0'],
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            emit_dashboard_log("❌ Proxy disabled", type="info")
            return jsonify({
                "status": "ok",
                "message": "Proxy disabled",
                "enabled": False
            })

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        emit_dashboard_log(f"Proxy config failed: {error_msg}", type="error")
        return jsonify({"status": "error", "message": f"ADB command failed: {error_msg}"}), 500
    except Exception as e:
        emit_dashboard_log(f"Proxy error: {str(e)}", type="error")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/proxy/status')
def get_proxy_status():
    """Get current proxy status from Android device"""
    try:
        result = subprocess.run(
            ['adb', 'shell', 'settings', 'get', 'global', 'http_proxy'],
            capture_output=True,
            text=True,
            timeout=10
        )

        proxy = result.stdout.strip()

        # Check if proxy is enabled (not :0 and not empty)
        enabled = proxy and proxy != ':0' and proxy != 'null'

        return jsonify({
            "status": "ok",
            "enabled": enabled,
            "proxy": proxy if enabled else None
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "enabled": False
        }), 500


@app.route('/api/adb/devices')
def get_adb_devices():
    silent = _is_silent()
    try:
        output = subprocess.check_output(['adb', 'devices'], stderr=subprocess.STDOUT, text=True)
        lines = output.strip().split('\n')[1:]
        devices = []
        for line in lines:
            if line.strip() and 'device' in line and 'offline' not in line:
                serial = line.split()[0]
                # Get device model/name via getprop
                try:
                    model = subprocess.check_output(
                        ['adb', '-s', serial, 'shell', 'getprop', 'ro.product.model'],
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=2
                    ).strip()
                    name = f"{model} ({serial})" if model else f"Device ({serial})"
                except:
                    name = f"Device ({serial})"
                devices.append({"id": serial, "name": name})

        count = len(devices)
        if (_LAST_STATE.get("device_count") != count) or not silent:
            _LAST_STATE["device_count"] = count
            emit_console_dedup(f"Found {count} ADB device(s)", type="success", key="adb_devices", cooldown=5.0)

        # Get currently selected device
        from frida_ops import session_cache
        selected_device = session_cache.get("selected_device_id")

        return jsonify({
            "devices": devices,
            "selected": selected_device
        })
    except Exception as e:
        if not silent:
            emit_console_dedup(f"ADB devices error: {str(e)}", type="error", key="adb_devices_err", cooldown=10.0)
        return jsonify({"error": str(e)}), 500


@app.route('/api/adb/select-device', methods=['POST'])
def select_device():
    """Set the active device for Frida operations"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')

        if not device_id:
            return jsonify({"ok": False, "message": "No device_id provided"}), 400

        # Store in frida_ops session cache
        from frida_ops import session_cache
        session_cache["selected_device_id"] = device_id

        emit_dashboard_log(f"Selected device: {device_id}", type="info")

        return jsonify({
            "ok": True,
            "message": f"Device {device_id} selected",
            "device_id": device_id
        })
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500




@app.route('/api/frida/status')
def frida_status():
    path = get_frida_server_path()
    binary = os.path.basename(path)
    silent = _is_silent()

    try:
        # Use basename only - pidof on Android doesn't work with full paths
        output = subprocess.check_output(
            ['adb', 'shell', f'pidof {binary}'],
            stderr=subprocess.STDOUT,
            text=True
        ).strip()
        running = bool(output)
        pid = output if output else None

        # Only log if state changed (or not silent)
        if (running != _LAST_STATE.get("frida_running")) or not silent:
            _LAST_STATE["frida_running"] = running
            msg = "Frida server running" if running else "Frida server not running"
            # dedup extra hard in case multiple tabs call without silent
            emit_console_dedup(msg, type="info" if running else "warn", key="frida_status", cooldown=5.0)

        return jsonify({"running": running, "pid": pid, "process": binary})

    except subprocess.CalledProcessError as e:
        if (_LAST_STATE.get("frida_running") is not False) or not silent:
            _LAST_STATE["frida_running"] = False
            emit_console_dedup("Frida server not running", type="warn", key="frida_status_err", cooldown=5.0)
        return jsonify({"running": False, "error": e.output.strip(), "process": binary})
    except Exception as e:
        if (_LAST_STATE.get("frida_running") is not False) or not silent:
            _LAST_STATE["frida_running"] = False
        return jsonify({"running": False, "error": str(e), "process": binary})




@app.post("/api/spawn-and-inject")
def api_spawn_and_inject():
    data = request.get_json(silent=True) or {}
    identifier = data.get("identifier")
    code = data.get("code", "")

    if not identifier or not code:
        return jsonify({"status": "error", "message": "identifier and code are required"}), 400

    try:
        result = spawn_and_inject(identifier, code)
        # Optional: friendly name (best effort)
        name = data.get("name") or identifier
        emit_frida_log(f"Spawned & injected into {name} (PID {result['pid']})", type="success", session_id=result["session_id"])
        return jsonify({
            "status": "ok",
            "pid": result["pid"],
            "session_id": result["session_id"],
            "identifier": result["identifier"],
            "name": name
        })
    except Exception as e:
        msg = f"Spawn+inject failed: {e}"
        emit_frida_log(msg, type="error")
        return jsonify({"status": "error", "message": msg}), 500




@socketio.on('join', namespace=FRIDA_NS)
def frida_join(data):
    print(f"[Socket] Client requested to join session: {data}")
    
    session_id = (data or {}).get("session_id")
    if not session_id:
        print("[Socket] ❌ No session_id provided for join")
        emit("console_output", {
            "type": "error", 
            "payload": "session_id required for join()"
        }, namespace=FRIDA_NS)
        return
    
    print(f"[Socket] ✅ Joining room: {session_id}")
    join_room(session_id)
    
    # Send confirmation back to the specific client
    emit("joined", {
        "room": session_id,
        "status": "success",
        "message": f"Joined room {session_id}",
        "session_id": session_id
    })
    
    # Also send a console message to the room
    emit("console_output", {
        "type": "success", 
        "payload": f"✅ Successfully joined room {session_id}"
    }, namespace=FRIDA_NS, room=session_id)
    
    print(f"[Socket] ✅ Client joined room: {session_id}")



@socketio.on('leave', namespace=FRIDA_NS)
def frida_leave(data):
    session_id = (data or {}).get("session_id")
    if session_id:
        leave_room(session_id)
        emit_frida_log(f"Left room {session_id}", type="info", session_id=session_id)



@app.route('/api/start-frida', methods=['POST'])
def start_frida_server():
    data = request.get_json(silent=True) or {}
    path = data.get('path') or get_frida_server_path()

    try:
        # Save the path to settings if provided
        if data.get('path'):
            try:
                os.makedirs('settings', exist_ok=True)
                with open('settings/server_path.txt', 'w') as f:
                    f.write(path)
                print(f"[Settings] Saved Frida server path: {path}")
            except Exception as save_err:
                print(f"[Settings] Warning: Could not save path: {save_err}")

        # Step 1: Check if any ADB device is connected
        adb_devices = subprocess.check_output(["adb", "devices"], text=True).strip().split("\n")
        connected = [line for line in adb_devices[1:] if line.strip() and "device" in line and not "offline" in line]

        if not connected:
            raise RuntimeError("No connected ADB device found")

        # Step 2: Build and run remote command with nohup for background execution
        # Both chmod and execution need root permissions
        # Use nohup inside su and properly daemonize with redirects
        remote_command = f"su -c 'chmod +x {shlex.quote(path)} && nohup {shlex.quote(path)} >/dev/null 2>&1 &' >/dev/null 2>&1 &"
        full_command = ["adb", "shell", remote_command]

        # Run in background - don't wait for it
        subprocess.Popen(full_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Give it a moment to start
        import time
        time.sleep(0.5)

        emit_dashboard_log(f"Starting Frida server: {path}", type="info")
        return jsonify({
            "status": "ok",
            "message": f"Frida server started from: {path}"
        })

    except subprocess.CalledProcessError as e:
        emit_dashboard_log(f"Failed to start Frida: {e.output}", type="error")
        return jsonify({"status": "error", "message": str(e.output)}), 500

    except Exception as e:
        emit_dashboard_log(f"Error: {str(e)}", type="error")
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route('/api/stop-frida', methods=['POST'])
def stop_frida_server():
    try:
        path = get_frida_server_path()
        filename = os.path.basename(path)
        pids = set()

        # Try pidof with basename only (Android pidof doesn't work with full paths)
        try:
            out = subprocess.check_output(
                ['adb', 'shell', f'pidof {shlex.quote(filename)}'],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            if out:
                for pid in out.split():
                    if pid.isdigit():
                        pids.add(pid)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Fallback to pgrep with basename
        if not pids:
            try:
                out = subprocess.check_output(
                    ['adb', 'shell', f'pgrep {shlex.quote(filename)}'],
                    text=True, stderr=subprocess.DEVNULL
                ).strip()
                if out:
                    for pid in out.split():
                        if pid.isdigit():
                            pids.add(pid)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        # Ultimate fallback: ps | grep with basename
        if not pids:
            for probe in ['ps', 'ps -A', 'ps -ef']:
                try:
                    out = subprocess.check_output(
                        ['adb', 'shell', f'{probe} | grep {shlex.quote(filename)} | grep -v grep'],
                        text=True, stderr=subprocess.DEVNULL
                    ).strip()
                    for line in filter(None, out.split('\n')):
                        parts = line.split()
                        for tok in parts:
                            if tok.isdigit():
                                pids.add(tok)
                                break
                    if pids:
                        break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue

        if not pids:
            emit_dashboard_log(f"No running process found for {filename}", type="warn")
            return jsonify({"status": "warn", "message": f"No running process found for {filename}."})

        # Try graceful stop first
        term_ok = 0
        for pid in list(pids):
            try:
                rc = subprocess.run(
                    ['adb', 'shell', f'kill -s TERM {pid}'],
                    stderr=subprocess.DEVNULL,
                    timeout=5
                ).returncode
                if rc == 0:
                    term_ok += 1
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        # If nothing succeeded, try with su (for rooted devices)
        if term_ok == 0:
            for pid in pids:
                try:
                    subprocess.run(
                        ['adb', 'shell', f'su -c "kill -s TERM {pid}"'],
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue

        # Force kill if TERM didn't work
        still_running = set()
        for pid in pids:
            try:
                # Check if process still exists
                result = subprocess.run(
                    ['adb', 'shell', f'ps -p {pid}'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    still_running.add(pid)
            except subprocess.CalledProcessError:
                pass

        # Force kill any remaining processes
        if still_running:
            for pid in still_running:
                try:
                    subprocess.run(
                        ['adb', 'shell', f'su -c "kill -9 {pid}"'],
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass

        emit_frida_log(f"🛑 Stopped {len(pids)} Frida server instance(s)", type="success")
        emit_dashboard_log(f"🛑 Stopped {len(pids)} Frida server instance(s)", type="success")

        return jsonify({
            "status": "ok",
            "message": f"Sent TERM to {len(pids)} instance(s) of '{filename}'",
            "pids": sorted(pids)
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/scripts')
def scripts_page():
    emit_frida_log("📂 Scripts page loaded", type="info")
    return render_template('scripts.html')



@app.route('/api/processes', methods=['GET'])
def get_processes():
    silent = _is_silent()
    try:
        result = subprocess.run(["frida-ps", "-Uai"], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')[2:]
        processes = []
        for line in lines:
            parts = line.strip().rsplit(None, 1)
            if len(parts) == 2:
                raw_name = parts[0].strip()
                identifier = parts[1].strip()
                if identifier.startswith(("com.android.", "com.google.", "com.samsung.", "com.huawei.", "com.mi.", "com.vivo.", "com.oppo.", "com.realme.", "com.motorola.")):
                    continue
                name_parts = raw_name.split(None, 1)
                cleaned_name = name_parts[1] if len(name_parts) == 2 else name_parts[0]
                processes.append({"name": cleaned_name, "identifier": identifier})

        count = len(processes)
        if (_LAST_STATE.get("process_count") != count) or not silent:
            _LAST_STATE["process_count"] = count
            emit_console_dedup(f"Found {count} processes", type="info", key="frida_processes", cooldown=5.0)

        return jsonify({"processes": processes})
    except subprocess.CalledProcessError as e:
        if not silent:
            emit_console_dedup(f"Frida-ps error: {e.stderr}", type="error", key="frida_processes_err", cooldown=10.0)
        return jsonify({"error": "Frida error", "details": e.stderr}), 500
    except FileNotFoundError:
        if not silent:
            emit_console_dedup("frida-ps not found", type="error", key="frida_processes_notfound", cooldown=30.0)
        return jsonify({"error": "frida-ps not found. Make sure frida-tools is installed."}), 500



# FIXED: Use frida_ops session management instead of overriding it
@app.route('/api/attach/<string:pid>', methods=['POST'])
def attach(pid):
    print(f"[DEBUG] Attach request received for PID: {pid}")
    
    # Idempotency: if already attached to this PID, return OK
    if session_cache.get("session") and session_cache.get("pid") == pid:
        return jsonify({
            "status": "ok",
            "message": f"Already attached to {pid}",
            "pid": pid,
            "session_active": True,
            "session_id": session_cache.get("session_id"),
            "name": session_cache.get("name")
        })
        
    try:
        session = attach_to_process(pid)
        body = request.get_json(silent=True) or {}
        proc_name = body.get("name") or f"pid:{pid}"

        session_id = f"session_{pid}_{uuid.uuid4().hex[:8]}"
        session_cache["pid"] = pid
        session_cache["session"] = session
        session_cache["session_id"] = session_id
        session_cache["name"] = proc_name

        payload = {
            "attached": True,
            "pid": pid,
            "name": proc_name,
            "session_id": session_id,
        }
        
        # EMIT TO BOTH DEFAULT AND FRIDA NAMESPACES
        print(f"[Socket] Emitting 'attached' to room {session_id} in both namespaces")
        
        # Emit to default namespace (dashboard)
        socketio.emit("attached", payload)
        
        # Emit to frida namespace with room targeting
        socketio.emit("attached", payload, namespace=FRIDA_NS, room=session_id)
        
        emit_console(f"Successfully attached to process {pid}", only_namespace=FRIDA_NS, room=session_id)
        emit_dashboard_log(f"Successfully attached to process {pid}", type="success")

        response_data = {
            "status": "ok",
            "session_id": session_id,
            "pid": pid,
            "name": proc_name,
            "message": f"Successfully attached to process {pid}",
            "session_active": True
        }
        return jsonify(response_data)

    except Exception as e:
        error_msg = f"Failed to attach to process {pid}: {str(e)}"
        emit_console(error_msg, "error")
        return jsonify({
            "status": "error",
            "message": error_msg,
            "pid": None,
            "session_active": False
        }), 500


@app.route('/api/attach-only/<string:identifier>', methods=['POST'])
def attach_only(identifier):
    """
    Attach to an already-running process ONLY. Does not launch or spawn.
    Used for reconnecting to a crashed/killed app that's been manually restarted.
    """
    print(f"[DEBUG] Attach-only request received for identifier: {identifier}")

    # Idempotency: if already attached to this identifier, return OK
    if session_cache.get("session") and session_cache.get("pid") == identifier:
        return jsonify({
            "status": "ok",
            "message": f"Already attached to {identifier}",
            "pid": identifier,
            "session_active": True,
            "session_id": session_cache.get("session_id"),
            "name": session_cache.get("name")
        })

    try:
        device = get_selected_device()
        body = request.get_json(silent=True) or {}
        proc_name = body.get("name") or f"process:{identifier}"

        session = None
        actual_pid = None

        # Check if identifier is a numeric PID
        if identifier.isdigit():
            print(f"[DEBUG] Attaching to PID: {identifier}")
            pid = int(identifier)
            session = device.attach(pid)
            actual_pid = pid
        else:
            # Try to find running process by package name
            print(f"[DEBUG] Looking for running process with identifier: {identifier}")
            processes = device.enumerate_processes()

            # First, try exact name match
            for proc in processes:
                if proc.name == identifier:
                    print(f"[DEBUG] Found running process by name: {proc.name} (PID: {proc.pid})")
                    session = device.attach(proc.pid)
                    actual_pid = proc.pid
                    proc_name = proc.name
                    break

            # If not found by name, try to match by package identifier
            if session is None:
                print(f"[DEBUG] Not found by name, checking applications...")
                try:
                    applications = device.enumerate_applications()

                    # Debug: Print processes containing our identifier
                    print(f"[DEBUG] Total running processes: {len(processes)}")
                    matching_procs = [p for p in processes if identifier.lower() in p.name.lower() or 'sooum' in p.name.lower()]
                    if matching_procs:
                        print(f"[DEBUG] Potentially matching processes:")
                        for proc in matching_procs:
                            print(f"[DEBUG]   - {proc.name} (PID: {proc.pid})")
                    else:
                        print(f"[DEBUG] No processes found matching '{identifier}'")

                    # Find the app with matching identifier
                    target_app = None
                    for app in applications:
                        if app.identifier == identifier:
                            target_app = app
                            print(f"[DEBUG] Found application: {app.name} ({app.identifier})")
                            break

                    if target_app:
                        # Now find the running process with more flexible matching
                        for proc in processes:
                            # Try exact match
                            if proc.name == target_app.name:
                                print(f"[DEBUG] Found running process (exact): {proc.name} (PID: {proc.pid})")
                                session = device.attach(proc.pid)
                                actual_pid = proc.pid
                                proc_name = target_app.name
                                break
                            # Try case-insensitive match
                            elif proc.name.lower() == target_app.name.lower():
                                print(f"[DEBUG] Found running process (case-insensitive): {proc.name} (PID: {proc.pid})")
                                session = device.attach(proc.pid)
                                actual_pid = proc.pid
                                proc_name = target_app.name
                                break
                            # Try partial match (for shortened names)
                            elif target_app.name.lower() in proc.name.lower() or proc.name.lower() in target_app.name.lower():
                                print(f"[DEBUG] Found running process (partial): {proc.name} (PID: {proc.pid})")
                                session = device.attach(proc.pid)
                                actual_pid = proc.pid
                                proc_name = target_app.name
                                break

                    # Last resort: try matching identifier directly with process name
                    if session is None:
                        print(f"[DEBUG] Last resort: checking if identifier matches any process name...")
                        for proc in processes:
                            if identifier.lower() in proc.name.lower() or proc.name.lower() in identifier.lower():
                                print(f"[DEBUG] Found running process (identifier match): {proc.name} (PID: {proc.pid})")
                                session = device.attach(proc.pid)
                                actual_pid = proc.pid
                                proc_name = proc.name
                                break

                except Exception as e:
                    print(f"[DEBUG] Error during application lookup: {e}")

        # If still not found, fail (don't launch)
        if session is None:
            error_msg = f"Process '{identifier}' is not running. Please launch the app first."
            print(f"[DEBUG] {error_msg}")
            return jsonify({
                "status": "error",
                "message": error_msg,
                "pid": None,
                "session_active": False
            }), 404

        # Successfully attached
        session_id = f"session_{actual_pid}_{uuid.uuid4().hex[:8]}"
        session_cache["pid"] = str(actual_pid)
        session_cache["session"] = session
        session_cache["session_id"] = session_id
        session_cache["name"] = proc_name

        payload = {
            "attached": True,
            "pid": str(actual_pid),
            "name": proc_name,
            "session_id": session_id,
        }

        # Emit socket events
        print(f"[Socket] Emitting 'attached' for reconnect")
        socketio.emit("attached", payload)
        socketio.emit("attached", payload, namespace=FRIDA_NS, room=session_id)

        emit_console(f"Reconnected to process {actual_pid}", only_namespace=FRIDA_NS, room=session_id)
        emit_dashboard_log(f"Reconnected to process {actual_pid}", type="success")

        return jsonify({
            "status": "ok",
            "session_id": session_id,
            "pid": str(actual_pid),
            "name": proc_name,
            "message": f"Successfully reconnected to process {actual_pid}",
            "session_active": True
        })

    except Exception as e:
        error_msg = f"Failed to reconnect to process '{identifier}': {str(e)}"
        print(f"[ERROR] {error_msg}")
        emit_console(error_msg, "error")
        return jsonify({
            "status": "error",
            "message": error_msg,
            "pid": None,
            "session_active": False
        }), 500


@app.route('/api/detach/<string:pid>', methods=['POST'])
def detach(pid):
    current_pid = session_cache.get("pid")
    if current_pid != pid:
        error_msg = f"Cannot detach {pid} - attached to {current_pid}"
        emit_dashboard_log(f"{error_msg}", type="error")
        return jsonify({"status": "error", "message": error_msg}), 400

    session_id = session_cache.get("session_id")
    frida_detach()
    socketio.emit("detached", {"previous_session": session_id}, namespace=FRIDA_NS)
    
    emit_frida_log(f"Detached from process {pid}", type="success", session_id=session_id)
    emit_dashboard_log(f"Detached from process {pid}", type="success")

    return jsonify({"status": "ok", "message": f"Detached from process {pid}"})

@app.route('/api/detach', methods=['POST'])
def detach_current():
    try:
        current_pid = session_cache.get("pid")
        session_id = session_cache.get("session_id")
        frida_detach()

        socketio.emit("detached", {"previous_session": session_id}, namespace=FRIDA_NS)
        if current_pid:
            emit_frida_log(f"Detached from process {current_pid}", type="success", session_id=session_id)
            emit_dashboard_log(f"Detached from process {current_pid}", type="success")
            return jsonify({"status": "ok", "message": f"Detached from process {current_pid}"})
        else:
            emit_dashboard_log("No process was attached", type="info")
            return jsonify({"status": "ok", "message": "No process was attached"})
    except Exception as e:
        error_msg = f"Failed to detach: {str(e)}"
        emit_dashboard_log(f"{error_msg}", type="error")
        return jsonify({"status": "error", "message": error_msg}), 500


# FIXED: Use get_current_session_info() from frida_ops
@app.route('/api/attached-process', methods=['GET'])
def get_attached_process():
    try:
        session_info = get_current_session_info()
        return jsonify(session_info)
    except Exception as e:
        return jsonify({
            "pid": None,
            "session_id": None,
            "name": None,
            "session_active": False,
            "status": "error",
            "message": str(e)
        }), 500




@app.route('/api/load-script', methods=['POST'])
def load_frida_script():
    data = request.get_json()
    code = data.get("code")
    
    if not code:
        return jsonify({"status": "error", "message": "Missing script code"}), 400

    if not session_cache.get("pid"):
        return jsonify({"status": "error", "message": "No process attached"}), 400

    try:
        session_id = session_cache.get("session_id")
        
        # DEBUG: Print the code being injected
        print(f"[DEBUG] Injecting script of length: {len(code)} characters")
        print(f"[DEBUG] First 200 chars: {code[:200]}...")
        
        # ACTUALLY inject the user's script code
        inject_script(code)
        
        emit_frida_log("Script injected successfully", type="success", session_id=session_id)
        return jsonify({"status": "ok", "message": "Script injected successfully"})
        
    except Exception as e:
        # DEBUG: Print the full error traceback
        import traceback
        error_traceback = traceback.format_exc()
        print(f"[ERROR] Script injection failed: {e}")
        print(f"[ERROR] Traceback:\n{error_traceback}")
        
        error_msg = f"Script injection failed: {str(e)}"
        session_id = session_cache.get("session_id")
        emit_frida_log(f"{error_msg}", type="error", session_id=session_id)
        return jsonify({"status": "error", "message": error_msg}), 500



@app.route('/api/load-script/<session_id>', methods=['POST'])
def load_script(session_id):
    if session_cache.get("session_id") != session_id or not session_cache.get("pid"):
        return jsonify({"status": "error", "message": "No active session"}), 400

    data = request.get_json(silent=True) or {}
    script_id = data.get('script_id', 'unknown')

    emit_frida_log(f"Loading script: {script_id}", type="info", session_id=session_id)

    return jsonify({"status": "ok"})


@app.route('/api/inject-library-scripts', methods=['POST'])
def inject_library_scripts():
    """
    Inject multiple library scripts into an already-attached process.
    Does NOT spawn or relaunch - just injects into current session.
    Combines multiple scripts into one to avoid conflicts.
    """
    data = request.get_json() or {}
    script_ids = data.get("script_ids", [])

    if not script_ids or not isinstance(script_ids, list):
        return jsonify({"status": "error", "message": "script_ids required"}), 400

    if not session_cache.get("session") or not session_cache.get("pid"):
        return jsonify({"status": "error", "message": "No active session. Attach to a process first."}), 400

    try:
        session_id = session_cache.get("session_id")
        db = ScriptDatabase()

        # Collect all script codes
        codes = []
        script_names = []

        for script_id in script_ids:
            script = db.get_script_by_id(script_id)
            if script and script.get('code'):
                codes.append(script['code'])
                script_names.append(script.get('name', f'Script {script_id}'))

        if not codes:
            return jsonify({"status": "error", "message": "No valid scripts found"}), 400

        # Combine all scripts into one to avoid conflicts (same as spawn_and_inject_multiple)
        if len(codes) == 1:
            # Single script - inject directly
            combined_code = codes[0]
            emit_console(f"✅ Injecting: {script_names[0]}", only_namespace=FRIDA_NS, room=session_id)
        else:
            # Multiple scripts - combine them with sequential execution
            print(f"[INJECT] Combining {len(codes)} scripts to prevent conflicts...")
            emit_console(f"Combining {len(codes)} scripts...", type="info", only_namespace=FRIDA_NS, room=session_id)

            combined_code = "(function() {\n"
            combined_code += "    var scriptQueue = [];\n"
            combined_code += "    var currentIndex = 0;\n\n"

            for i, (code, name) in enumerate(zip(codes, script_names)):
                # Wrap each script in a function to execute sequentially
                combined_code += f"    // Script {i+1}: {name}\n"
                combined_code += f"    scriptQueue.push(function() {{\n"
                combined_code += f"        {code}\n"
                combined_code += f"    }});\n\n"

            # Execute scripts sequentially with delay
            combined_code += """
    function executeNext() {
        if (currentIndex < scriptQueue.length) {
            console.log('[Frida] Executing script ' + (currentIndex + 1) + '/' + scriptQueue.length);
            try {
                scriptQueue[currentIndex]();
            } catch (e) {
                console.error('[Frida] Script ' + (currentIndex + 1) + ' error: ' + e.message);
            }
            currentIndex++;
            setTimeout(executeNext, 200);  // 200ms delay between scripts
        }
    }

    setTimeout(executeNext, 100);  // Start after 100ms
})();
"""

        # Inject the combined script
        inject_script(combined_code)

        message = f"Injected {len(codes)} script(s): {', '.join(script_names)}"
        emit_console(message, type="success", only_namespace=FRIDA_NS, room=session_id)

        return jsonify({
            "status": "ok",
            "message": message,
            "loaded_count": len(codes),
            "session_id": session_id,
            "pid": session_cache.get("pid")
        })

    except Exception as e:
        error_msg = f"Failed to inject scripts: {str(e)}"
        print(f"[ERROR] {error_msg}")
        session_id = session_cache.get("session_id")
        if session_id:
            emit_console(error_msg, type="error", only_namespace=FRIDA_NS, room=session_id)
        return jsonify({"status": "error", "message": error_msg}), 500


# Debug routes
@app.route('/api/debug/processes')
def debug_processes():
    try:
        from frida_ops import debug_list_processes
        processes = debug_list_processes()
        
        process_list = []
        for proc in processes:
            process_list.append({
                "pid": proc.pid,
                "name": proc.name
            })
        
        emit_dashboard_log(f"Debug: Found {len(process_list)} processes", type="info")
        return jsonify({
            "status": "ok",
            "processes": process_list,
            "count": len(process_list)
        })
    except Exception as e:
        emit_dashboard_log(f"Debug error: {str(e)}", type="error")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/debug/applications')
def debug_applications():
    try:
        from frida_ops import debug_list_applications
        applications = debug_list_applications()
        
        app_list = []
        for app in applications:
            app_list.append({
                "identifier": app.identifier,
                "name": app.name
            })
        
        emit_dashboard_log(f"Debug: Found {len(app_list)} applications", type="info")
        return jsonify({
            "status": "ok",
            "applications": app_list,
            "count": len(app_list)
        })
    except Exception as e:
        emit_dashboard_log(f"Debug error: {str(e)}", type="error")
        return jsonify({"status": "error", "message": str(e)}), 500

@socketio.on('connect')
def ws_connect():
    emit_console_dedup("WebSocket connected", type="info", key="ws_connect_default", cooldown=30.0)


@socketio.on('connect', namespace=FRIDA_NS)
def ws_connect_frida():
    emit_console_dedup("WebSocket connected to Frida namespace", type="info", key="ws_connect_frida", cooldown=30.0)


if __name__ == '__main__':
    init_script_db()
    seed_script_library()
    print("✅ Frida GUI Controller starting...")
    socketio.run(app, host='0.0.0.0', port=8010, debug=False, log_output=True)