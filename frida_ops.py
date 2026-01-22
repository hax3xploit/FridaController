import os
import frida
import subprocess
import time
import uuid
from flask_socketio import emit
import sqlite3
from database import ScriptDatabase

socketio = None
FRIDA_NS = "/frida"

# Global session map to support multiple PIDs
sessions = {}
console_messages = {}  # session_id -> list of messages

_saved_target = {"identifier": None, "name": None}

# Session cache for device selection
session_cache = {}


def get_selected_device():
    """Get the Frida device based on user selection, or default to USB device"""
    device_id = session_cache.get("selected_device_id")

    if device_id:
        try:
            # Try to get specific device by ID
            device_manager = frida.get_device_manager()
            devices = device_manager.enumerate_devices()

            for dev in devices:
                if dev.id == device_id:
                    print(f"[Device] Using selected device: {dev.name} ({dev.id})")
                    return dev

            # If selected device not found, fall back to USB
            print(f"[Device] Selected device {device_id} not found, falling back to USB device")
        except Exception as e:
            print(f"[Device] Error getting selected device: {e}, falling back to USB device")

    # Default: get first USB device
    device = frida.get_usb_device(timeout=10)
    print(f"[Device] Using default USB device: {device.name} ({device.id})")
    return device


def set_socketio_instance(instance):
    global socketio
    socketio = instance


def on_session_detached(reason):
    """
    Called by Frida when the session is detached (process killed, crashed, etc.)
    """
    print(f"🔌 [Frida] Session detached! Reason: {reason}")

    session_id = session_cache.get("session_id")
    pid = session_cache.get("pid")

    # Clear the session state
    session_cache.update({
        "session": None,
        "pid": None,
        "script": None,
        "scripts": [],
        "session_id": None
    })

    # Also clear the saved target since the process is gone
    global _saved_target
    _saved_target = {"identifier": None, "name": None}

    # Emit disconnect event to frontend
    if socketio:
        disconnect_event = {
            "type": "session_detached",
            "reason": str(reason),
            "session_id": session_id,
            "pid": pid,
            "message": f"Process disconnected: {reason}"
        }
        try:
            # Broadcast to ALL clients in namespace (no room parameter = broadcast)
            # This works from outside request context unlike broadcast=True
            socketio.emit("frida_disconnected", disconnect_event, namespace=FRIDA_NS)

            # Also send as a console message (broadcast to all)
            socketio.emit("frida_output", {
                "type": "error",
                "message": f"⚠️ Process disconnected: {reason}"
            }, namespace=FRIDA_NS)
            print(f"[Socket.IO] Emitted frida_disconnected event to all clients")
        except Exception as e:
            print(f"[Socket.IO] Error emitting disconnect event: {e}")

# Global cache to manage session and script
session_cache = {
    "session": None,
    "pid": None,
    "script": None,
    "session_id": None,  # Add this!
}


def spawn_and_inject_multiple(identifier: str, script_ids: list[int]):
    """
    CLI-equivalent workflow (like: frida -U -f app -l a.js -l b.js):
      1) Spawn (suspended)
      2) Attach
      3) Load each script separately while suspended (same as CLI)
      4) Resume (scripts become active immediately)

    This mirrors exactly how `frida -l script1.js -l script2.js` works.
    """
    device = get_selected_device()

    # Clean old state
    try:
        if session_cache.get("scripts"):
            for script in session_cache["scripts"]:
                try: script.unload()
                except: pass
        if session_cache.get("script"):
            session_cache["script"].unload()
        if session_cache.get("session"):
            session_cache["session"].detach()
    except: pass

    session_cache.update({
        "session": None, "pid": None, "script": None,
        "scripts": [], "session_id": None
    })

    # Get script codes
    codes = load_codes_by_ids(script_ids)
    if not codes:
        raise RuntimeError("No scripts found")

    print(f"[SPAWN] Starting spawn+inject for {identifier} with {len(codes)} scripts")

    # Step 1: Spawn process (suspended)
    pid = device.spawn([identifier])
    print(f"[SPAWN] Process spawned (suspended) PID: {pid}")

    # Step 2: Attach to suspended process
    session = device.attach(pid)
    session_id = f"session_{uuid.uuid4().hex[:8]}"
    print(f"[SPAWN] Attached to suspended process, session: {session_id}")

    # Register detached handler to detect when process is killed
    session.on("detached", on_session_detached)

    # Step 3: Load scripts while process is suspended
    # For multiple scripts, combine them into one to avoid race conditions
    loaded_scripts = []
    load_errors = []

    if len(codes) == 1:
        # Single script - load normally
        try:
            print(f"[SPAWN] Loading single script into suspended process...")
            script = session.create_script(codes[0])
            script.on("message", on_frida_message)
            script.set_log_handler(on_frida_log)
            script.load()
            loaded_scripts.append(script)
            print(f"[SPAWN] Script loaded successfully")
        except Exception as e:
            raise RuntimeError(f"Script failed to load: {e}")
    else:
        # Multiple scripts - combine them with sequential Java.perform() execution
        # This prevents race conditions when multiple scripts initialize Java VM
        print(f"[SPAWN] Combining {len(codes)} scripts to prevent conflicts...")

        combined_code = "(function() {\n"
        combined_code += "    var scriptQueue = [];\n"
        combined_code += "    var currentIndex = 0;\n\n"

        for i, code in enumerate(codes):
            # Wrap each script in a function to execute sequentially
            combined_code += f"    // Script {i+1}\n"
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

        try:
            print(f"[SPAWN] Loading combined script into suspended process...")
            script = session.create_script(combined_code)
            script.on("message", on_frida_message)
            script.set_log_handler(on_frida_log)
            script.load()
            loaded_scripts.append(script)
            print(f"[SPAWN] Combined script loaded successfully")
        except Exception as e:
            raise RuntimeError(f"Combined script failed to load: {e}")

    # Save state before resume
    session_cache.update({
        "pid": str(pid),
        "session": session,
        "session_id": session_id,
        "scripts": loaded_scripts,
        "script": loaded_scripts[0] if loaded_scripts else None
    })

    print(f"[SPAWN] {len(loaded_scripts)}/{len(codes)} scripts loaded, resuming process...")

    # Step 4: Resume process - scripts become active immediately
    device.resume(pid)
    print(f"[SPAWN] Process resumed - scripts are now active")

    # Wait longer for multiple scripts to initialize and hook properly
    # This prevents race conditions where scripts try to hook the same methods
    delay = 0.5 if len(loaded_scripts) == 1 else 1.5
    print(f"[SPAWN] Waiting {delay}s for scripts to initialize...")
    time.sleep(delay)

    # Check if process is still alive after script initialization
    try:
        # Try to get session info to verify it's still alive
        if session.is_detached:
            warning_msg = "⚠️ Process crashed after script injection. This usually means:\n" \
                         "1. Multiple scripts are hooking the same functions (conflict)\n" \
                         "2. A script has syntax/runtime errors\n" \
                         "3. Scripts are incompatible with this app version"
            print(f"[SPAWN] {warning_msg}")
            if socketio:
                socketio.emit("frida_output", {
                    "type": "error",
                    "message": warning_msg
                }, namespace=FRIDA_NS)
    except Exception as check_err:
        print(f"[SPAWN] Could not verify process state: {check_err}")

    # Report any load errors to console (broadcast to all clients)
    if load_errors:
        for err in load_errors:
            if socketio:
                socketio.emit("frida_output", {
                    "type": "warn",
                    "message": f"⚠️ {err}"
                }, namespace=FRIDA_NS)

    return {
        "pid": pid,
        "session_id": session_id,
        "identifier": identifier,
        "loaded_count": len(loaded_scripts),
        "total_scripts": len(codes),
        "errors": load_errors
    }




def load_codes_by_ids(script_ids):
    """
    Return a list of script source strings for the given IDs.
    Uses the same DB access layer as your script_library blueprint.
    """
    codes = []
    for sid in script_ids:
        s = ScriptDatabase.get_script_by_id(sid)
        if s and s.get("code"):
            print(f"[SPAWN] Loaded script ID {sid}: {s.get('name', 'Unnamed')} ({len(s['code'])} bytes)")
            codes.append(s["code"])
    return codes

def set_saved_target(identifier, name=None):
    _saved_target["identifier"] = identifier
    _saved_target["name"] = name

def get_saved_target():
    return dict(_saved_target)

def clear_saved_target():
    _saved_target["identifier"] = None
    _saved_target["name"] = None
    return dict(_saved_target)




def add_console_message(session_id, message, msg_type="log"):
    """Add a message to the console buffer for a session"""
    global console_messages

    if session_id not in console_messages:
        console_messages[session_id] = []

    # Get next message ID (ensure it's always incrementing)
    existing_messages = console_messages[session_id]
    message_id = (existing_messages[-1]["id"] + 1) if existing_messages else 1

    console_messages[session_id].append({
        "id": message_id,
        "message": message,
        "type": msg_type,
        "timestamp": time.time()
    })

    # Keep only last 200 messages per session
    if len(console_messages[session_id]) > 200:
        console_messages[session_id] = console_messages[session_id][-200:]

    # Clean up old sessions (keep only last 10 sessions)
    if len(console_messages) > 10:
        # Sort sessions by most recent message timestamp
        sessions_by_time = sorted(
            console_messages.keys(),
            key=lambda sid: console_messages[sid][-1]["timestamp"] if console_messages[sid] else 0,
            reverse=True
        )
        # Remove oldest sessions
        for old_session in sessions_by_time[10:]:
            del console_messages[old_session]
            print(f"[Console Buffer] Cleaned up old session: {old_session}")

    print(f"[Console Buffer] Added message #{message_id} for session {session_id}")



def get_console_messages_for_session(session_id, since=0):
    """Get console messages for a session since a given message ID"""
    messages = console_messages.get(session_id, [])
    return [msg for msg in messages if msg['id'] > since]



def attach_to_process(identifier: str):
    """
    Attach to a process by PID or package identifier.
    """
    print(f"[DEBUG] attach_to_process called with identifier: {identifier}")

    device = get_selected_device()
    print(f"[DEBUG] Got device: {device}")
    
    # Generate a unique session ID
    session_id = f"session_{uuid.uuid4().hex[:8]}"
    print(f"[DEBUG] Generated session_id: {session_id}")
    
    # Check if identifier is a numeric PID
    if identifier.isdigit():
        print(f"[DEBUG] Identifier is numeric PID: {identifier}")
        pid = int(identifier)
        session = device.attach(pid)
        actual_pid = pid
    else:
        print(f"[DEBUG] Identifier is package name: {identifier}")
        session = None
        actual_pid = None
        
        # Method 1: Check if app is already running
        print(f"[DEBUG] Checking if app is already running...")
        processes = device.enumerate_processes()
        for proc in processes:
            # Check both by name and by identifier
            # Some apps show up by display name (e.g., "QDI") rather than package name
            if proc.name == identifier:
                print(f"[DEBUG] Found running process by exact name: {proc.name} (PID: {proc.pid})")
                session = device.attach(proc.pid)
                actual_pid = proc.pid
                break
        
        # If not found by exact name, also check applications to match PID with package
        if session is None:
            print(f"[DEBUG] Not found by exact name, checking running applications...")
            try:
                # Get list of running applications with their PIDs
                applications = device.enumerate_applications()
                running_apps = device.enumerate_processes()
                
                # Look for the package identifier in applications list
                target_app = None
                for app in applications:
                    if app.identifier == identifier:
                        target_app = app
                        break
                
                if target_app:
                    print(f"[DEBUG] Found target application: {target_app.name} ({target_app.identifier})")
                    # Now find the corresponding running process
                    for proc in running_apps:
                        # Match by process name with the app name
                        if proc.name.lower() == target_app.name.lower() or proc.name == target_app.name:
                            print(f"[DEBUG] Found running process for app: {proc.name} (PID: {proc.pid})")
                            session = device.attach(proc.pid)
                            actual_pid = proc.pid
                            break
                        # Also try matching shortened names (e.g., "QDI" matches "QDI App")
                        elif target_app.name.lower().startswith(proc.name.lower()) or proc.name.lower().startswith(target_app.name.lower()):
                            print(f"[DEBUG] Found potential match: {proc.name} for {target_app.name} (PID: {proc.pid})")
                            session = device.attach(proc.pid)
                            actual_pid = proc.pid
                            break
            except Exception as e:
                print(f"[DEBUG] Error during application matching: {e}")
        
        # Method 2: If not running, try to launch it first with ADB, then attach
        if session is None:
            print(f"[DEBUG] App not running, trying alternative launch methods...")
            
            # Skip ADB launch - go directly to Frida spawn for cleaner app launch
            print(f"[DEBUG] Skipping ADB launch, using Frida spawn for clean launch...")
            
            # Method 2b: If ADB launch didn't work, try Frida spawn with longer timeout
            if session is None:
                print(f"[DEBUG] Trying Frida spawn with extended timeout...")
                try:
                    # First check if the app exists in applications
                    applications = device.enumerate_applications()
                    app_exists = False
                    for app in applications:
                        if app.identifier == identifier:
                            app_exists = True
                            print(f"[DEBUG] Found application: {app.name} ({app.identifier})")
                            break
                    
                    if not app_exists:
                        raise frida.ProcessNotFoundError(f"Application '{identifier}' not found in installed apps")
                    
                    # Try to spawn with custom options
                    print(f"[DEBUG] Spawning application: {identifier}")
                    spawn_options = {
                        "timeout": 15  # 15 second timeout instead of default
                    }
                    
                    pid = device.spawn(identifier, **spawn_options)
                    print(f"[DEBUG] Spawned with PID: {pid}")
                    
                    # Attach to the spawned process
                    session = device.attach(pid)
                    print(f"[DEBUG] Attached to spawned process")
                    
                    # Resume the process so it starts running
                    device.resume(pid)
                    print(f"[DEBUG] Resumed process")
                    
                    actual_pid = pid
                    
                except frida.InvalidArgumentError as e:
                    print(f"[DEBUG] Invalid argument error: {e}")
                    raise frida.ProcessNotFoundError(f"Cannot spawn application '{identifier}': {e}")
                except frida.TimedOutError as e:
                    print(f"[DEBUG] Spawn timeout: {e}")
                    raise frida.ProcessNotFoundError(f"App '{identifier}' took too long to start. Try launching it manually first.")
                except Exception as e:
                    print(f"[DEBUG] Spawn failed: {e}")
                    # Don't give up yet - suggest manual launch
                    raise frida.ProcessNotFoundError(f"Auto-launch failed for '{identifier}'. Please launch the app manually on your device, then try attaching again.")
    
    if session is None or actual_pid is None:
        raise frida.ProcessNotFoundError(f"Could not attach to process '{identifier}'")
    
    # Store in session cache with session_id
    session_cache["pid"] = str(actual_pid)
    session_cache["session"] = session
    session_cache["session_id"] = session_id  # CRITICAL: Store the session_id
    
    print(f"[DEBUG] Successfully attached. Session: {session}, PID: {actual_pid}, Session ID: {session_id}")
    
    return session

def detach():
    """
    Detach from the current session and clear cache.
    """
    # Unload ALL scripts if they exist
    if session_cache.get("scripts"):
        for script in session_cache["scripts"]:
            try:
                script.unload()
            except:
                pass
    elif session_cache.get("script"):
        try:
            session_cache["script"].unload()
        except:
            pass

    if session_cache["session"]:
        try:
            session_cache["session"].detach()
        except:
            pass

    session_cache.update({
        "script": None,
        "scripts": [],
        "session": None,
        "pid": None,
        "session_id": None
    })

# --- ADD in frida_ops.py ---
def spawn_and_inject(identifier: str, js_code: str):
    """
    CLI-equivalent flow:
    1) device.spawn(identifier)          (do NOT resume)
    2) device.attach(pid)
    3) session.create_script(...).load() (before resume)
    4) device.resume(pid)
    """
    device = get_selected_device()

    # Clean any stale state
    try:
        if session_cache.get("script"):
            session_cache["script"].unload()
    except Exception:
        pass
    try:
        if session_cache.get("session"):
            session_cache["session"].detach()
    except Exception:
        pass
    session_cache.update({"session": None, "pid": None, "script": None, "session_id": None})

    # 1) Spawn (no resume yet)
    pid = device.spawn(identifier)
    # 2) Attach
    session = device.attach(pid)
    session_id = f"session_{uuid.uuid4().hex[:8]}"

    # Register detached handler to detect when process is killed
    session.on("detached", on_session_detached)

    # 3) Load script pre-resume
    script = session.create_script(js_code)
    script.on("message", on_frida_message)
    script.set_log_handler(on_frida_log)  # Capture console.log() output
    script.load()

    # Save state
    session_cache["pid"] = str(pid)
    session_cache["session"] = session
    session_cache["session_id"] = session_id
    session_cache["script"] = script

    # 4) Resume process
    device.resume(pid)

    # Optional: small delay to let early Java hooks log
    time.sleep(0.25)

    return {
        "pid": pid,
        "session_id": session_id,
        "identifier": identifier,
        "status": "attached_pre_resume_loaded"
    }


def on_frida_log(level, text):
    """
    Handle console.log() output from Frida scripts.
    This is separate from on_frida_message which handles send() calls.

    Args:
        level: Log level ('info', 'warning', 'error')
        text: The log message text
    """
    print(f"📋 [Frida Console.log] [{level}] {text}")

    # Map Frida log levels to our types
    type_map = {
        'info': 'log',
        'warning': 'warn',
        'error': 'error'
    }
    msg_type = type_map.get(level, 'log')

    evt = {
        "type": msg_type,
        "payload": text,
        "message": text
    }

    # Store in console buffer AND emit via Socket.IO
    session_id = session_cache.get("session_id")
    if session_id:
        try:
            add_console_message(session_id, text, msg_type)

            # Emit via Socket.IO for real-time updates
            if socketio:
                try:
                    # Broadcast to ALL clients in namespace (no room parameter = broadcast)
                    # This works from outside request context unlike broadcast=True
                    socketio.emit("frida_output", evt, namespace=FRIDA_NS)
                    print(f"[Socket.IO] Emitted frida_output to all clients: {text[:50]}...")
                except Exception as emit_err:
                    print(f"[Socket.IO] Emit error in log handler: {emit_err}")
        except Exception as e:
            print(f"[Console] Error adding log message to buffer: {e}")


def on_frida_message(message, data):
    print(f"🔥 [Frida Message Raw] {message}")

    evt = None

    # Handle different message types from Frida
    if isinstance(message, dict):
        msg_type_raw = message.get('type', '')

        if msg_type_raw == 'send':
            payload = message.get('payload', '')

            # Handle JSON string payloads
            if isinstance(payload, str):
                if payload.strip().startswith('{') and payload.strip().endswith('}'):
                    try:
                        import json
                        parsed_payload = json.loads(payload)
                        if isinstance(parsed_payload, dict):
                            msg_type = parsed_payload.get('type', 'log')
                            message_text = parsed_payload.get('message',
                                            parsed_payload.get('payload',
                                            str(parsed_payload)))
                        else:
                            msg_type = 'log'
                            message_text = payload
                    except json.JSONDecodeError:
                        msg_type = 'log'
                        message_text = payload
                else:
                    msg_type = 'log'
                    message_text = payload
            elif isinstance(payload, dict):
                msg_type = payload.get('type', 'log')
                message_text = payload.get('message',
                                payload.get('payload',
                                str(payload)))
            else:
                msg_type = 'log'
                message_text = str(payload)

            evt = {
                "type": msg_type,
                "payload": message_text,
                "message": message_text
            }

        elif msg_type_raw == 'log':
            # Handle console.log() output from Frida scripts
            # The 'payload' contains the log level and message
            log_payload = message.get('payload', '')
            if isinstance(log_payload, str):
                message_text = log_payload
            else:
                message_text = str(log_payload)

            # Determine log type from level if available
            level = message.get('level', 'info')
            if level == 'warning':
                msg_type = 'warn'
            elif level == 'error':
                msg_type = 'error'
            else:
                msg_type = 'log'

            evt = {
                "type": msg_type,
                "payload": message_text,
                "message": message_text
            }

        elif msg_type_raw == 'error':
            error_desc = message.get('description', 'Unknown error')
            error_stack = message.get('stack', '')
            error_msg = f"{error_desc}"
            if error_stack:
                error_msg += f"\n{error_stack}"

            evt = {
                "type": "error",
                "payload": error_msg,
                "message": error_msg
            }

        else:
            # Handle any other message type
            evt = {
                "type": "info",
                "payload": str(message),
                "message": str(message)
            }
    else:
        evt = {
            "type": "info",
            "payload": str(message),
            "message": str(message)
        }

    # Store in console buffer AND emit via Socket.IO
    if evt:
        session_id = session_cache.get("session_id")
        if session_id:
            print(f"[Console] Adding message to buffer for session {session_id}: {evt['message'][:100]}")
            try:
                add_console_message(session_id, evt["message"], evt["type"])

                # Emit via Socket.IO for real-time updates
                if socketio:
                    try:
                        # Broadcast to ALL clients in namespace (no room parameter = broadcast)
                        # This works from outside request context unlike broadcast=True
                        socketio.emit("frida_output", evt, namespace=FRIDA_NS)
                        print(f"[Socket.IO] Emitted frida_output to all clients: {evt['message'][:50]}...")
                    except Exception as emit_err:
                        print(f"[Socket.IO] Emit error: {emit_err}")
            except Exception as e:
                print(f"[Console] Error adding message to buffer: {e}")
        else:
            print(f"[Console] No session_id, message not stored: {evt['message'][:50]}")


def inject_script(js_code: str):
    """
    Injects JavaScript into the attached process.
    """
    print(f"[DEBUG] inject_script called with {len(js_code)} chars")
    
    if not session_cache.get("pid"):
        raise RuntimeError("No process attached")

    # Check if session is still valid
    if not session_cache["session"]:
        print("[DEBUG] No active session, reattaching...")
        attach_to_process(session_cache["pid"])

    # Unload previous script if exists
    if session_cache["script"]:
        try:
            print("[DEBUG] Unloading previous script")
            session_cache["script"].unload()
        except Exception as e:
            print(f"[DEBUG] Error unloading previous script (may be expected): {e}")

    try:
        print("[DEBUG] Creating new script")
        script = session_cache["session"].create_script(js_code)
        script.on("message", on_frida_message)
        script.set_log_handler(on_frida_log)  # Capture console.log() output
        print("[DEBUG] Loading script")
        script.load()
        session_cache["script"] = script
        print("[DEBUG] Script loaded successfully")
        
        # Wait briefly for script initialization and any immediate messages
        import time
        time.sleep(0.3)
        
        # Send verification message to ensure room connection is working
        if session_cache.get("session_id") and socketio:
            test_message = {
                "type": "success",
                "payload": "Script loaded and ready for output",
                "message": "Script loaded and ready for output"
            }
            print(f"[Socket] Sending verification message to room {session_cache['session_id']}")
            
            # Emit to both namespace and default for maximum compatibility
            try:
                socketio.emit("console_output", test_message, namespace=FRIDA_NS, room=session_cache["session_id"])
                print(f"[Socket] Verification message sent to /frida namespace")
                
                # Also try without namespace as backup
                socketio.emit("console_output", test_message, room=session_cache["session_id"])
                print(f"[Socket] Verification message sent to default namespace")
                
            except Exception as emit_error:
                print(f"[Socket] Error sending verification message: {emit_error}")
            
        return True
    except Exception as e:
        print(f"[ERROR] Script injection failed: {e}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        raise RuntimeError(f"Script injection failed: {e}")



# Add helper function to get current session info
def get_current_session_info():
    pid = session_cache.get("pid")
    session = session_cache.get("session")
    session_id = session_cache.get("session_id")
    name = session_cache.get("name")

    if pid and session:
        if hasattr(session, 'is_detached') and session.is_detached:
            # clear stale session
            session_cache["pid"] = None
            session_cache["session"] = None
            session_cache["script"] = None
            session_cache["session_id"] = None
            session_cache["name"] = None

            return {
                "pid": None,
                "session_id": None,
                "name": None,
                "session_active": False,
                "status": "detached"
            }

        return {
            "pid": pid,
            "session_id": session_id,
            "name": name,
            "session_active": True,
            "status": "attached"
        }

    return {
        "pid": None,
        "session_id": None,
        "name": None,
        "session_active": False,
        "status": "detached"
    }


# Keep existing functions unchanged
def load_frida_script(pid, script_code):
    if pid not in sessions:
        session = attach_to_process(pid)
    else:
        session = sessions[pid]

    script = session.create_script(script_code)
    script.on("message", on_frida_message)
    script.set_log_handler(on_frida_log)  # Capture console.log() output
    script.load()

def attach_to_process_by_name(name: str):
    """
    Attach to a process by package name (exact match).
    This is now just an alias for attach_to_process since it handles both cases.
    """
    return attach_to_process(name)

def debug_list_processes():
    """
    Debug function to list all processes that Frida can see
    """
    try:
        device = get_selected_device()
        processes = device.enumerate_processes()
        
        print(f"[DEBUG] Found {len(processes)} processes:")
        print(f"[DEBUG] {'PID':<8} {'Name'}")
        print(f"[DEBUG] {'-' * 50}")
        
        for proc in processes:
            print(f"[DEBUG] {proc.pid:<8} {proc.name}")
            
        return processes
    except Exception as e:
        print(f"[DEBUG] Error listing processes: {e}")
        return []

def debug_list_applications():
    """
    Debug function to list all applications that can be spawned
    """
    try:
        device = get_selected_device()
        applications = device.enumerate_applications()
        
        print(f"[DEBUG] Found {len(applications)} applications:")
        print(f"[DEBUG] {'Identifier':<30} {'Name'}")
        print(f"[DEBUG] {'-' * 70}")
        
        for app in applications:
            print(f"[DEBUG] {app.identifier:<30} {app.name}")
            
        return applications
    except Exception as e:
        print(f"[DEBUG] Error listing applications: {e}")
        return []