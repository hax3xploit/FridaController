from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
import sqlite3
from frida_ops import inject_script, session_cache, add_console_message
from database import ScriptDatabase

# Create scripts folder if it doesn't exist
os.makedirs('scripts', exist_ok=True)

script_library_bp = Blueprint('script_library', __name__)

@script_library_bp.route('/api/scripts', methods=['GET'])
def get_scripts():
    """Get all scripts, optionally filtered by category/platform"""
    category = request.args.get('category', 'all')
    platform = request.args.get('platform', 'all')
    
    scripts = ScriptDatabase.get_all_scripts(category, platform)
    return jsonify(scripts)

@script_library_bp.route('/api/scripts/<int:script_id>', methods=['GET'])
def get_script(script_id):
    """Get a specific script by ID"""
    script = ScriptDatabase.get_script_by_id(script_id)
    
    if script:
        return jsonify(script)
    return jsonify({"error": "Script not found"}), 404

@script_library_bp.route('/api/scripts/upload', methods=['POST'])
def upload_script():
    """Upload a single script file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file and file.filename.endswith('.js'):
        filename = secure_filename(file.filename)
        filepath = os.path.join('scripts', filename)
        file.save(filepath)
        
        # Read file content
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            return jsonify({"error": f"Failed to read file: {str(e)}"}), 400
        
        # Extract name from filename
        name = os.path.splitext(filename)[0].replace('_', ' ').replace('-', ' ').title()
        
        # Get additional info from form
        category = request.form.get('category', 'Custom')
        description = request.form.get('description', f'Uploaded script: {filename}')
        platform = request.form.get('platform', 'all')
        difficulty = request.form.get('difficulty', 'beginner')
        
        # Save to database
        try:
            script_id = ScriptDatabase.add_script(
                name, category, description, code, platform, difficulty, filename
            )
            return jsonify({
                "status": "ok", 
                "message": f"Script {filename} uploaded successfully",
                "script_id": script_id
            })
        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    return jsonify({"error": "Only .js files are allowed"}), 400

@script_library_bp.route('/api/scripts/import-folder', methods=['POST'])
def import_folder():
    """Import all .js files from the scripts/ folder"""
    result = ScriptDatabase.import_from_folder('scripts')
    
    return jsonify({
        "status": "ok",
        "imported": result["imported"],
        "errors": result["errors"],
        "message": f"Imported {result['imported']} scripts"
    })

@script_library_bp.route('/api/scripts/categories', methods=['GET'])
def get_categories():
    """Get all available script categories"""
    scripts = ScriptDatabase.get_all_scripts()
    categories = list(set(script['category'] for script in scripts))
    categories.sort()
    
    return jsonify({"categories": categories})


@script_library_bp.route('/api/scripts/<int:script_id>', methods=['DELETE'])
def delete_script(script_id):
    try:
        conn = sqlite3.connect('frida_scripts.db')
        cursor = conn.execute('DELETE FROM frida_scripts WHERE id = ?', (script_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "message": "Script deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



@script_library_bp.route('/api/load-multiple-scripts', methods=['POST'])
def load_multiple_scripts():
    """
    Inject multiple selected scripts into the active Frida session.
    Expects JSON: { "script_ids": [1, 2, 3] }
    """
    data = request.get_json(silent=True) or {}
    script_ids = data.get("script_ids", [])

    if not script_ids or not isinstance(script_ids, list):
        return jsonify({"status": "error", "message": "Invalid or missing script_ids"}), 400

    # Ensure we have an active session
    if not session_cache.get("pid") or not session_cache.get("session"):
        return jsonify({"status": "error", "message": "No active Frida session"}), 400

    try:
        # Fetch and combine scripts
        combined_code = ""
        loaded_names = []

        for sid in script_ids:
            script = ScriptDatabase.get_script_by_id(sid)
            if script:
                combined_code += f"\n// === {script['name']} ===\n{script['code']}\n"
                loaded_names.append(script['name'])

        if not combined_code.strip():
            return jsonify({"status": "error", "message": "No valid scripts found"}), 400

        # Inject combined script
        inject_script(combined_code)

        session_id = session_cache.get("session_id")
        msg = f"Injected {len(loaded_names)} scripts: {', '.join(loaded_names)}"
        add_console_message(session_id, msg, "success")

        return jsonify({
            "status": "ok",
            "message": msg,
            "script_count": len(loaded_names),
            "scripts": loaded_names
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500
