import sqlite3
import os
import time

def init_script_db():
    """Initialize the scripts database"""
    conn = sqlite3.connect('frida_scripts.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS frida_scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            code TEXT NOT NULL,
            platform TEXT DEFAULT 'all',
            tags TEXT,
            difficulty TEXT DEFAULT 'beginner',
            filename TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.close()

def seed_script_library():
    """Add some default useful scripts"""
    scripts = [
        {
            "name": "Universal SSL Pinning Bypass",
            "category": "Security", 
            "platform": "android",
            "difficulty": "intermediate",
            "description": "Auto-detects runtime and bypasses SSL pinning on Android",
            "code": '''// Universal SSL Pinning Bypass with Runtime Detection
if (typeof Java !== 'undefined') {
    Java.perform(function() {
        send({type: "info", message: "Android Java runtime detected - setting up SSL bypass"});
        
        // Hook TrustManagerImpl
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                send({type: "success", message: "SSL Pinning bypassed via TrustManagerImpl"});
                return;
            };
        } catch(e) {
            send({type: "error", message: "TrustManagerImpl hook failed: " + e});
        }
        
        // Hook OkHttp CertificatePinner
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
                send({type: "success", message: "SSL Pinning bypassed via OkHttp"});
                return;
            };
        } catch(e) {
            send({type: "info", message: "OkHttp CertificatePinner not found - may not be used by this app"});
        }
    });
} else {
    send({type: "warn", message: "Java runtime not available - cannot bypass SSL pinning"});
    send({type: "info", message: "This script requires an Android app process with Java runtime"});
}'''
        },
        {
            "name": "Universal Root Detection Bypass",
            "category": "Security",
            "platform": "android", 
            "difficulty": "beginner",
            "description": "Auto-detects runtime and bypasses common root detection",
            "code": '''// Universal Root Detection Bypass with Runtime Detection
if (typeof Java !== 'undefined') {
    Java.perform(function() {
        send({type: "info", message: "Android Java runtime detected - setting up root bypass"});
        
        // Hook RootBeer library
        try {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            RootBeer.isRooted.implementation = function() {
                send({type: "success", message: "Root detection bypassed via RootBeer.isRooted"});
                return false;
            };
        } catch(e) {
            send({type: "info", message: "RootBeer library not found - app may not use it"});
        }
        
        // Hook Runtime.exec for su commands
        try {
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function(commands) {
                if (commands && commands.length > 0 && commands[0].includes("su")) {
                    send({type: "success", message: "Blocked su command execution"});
                    throw Java.use("java.io.IOException").$new("Command not found");
                }
                return this.exec(commands);
            };
        } catch(e) {
            send({type: "error", message: "Runtime.exec hook failed: " + e});
        }
    });
} else {
    send({type: "warn", message: "Java runtime not available - cannot bypass root detection"});
    send({type: "info", message: "This script requires an Android app process with Java runtime"});
}'''
        },
        {
            "name": "Universal Method Logger",
            "category": "Debugging",
            "platform": "all",
            "difficulty": "beginner", 
            "description": "Auto-detects runtime and logs method calls appropriately",
            "code": '''// Universal Method Logger with Runtime Detection
if (typeof Java !== 'undefined') {
    Java.perform(function() {
        send({type: "info", message: "Java runtime detected - Android method logging available"});
        
        // Replace 'com.example.TargetClass' with your target class
        var targetClass = "com.example.TargetClass";
        
        try {
            var TargetClass = Java.use(targetClass);
            var methods = TargetClass.class.getDeclaredMethods();
            
            send({type: "info", message: "Found " + methods.length + " methods in " + targetClass});
            
            methods.forEach(function(method) {
                var methodName = method.getName();
                try {
                    TargetClass[methodName].implementation = function() {
                        send({type: "info", message: "Called: " + targetClass + "." + methodName});
                        return this[methodName].apply(this, arguments);
                    };
                } catch(e) {
                    // Some methods might not be hookable
                }
            });
            
        } catch(e) {
            send({type: "error", message: "Failed to hook " + targetClass + ": " + e});
            send({type: "info", message: "Make sure the class name is correct and the app uses it"});
        }
    });
} else {
    send({type: "info", message: "Native process detected - using native function logging"});
    
    // Native process monitoring
    send({type: "info", message: "Process: " + Process.id + " (" + Process.platform + ", " + Process.arch + ")"});
    
    var modules = Process.enumerateModules();
    send({type: "info", message: "Loaded modules: " + modules.length});
    
    // List first few modules
    modules.slice(0, 5).forEach(function(module) {
        send({type: "info", message: "Module: " + module.name + " @ " + module.base});
    });
    
    // Example: Hook malloc for native processes
    try {
        var mallocPtr = Module.findExportByName(null, "malloc");
        if (mallocPtr) {
            Interceptor.attach(mallocPtr, {
                onEnter: function(args) {
                    this.size = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (this.size > 10240) { // Log allocations > 10KB
                        send({type: "info", message: "Large malloc(" + this.size + ") = " + retval});
                    }
                }
            });
            send({type: "success", message: "Native malloc hook installed"});
        }
    } catch(e) {
        send({type: "error", message: "Native malloc hook failed: " + e});
    }
}'''
        },
        {
            "name": "Runtime Detector", 
            "category": "Debugging",
            "platform": "all",
            "difficulty": "beginner",
            "description": "Detects available runtime APIs and suggests appropriate hooks",
            "code": '''// Runtime Detection and Capability Assessment
send({type: "info", message: "=== Runtime Detection Started ==="});

// Check Java runtime
if (typeof Java !== 'undefined') {
    send({type: "success", message: "✓ Java runtime available - Android app process"});
    
    Java.perform(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var app = ActivityThread.currentApplication();
            if (app) {
                send({type: "info", message: "App package: " + app.getPackageName()});
            }
            
            // Check for common frameworks
            try {
                Java.use("okhttp3.OkHttpClient");
                send({type: "info", message: "✓ OkHttp library detected"});
            } catch(e) {
                send({type: "info", message: "✗ OkHttp library not found"});
            }
            
            try {
                Java.use("com.scottyab.rootbeer.RootBeer");
                send({type: "info", message: "✓ RootBeer library detected"});
            } catch(e) {
                send({type: "info", message: "✗ RootBeer library not found"});
            }
            
        } catch(e) {
            send({type: "warn", message: "Java available but Android context limited: " + e});
        }
    });
} else {
    send({type: "warn", message: "✗ Java runtime not available - native process"});
}

// Check ObjC runtime (iOS/macOS)
if (typeof ObjC !== 'undefined') {
    send({type: "success", message: "✓ ObjC runtime available - iOS/macOS process"});
    send({type: "info", message: "Available classes: " + Object.keys(ObjC.classes).length});
} else {
    send({type: "info", message: "✗ ObjC runtime not available"});
}

// Native APIs (always available)
send({type: "success", message: "✓ Native APIs available"});
send({type: "info", message: "Platform: " + Process.platform + " (" + Process.arch + ")"});
send({type: "info", message: "Process ID: " + Process.id});

var modules = Process.enumerateModules();
send({type: "info", message: "Loaded modules: " + modules.length});

// Show some key modules
var keyModules = modules.filter(function(m) {
    return m.name.includes("libc") || m.name.includes("ssl") || 
           m.name.includes("crypto") || m.name.includes("android");
});

if (keyModules.length > 0) {
    send({type: "info", message: "Key modules found:"});
    keyModules.forEach(function(module) {
        send({type: "info", message: "  " + module.name + " @ " + module.base});
    });
}

// Suggest appropriate hooks based on detected runtime
send({type: "info", message: "=== Recommendations ==="});
if (typeof Java !== 'undefined') {
    send({type: "info", message: "💡 Use Java.use() for Android app hooks"});
    send({type: "info", message: "💡 Try SSL pinning bypass, root detection bypass"});
} else if (Process.platform === 'darwin') {
    send({type: "info", message: "💡 Use ObjC hooks for iOS/macOS apps"});
} else {
    send({type: "info", message: "💡 Use Interceptor.attach() for native function hooks"});
    send({type: "info", message: "💡 Try hooking libc functions, system calls"});
}

send({type: "info", message: "=== Detection Complete ==="});'''
        }
    ]
    
    conn = sqlite3.connect('frida_scripts.db')
    for script in scripts:
        # Check if already exists
        existing = conn.execute('SELECT id FROM frida_scripts WHERE name = ?', (script['name'],)).fetchone()
        if not existing:
            conn.execute('''
                INSERT INTO frida_scripts (name, category, description, code, platform, difficulty)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (script['name'], script['category'], script['description'], 
                  script['code'], script['platform'], script['difficulty']))
    conn.commit()
    conn.close()



    

class ScriptDatabase:
    """Database operations for scripts"""
    
    @staticmethod
    def get_all_scripts(category='all', platform='all'):
        conn = sqlite3.connect('frida_scripts.db')
        conn.row_factory = sqlite3.Row
        
        query = "SELECT * FROM frida_scripts WHERE 1=1"
        params = []
        
        if category != 'all':
            query += " AND category = ?"
            params.append(category)
            
        query += " ORDER BY category, name"
        
        scripts = conn.execute(query, params).fetchall()
        conn.close()
        
        return [dict(script) for script in scripts]
    
    @staticmethod
    def get_script_by_id(script_id):
        conn = sqlite3.connect('frida_scripts.db')
        conn.row_factory = sqlite3.Row
        script = conn.execute('SELECT * FROM frida_scripts WHERE id = ?', (script_id,)).fetchone()
        conn.close()
        
        return dict(script) if script else None
    
    @staticmethod
    def add_script(name, category, description, code, platform='all', difficulty='beginner', filename=None):
        conn = sqlite3.connect('frida_scripts.db')
        cursor = conn.execute('''
            INSERT INTO frida_scripts (name, category, description, code, platform, difficulty, filename)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, category, description, code, platform, difficulty, filename))
        
        script_id = cursor.lastrowid  # ✅ This works now
        conn.commit()
        conn.close()
        
        return script_id

    
    @staticmethod
    def import_from_folder(scripts_dir='scripts'):
        """Import all .js files from a folder"""
        if not os.path.exists(scripts_dir):
            return {"imported": 0, "errors": ["Scripts folder not found"]}
        
        imported = 0
        errors = []
        
        conn = sqlite3.connect('frida_scripts.db')
        
        for filename in os.listdir(scripts_dir):
            if filename.endswith('.js'):
                try:
                    filepath = os.path.join(scripts_dir, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        code = f.read()
                    
                    name = os.path.splitext(filename)[0].replace('_', ' ').replace('-', ' ').title()
                    
                    # Check if already exists
                    existing = conn.execute('SELECT id FROM frida_scripts WHERE filename = ?', (filename,)).fetchone()
                    if not existing:
                        conn.execute('''
                            INSERT INTO frida_scripts (name, category, description, code, platform, filename)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (name, 'Imported', f'Imported from {filename}', code, 'all', filename))
                        imported += 1
                    
                except Exception as e:
                    errors.append(f"{filename}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        return {"imported": imported, "errors": errors}