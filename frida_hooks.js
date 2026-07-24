/**
 * frida_hooks.js — Dynamic behavioral capture for Android malware analysis.
 *
 * Writes structured JSON lines to:
 *   /data/local/tmp/frida_events.jsonl
 * and a human-readable mirror to:
 *   /data/local/tmp/frida.log
 *
 * Usage:
 *   frida -U -f <package> -l frida_hooks.js --no-pause
 *   frida -U -n <process> -l frida_hooks.js
 */

"use strict";

var JSONL_PATH = "/data/local/tmp/frida_events.jsonl";
var LOG_PATH = "/data/local/tmp/frida.log";
var jsonlFile = null;
var logFile = null;
var hookCount = 0;

function nowMs() {
    return Date.now();
}

function emit(event, fields) {
    var obj = fields || {};
    obj.event = event;
    obj.timestamp = nowMs();
    obj.pid = Process.id;
    try {
        obj.tid = Process.getCurrentThreadId();
    } catch (e) {
        obj.tid = 0;
    }
    var line = JSON.stringify(obj);
    try {
        if (jsonlFile !== null) {
            jsonlFile.write(line + "\n");
            jsonlFile.flush();
        }
    } catch (e) {}
    try {
        if (logFile !== null) {
            logFile.write("[" + new Date().toISOString() + "] [" + event + "] " + line + "\n");
            logFile.flush();
        }
    } catch (e) {}
    try {
        console.log(line);
    } catch (e) {}
}

function initLogs() {
    try {
        jsonlFile = new File(JSONL_PATH, "a");
    } catch (e) {
        jsonlFile = null;
    }
    try {
        logFile = new File(LOG_PATH, "a");
    } catch (e) {
        logFile = null;
    }
    emit("init", {
        arch: Process.arch,
        platform: Process.platform,
        message: "Frida hooks loaded"
    });
}

function safeStr(v) {
    try {
        if (v === null || v === undefined) return "";
        return v.toString();
    } catch (e) {
        return "";
    }
}

function hookJava() {
    Java.perform(function () {
        // Activity lifecycle
        try {
            var Activity = Java.use("android.app.Activity");
            Activity.onCreate.overload("android.os.Bundle").implementation = function (b) {
                emit("api", { name: "Activity.onCreate", class: this.getClass().getName() });
                return this.onCreate(b);
            };
            hookCount += 1;
        } catch (e) {
            emit("error", { name: "Activity.onCreate", message: e.message });
        }

        // Network: URL
        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload("java.lang.String").implementation = function (u) {
                emit("network", { url: safeStr(u), method: "URL" });
                return this.$init(u);
            };
            hookCount += 1;
        } catch (e) {}

        // Network: HttpURLConnection
        try {
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            HttpURLConnection.connect.implementation = function () {
                try {
                    emit("network", {
                        url: safeStr(this.getURL()),
                        method: safeStr(this.getRequestMethod())
                    });
                } catch (e) {}
                return this.connect();
            };
            hookCount += 1;
        } catch (e) {}

        // OkHttp (common in modern apps)
        try {
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            RequestBuilder.url.overload("java.lang.String").implementation = function (u) {
                emit("network", { url: safeStr(u), method: "okhttp3" });
                return this.url(u);
            };
            hookCount += 1;
        } catch (e) {}

        // File I/O
        try {
            var File = Java.use("java.io.File");
            File.$init.overload("java.lang.String").implementation = function (p) {
                emit("file", { path: safeStr(p), op: "open" });
                return this.$init(p);
            };
            hookCount += 1;
        } catch (e) {}

        try {
            var FOS = Java.use("java.io.FileOutputStream");
            FOS.$init.overload("java.lang.String").implementation = function (p) {
                emit("file", { path: safeStr(p), op: "write" });
                return this.$init(p);
            };
            hookCount += 1;
        } catch (e) {}

        // Reflection
        try {
            var Class = Java.use("java.lang.Class");
            Class.forName.overload("java.lang.String").implementation = function (name) {
                emit("reflection", { class_name: safeStr(name), name: "Class.forName" });
                return this.forName(name);
            };
            hookCount += 1;
        } catch (e) {}

        try {
            var Method = Java.use("java.lang.reflect.Method");
            Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (obj, args) {
                emit("reflection", {
                    name: "Method.invoke",
                    method: safeStr(this.getName()),
                    class_name: safeStr(this.getDeclaringClass().getName())
                });
                return this.invoke(obj, args);
            };
            hookCount += 1;
        } catch (e) {}

        // Runtime exec
        try {
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                emit("exec", { name: "Runtime.exec", args: safeStr(cmd) });
                return this.exec(cmd);
            };
            Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmd) {
                var joined = [];
                try {
                    for (var i = 0; i < cmd.length; i++) joined.push(safeStr(cmd[i]));
                } catch (e) {}
                emit("exec", { name: "Runtime.exec[]", args: joined.join(" ") });
                return this.exec(cmd);
            };
            hookCount += 2;
        } catch (e) {}

        // Telephony / identifiers
        try {
            var TM = Java.use("android.telephony.TelephonyManager");
            var methods = [
                "getDeviceId", "getImei", "getSubscriberId", "getLine1Number",
                "getSimSerialNumber", "getNetworkOperator", "getNetworkOperatorName"
            ];
            methods.forEach(function (m) {
                try {
                    var overloads = TM[m].overloads;
                    overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var ret = ov.apply(this, arguments);
                            emit("telephony", { name: "TelephonyManager." + m, result: safeStr(ret) });
                            return ret;
                        };
                    });
                    hookCount += 1;
                } catch (e) {}
            });
        } catch (e) {}

        // SMS
        try {
            var SmsManager = Java.use("android.telephony.SmsManager");
            SmsManager.sendTextMessage.overload(
                "java.lang.String", "java.lang.String", "java.lang.String",
                "android.app.PendingIntent", "android.app.PendingIntent"
            ).implementation = function (dest, sc, text, sI, dI) {
                emit("sms", { name: "SmsManager.sendTextMessage", args: safeStr(dest) });
                return this.sendTextMessage(dest, sc, text, sI, dI);
            };
            hookCount += 1;
        } catch (e) {}

        // ContentResolver (contacts/sms/call log)
        try {
            var CR = Java.use("android.content.ContentResolver");
            CR.query.overload(
                "android.net.Uri", "[Ljava.lang.String;", "java.lang.String",
                "[Ljava.lang.String;", "java.lang.String"
            ).implementation = function (uri, proj, sel, selArgs, sort) {
                var u = safeStr(uri);
                var evt = "api";
                if (u.indexOf("sms") >= 0) evt = "sms";
                else if (u.indexOf("contacts") >= 0) evt = "contacts";
                else if (u.indexOf("call_log") >= 0) evt = "api";
                emit(evt, { name: "ContentResolver.query", args: u });
                return this.query(uri, proj, sel, selArgs, sort);
            };
            hookCount += 1;
        } catch (e) {}

        // Location
        try {
            var LM = Java.use("android.location.LocationManager");
            LM.getLastKnownLocation.implementation = function (provider) {
                var ret = this.getLastKnownLocation(provider);
                emit("location", {
                    name: "LocationManager.getLastKnownLocation",
                    args: safeStr(provider),
                    result: ret ? (ret.getLatitude() + "," + ret.getLongitude()) : "null"
                });
                return ret;
            };
            hookCount += 1;
        } catch (e) {}

        // Camera / mic
        try {
            var Camera = Java.use("android.hardware.Camera");
            Camera.open.overload().implementation = function () {
                emit("camera", { name: "Camera.open" });
                return this.open();
            };
            hookCount += 1;
        } catch (e) {}

        try {
            var MediaRecorder = Java.use("android.media.MediaRecorder");
            MediaRecorder.start.implementation = function () {
                emit("microphone", { name: "MediaRecorder.start" });
                return this.start();
            };
            hookCount += 1;
        } catch (e) {}

        // Clipboard
        try {
            var CM = Java.use("android.content.ClipboardManager");
            CM.getPrimaryClip.implementation = function () {
                emit("clipboard", { name: "ClipboardManager.getPrimaryClip" });
                return this.getPrimaryClip();
            };
            hookCount += 1;
        } catch (e) {}

        // Package enumeration
        try {
            var PM = Java.use("android.app.ApplicationPackageManager");
            PM.getInstalledPackages.overload("int").implementation = function (flags) {
                emit("package", { name: "PackageManager.getInstalledPackages", args: "" + flags });
                return this.getInstalledPackages(flags);
            };
            hookCount += 1;
        } catch (e) {}

        // DexClassLoader (droppers / packing)
        try {
            var DCL = Java.use("dalvik.system.DexClassLoader");
            DCL.$init.overload(
                "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
            ).implementation = function (dex, opt, lib, parent) {
                emit("api", {
                    name: "DexClassLoader",
                    args: safeStr(dex),
                    result: safeStr(opt)
                });
                return this.$init(dex, opt, lib, parent);
            };
            hookCount += 1;
        } catch (e) {}

        emit("hooks_ready", { hook_count: hookCount });
    });
}

function hookNative() {
    var names = ["open", "openat", "connect", "execve"];
    names.forEach(function (name) {
        try {
            var addr = Module.findExportByName(null, name);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var payload = { name: name };
                    try {
                        if (name === "open" || name === "openat") {
                            payload.path = args[name === "open" ? 0 : 1].readCString();
                            payload.event_hint = "file";
                        } else if (name === "execve") {
                            payload.path = args[0].readCString();
                            payload.event_hint = "exec";
                        } else if (name === "connect") {
                            payload.event_hint = "network";
                        }
                    } catch (e) {}
                    if (payload.event_hint === "file") {
                        emit("file", payload);
                    } else if (payload.event_hint === "exec") {
                        emit("exec", payload);
                    } else if (payload.event_hint === "network") {
                        emit("network", payload);
                    } else {
                        emit("api", payload);
                    }
                }
            });
            hookCount += 1;
        } catch (e) {}
    });
}

setTimeout(function () {
    initLogs();
    try {
        hookNative();
    } catch (e) {
        emit("error", { name: "hookNative", message: e.message });
    }
    try {
        hookJava();
    } catch (e) {
        emit("error", { name: "hookJava", message: e.message });
    }
}, 0);
