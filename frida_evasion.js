'use strict';

/**
 * Anti-detection Frida script.
 * Hides frida-server from /proc/maps, bypasses ptrace checks,
 * spoofs Build properties, and defeats common anti-Frida heuristics.
 */

// ── Hide Frida from /proc/self/maps ──────────────────────────────
function hideFromMaps() {
    var origOpen = Module.findExportByName(null, 'open');
    var origRead = Module.findExportByName(null, 'read');

    if (origOpen && origRead) {
        Interceptor.attach(origOpen, {
            onEnter: function(args) {
                this.path = args[0].readCString();
                this.isMaps = this.path && this.path.indexOf('maps') !== -1;
            },
            onLeave: function(retval) {}
        });

        Interceptor.attach(origRead, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.toInt32() || retval.toInt32() <= 0) return;
                try {
                    var buf = args[1];
                    var size = retval.toInt32();
                    var content = buf.readCString(size);
                    if (content && (content.indexOf('frida') !== -1 || content.indexOf('gadget') !== -1 || content.indexOf('gmain') !== -1)) {
                        var lines = content.split('\n');
                        var filtered = lines.filter(function(line) {
                            return line.indexOf('frida') === -1 &&
                                   line.indexOf('gadget') === -1 &&
                                   line.indexOf('gmain') === -1 &&
                                   line.indexOf('linjector') === -1;
                        });
                        var newContent = filtered.join('\n');
                        var newBytes = Memory.allocUtf8String(newContent);
                        Memory.copy(buf, newBytes, newContent.length);
                        retval.replace(newContent.length);
                    }
                } catch (e) {}
            }
        });
    }
}

// ── Bypass ptrace anti-debug ──────────────────────────────────────
function bypassPtrace() {
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                this.request = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.request === 0) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }
}

// ── Bypass strstr-based Frida detection ───────────────────────────
function bypassStrstr() {
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function(args) {
                this.haystack = args[0];
                this.needle = args[1];
                try {
                    var needleStr = this.needle.readCString();
                    if (needleStr && (
                        needleStr.indexOf('frida') !== -1 ||
                        needleStr.indexOf('FRIDA') !== -1 ||
                        needleStr.indexOf('gadget') !== -1 ||
                        needleStr.indexOf('LIBFRIDA') !== -1
                    )) {
                        this.shouldBlock = true;
                    } else {
                        this.shouldBlock = false;
                    }
                } catch (e) {
                    this.shouldBlock = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr(0));
                }
            }
        });
    }
}

// ── Bypass pthread_create Frida thread check ──────────────────────
function bypassPthreadCreate() {
    var pthreadCreate = Module.findExportByName('libc.so', 'pthread_create');
    if (pthreadCreate) {
        Interceptor.attach(pthreadCreate, {
            onEnter: function(args) {
                try {
                    var funcPtr = args[2];
                    var module = Process.findModuleByAddress(funcPtr);
                    if (module && module.name.indexOf('frida') !== -1) {
                        args[2] = new NativeCallback(function() {
                            return 0;
                        }, 'int', []);
                    }
                } catch (e) {}
            }
        });
    }
}

// ── Spoof Android Build properties via Frida Java hooks ───────────
function spoofBuildProperties() {
    Java.perform(function() {
        try {
            var Build = Java.use('android.os.Build');
            Build.FINGERPRINT.value = 'samsung/r0qxxx/r0q:13/TP1A.220624.014/G991BXXUDFUE1:user/release-keys';
            Build.MODEL.value = 'SM-G991B';
            Build.MANUFACTURER.value = 'samsung';
            Build.BRAND.value = 'samsung';
            Build.DEVICE.value = 'r0q';
            Build.PRODUCT.value = 'r0qxxx';
            Build.HARDWARE.value = 'exynos2100';
            Build.BOARD.value = 'exynos2100';
            Build.HOST.value = '219KFXHRC99';
            Build.TAGS.value = 'release-keys';
            Build.TYPE.value = 'user';
        } catch (e) {}

        try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                if (key === 'ro.product.model') return 'SM-G991B';
                if (key === 'ro.product.manufacturer') return 'samsung';
                if (key === 'ro.product.brand') return 'samsung';
                if (key === 'ro.product.device') return 'r0q';
                if (key === 'ro.hardware') return 'exynos2100';
                if (key === 'ro.build.display.id') return 'TP1A.220624.014';
                if (key === 'ro.board.platform') return 'exynos2100';
                if (key === 'qemu.hw.mainkeys') return '0';
                if (key === 'ro.kernel.qemu') return '0';
                if (key === 'init.svc.qemud') return 'stopped';
                if (key === 'init.svc.qemu-props') return 'stopped';
                return this.get(key);
            };
        } catch (e) {}
    });
}

// ── Bypass /proc/self/status TracerPid check ──────────────────────
function bypassTracerPid() {
    Interceptor.attach(Module.findExportByName(null, 'fopen'), {
        onEnter: function(args) {
            this.path = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf('status') !== -1) {
                try {
                    var stream = retval;
                    var origRead = Module.findExportByName(null, 'fgets');
                    if (origRead) {
                        Interceptor.attach(origRead, {
                            onEnter: function(args) {
                                this.buf = args[0];
                                this.size = args[1].toInt32();
                                this.stream = args[2];
                            },
                            onLeave: function(retval) {
                                if (this.stream.equals(stream)) {
                                    try {
                                        var line = this.buf.readCString();
                                        if (line && line.indexOf('TracerPid:') !== -1) {
                                            var fake = 'TracerPid:\t0\n';
                                            Memory.writeUtf8String(this.buf, fake);
                                        }
                                    } catch (e) {}
                                }
                            }
                        });
                    }
                } catch (e) {}
            }
        }
    });
}

// ── Bypass common root detection libraries ────────────────────────
function bypassRootDetection() {
    Java.perform(function() {
        try {
            var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            RootBeer.isRooted.implementation = function() {
                return false;
            };
        } catch (e) {}

        try {
            var RootBeerGeneric = Java.use('com.scottyab.rootbeer.RootBeerGeneric');
            RootBeerGeneric.isRooted.implementation = function() {
                return false;
            };
        } catch (e) {}

        try {
            var RootUtils = Java.use('eu.chainfire.libsuperuser.Shell');
            Shell.SU.available.implementation = function() {
                return false;
            };
        } catch (e) {}
    });
}

// ── Bypass SafetyNet / Play Integrity ─────────────────────────────
function bypassSafetyNet() {
    Java.perform(function() {
        try {
            var SafetyNetApi = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
            SafetyNetApi.attest.implementation = function(client, nonce) {
                return null;
            };
        } catch (e) {}

        try {
            var PlayIntegrity = Java.use('com.google.android.play.core.integrity.IntegrityManager');
        } catch (e) {}
    });
}

// ── Init ──────────────────────────────────────────────────────────
setTimeout(function() {
    try { hideFromMaps(); } catch(e) {}
    try { bypassPtrace(); } catch(e) {}
    try { bypassStrstr(); } catch(e) {}
    try { bypassPthreadCreate(); } catch(e) {}
    try { spoofBuildProperties(); } catch(e) {}
    try { bypassTracerPid(); } catch(e) {}
    try { bypassRootDetection(); } catch(e) {}
    try { bypassSafetyNet(); } catch(e) {}
    send({type: 'evasion', data: 'Anti-detection hooks loaded'});
}, 0);
