// src/cybershadow_dyn.js
'use strict';

/**
 * CyberShadow dynamic hooks (real device robust)
 * Key changes:
 * - Do NOT rely on Java.available alone. We retry Java.perform() until success or timeout.
 * - Native hooks: avoid Module.findExportByName; use Process.getModuleByName("libdl.so") fallback.
 * - emit() uses send() primarily (console.log kept for manual debug).
 */

function now() { try { return new Date().toISOString(); } catch (e) { return ""; } }
function s(x) { try { return (x === null || x === undefined) ? ("" + x) : x.toString(); } catch (e) { return "[toString_error]"; } }

function emit(tag, msg) {
  // Keep console for manual runs
  try { console.log("[" + now() + "][" + tag + "] " + msg); } catch (e) {}
  // Machine-friendly channel (used by python tool)
  try { send({ ts: now(), tag: tag, msg: msg }); } catch (e2) {}
}

function diagBoot() {
  try {
    emit("BOOT", "pid=" + Process.id + " arch=" + Process.arch + " platform=" + Process.platform + " ptr=" + Process.pointerSize);
  } catch (e) {
    emit("BOOT", "Process info unavailable: " + s(e));
  }

  // ART indicator
  try {
    if (Process.enumerateModules) {
      var mods = Process.enumerateModules();
      var hasArt = false;
      for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf("libart.so") !== -1) { hasArt = true; break; }
      }
      emit("BOOT", "libart.so loaded=" + hasArt);
    }
  } catch (e) {}
}

// ----------------------------
// Native hooks (dlopen/android_dlopen_ext) - best effort without Module.findExportByName
// ----------------------------

function _findExportFallback(moduleName, exportName) {
  // Try Module.findExportByName if present; fallback to Process.getModuleByName(...).findExportByName(...)
  try {
    if (typeof Module !== "undefined" && Module.findExportByName) {
      return Module.findExportByName(null, exportName);
    }
  } catch (e) {}

  try {
    if (Process.getModuleByName) {
      var m = Process.getModuleByName(moduleName);
      if (m && m.findExportByName) return m.findExportByName(exportName);
    }
  } catch (e2) {}

  return null;
}

function hookDlopen() {
  try {
    var ptrAndroid = _findExportFallback("libdl.so", "android_dlopen_ext");
    var ptrDlopen = _findExportFallback("libdl.so", "dlopen");

    if (!ptrAndroid && !ptrDlopen) {
      emit("WARN", "dlopen exports not found; native load hooks skipped.");
      return;
    }

    function attachFn(ptr, name) {
      if (!ptr) return;
      Interceptor.attach(ptr, {
        onEnter: function (args) {
          try {
            var path = args[0] ? Memory.readCString(args[0]) : "";
            emit("NATIVE", name + "(" + s(path) + ")");
          } catch (e) {}
        }
      });
      emit("HOOK", "Native hook installed: " + name);
    }

    attachFn(ptrAndroid, "android_dlopen_ext");
    attachFn(ptrDlopen, "dlopen");

  } catch (e) {
    emit("WARN", "Native dlopen hook failed: " + s(e));
  }
}

// ----------------------------
// Java hooks (installed once we manage to enter Java.perform)
// ----------------------------

function installJavaHooks() {
  // DNS
  try {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getByName.implementation = function (host) {
      emit("DNS", "getByName " + s(host));
      return this.getByName(host);
    };
    emit("HOOK", "InetAddress.getByName hooked");
  } catch (e) {
    emit("HOOK", "InetAddress hook failed: " + s(e));
  }

  // Socket.connect (IP:port)
  try {
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
      emit("SOCKET", "connect " + s(addr) + " timeout=" + timeout);
      return this.connect(addr, timeout);
    };
    emit("HOOK", "Socket.connect hooked");
  } catch (e) {}

  // WebView URLs
  try {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
      emit("WEBVIEW", "loadUrl " + s(url));
      return this.loadUrl(url);
    };
    emit("HOOK", "WebView.loadUrl hooked");
  } catch (e) {}

  // Runtime.exec
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      emit("PROC", "Runtime.exec " + s(cmd));
      return this.exec(cmd);
    };
    emit("HOOK", "Runtime.exec hooked");
  } catch (e) {
    emit("HOOK", "Runtime.exec hook failed: " + s(e));
  }

  emit("READY", "Java hooks loaded. Interact with the app now.");
}

// ----------------------------
// Java.perform retry loop (do not trust Java.available)
// ----------------------------

function tryInstallJavaHooksWithRetry(maxMs, intervalMs) {
  var start = Date.now();
  var installed = false;

  function tick() {
    if (installed) return;

    // periodic status
    try {
      if (((Date.now() - start) % 5000) < intervalMs) {
        emit("BOOT", "trying Java.perform... elapsedMs=" + (Date.now() - start) + " Java.available=" + (typeof Java !== "undefined" ? Java.available : "noJavaObj"));
      }
    } catch (e0) {}

    try {
      // Even if Java.available is false, this may start working later.
      Java.perform(function () {
        if (installed) return;
        installed = true;
        installJavaHooks();
      });
      return; // success path
    } catch (e) {
      // keep retrying
    }

    if ((Date.now() - start) >= maxMs) {
      emit("ERR", "Java.perform never became available within timeout; running native-only.");
      return;
    }
    setTimeout(tick, intervalMs);
  }

  tick();
}

// ----------------------------
// Entry point
// ----------------------------

setImmediate(function () {
  emit("BOOT", "Script loaded.");
  diagBoot();
  hookDlopen();
  // try for 90s, polling 250ms
  tryInstallJavaHooksWithRetry(90000, 250);
});
