// src/cybershadow_dyn.js
'use strict';

const JS_VERSION = "2026-01-31-hardhooks-v2";

function nowIso() { try { return new Date().toISOString(); } catch (e) { return ""; } }
function emit(tag, msg) { try { send({ ts: nowIso(), tag: String(tag), msg: String(msg) }); } catch (e) {} }
function j2s(x) { try { return x === null || x === undefined ? "" : String(x); } catch (e) { return ""; } }

emit("SELFTEST", "js_version=" + JS_VERSION);
emit("BOOT", "Script loaded.");
try { emit("NATIVE", "proc=" + Process.name + " pid=" + Process.id); } catch (e) {}

setInterval(function () { emit("PING", "alive"); }, 2500);

Java.perform(function () {
  emit("READY", "Java runtime ready. js_version=" + JS_VERSION);

  // ACT lifecycle
  try {
    const Activity = Java.use("android.app.Activity");

    Activity.onCreate.overload("android.os.Bundle").implementation = function (b) {
      try { emit("ACT", "onCreate " + this.getClass().getName()); } catch (e) {}
      return this.onCreate(b);
    };

    Activity.onResume.implementation = function () {
      try { emit("ACT", "onResume " + this.getClass().getName()); } catch (e) {}
      return this.onResume();
    };

    Activity.onNewIntent.implementation = function (intent) {
      try { emit("ACT", "onNewIntent " + this.getClass().getName()); } catch (e) {}
      return this.onNewIntent(intent);
    };

    emit("HOOK", "Activity lifecycle hooks installed.");
  } catch (e) {
    emit("HOOK", "Activity lifecycle hook failed: " + e);
  }

  // PROC
  try {
    const Runtime = Java.use("java.lang.Runtime");
    const exec1 = Runtime.exec.overload("java.lang.String");
    exec1.implementation = function (cmd) {
      emit("PROC", "Runtime.exec " + j2s(cmd));
      return exec1.call(this, cmd);
    };

    const PB = Java.use("java.lang.ProcessBuilder");
    const pbStart = PB.start.overload();
    pbStart.implementation = function () {
      let c = "";
      try { c = this.command().toString(); } catch (e2) {}
      emit("PROC", "ProcessBuilder.start " + c);
      return pbStart.call(this);
    };

    emit("HOOK", "PROC hooks installed.");
  } catch (e) {
    emit("HOOK", "PROC hooks failed: " + e);
  }

  // FILE
  try {
    const File = Java.use("java.io.File");
    const del = File.delete.overload();
    del.implementation = function () {
      emit("FILE", "delete " + j2s(this.getAbsolutePath()));
      return del.call(this);
    };

    const FOS = Java.use("java.io.FileOutputStream");
    const i1 = FOS.$init.overload("java.lang.String");
    i1.implementation = function (path) {
      emit("FILE", "write-open " + j2s(path));
      return i1.call(this, path);
    };
    emit("HOOK", "FILE hooks installed.");
  } catch (e) {
    emit("HOOK", "FILE hooks failed: " + e);
  }

  // DLOAD
  try {
    const DexCL = Java.use("dalvik.system.DexClassLoader");
    DexCL.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader")
      .implementation = function (dexPath, optDir, libSearch, parent) {
        emit("DLOAD", `DexClassLoader dex=${j2s(dexPath)} opt=${j2s(optDir)}`);
        return this.$init(dexPath, optDir, libSearch, parent);
      };
    emit("HOOK", "DLOAD hooks installed.");
  } catch (e) {
    emit("HOOK", "DLOAD hooks failed: " + e);
  }

  // SMS query detection (light)
  try {
    const CR = Java.use("android.content.ContentResolver");
    const q = CR.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String");
    q.implementation = function (uri, proj, sel, args, sort) {
      try {
        const u = uri ? uri.toString() : "";
        if (u.startsWith("content://sms") || u.startsWith("content://mms-sms") || u.startsWith("content://mms")) {
          emit("SMS", "query " + u + " sel=" + j2s(sel));
        }
      } catch (e) {}
      return q.call(this, uri, proj, sel, args, sort);
    };
    emit("HOOK", "SMS hooks installed.");
  } catch (e) {
    emit("HOOK", "SMS hooks failed: " + e);
  }

  // CRYPTO (context)
  try {
    const Cipher = Java.use("javax.crypto.Cipher");
    const gi = Cipher.getInstance.overload("java.lang.String");
    gi.implementation = function (x) {
      emit("CRYPTO", "Cipher.getInstance " + j2s(x));
      return gi.call(this, x);
    };
    emit("HOOK", "CRYPTO hooks installed.");
  } catch (e) {
    emit("HOOK", "CRYPTO hooks failed: " + e);
  }
});
