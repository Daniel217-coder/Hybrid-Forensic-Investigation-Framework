# src/apk_static.py
import re
import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from androguard.core.apk import APK

# -----------------------------
# Logging control (quiet by default)
# -----------------------------
_VERBOSE = False


def set_verbose(enabled: bool):
    """
    Control androguard logging noise.
    Default: quiet (ERROR only).
    If enabled: show warnings/info (still not full spam).
    """
    global _VERBOSE
    _VERBOSE = bool(enabled)

    level = logging.DEBUG if _VERBOSE else logging.ERROR
    for name in [
        "androguard",
        "androguard.core",
        "androguard.core.axml",
        "androguard.misc",
        "loguru",
    ]:
        try:
            logging.getLogger(name).setLevel(level)
        except Exception:
            pass

    logging.getLogger().setLevel(logging.WARNING if _VERBOSE else logging.ERROR)


# -----------------------------
# Constants / heuristics
# -----------------------------
ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = f"{{{ANDROID_NS}}}"  # android:attr namespace in ElementTree

# 0–20 static risk score:
# SAFE apps should typically be <= 6 (especially if trusted signature).
SCORE_MAX = 20

# Domain whitelisting (common benign references inside APKs)
WHITELIST_DOMAINS = {
    "schemas.android.com",
    "ns.adobe.com",
    "github.com",
    "raw.githubusercontent.com",
    "fonts.google.com",
    "goo.gle",
    "play.google.com",
    "developer.android.com",
    "kotlinlang.org",
    "youtrack.jetbrains.com",
    "commons.apache.org",
    "www.w3.org",
    "www.apache.org",
    "opensource.org",
    "spdx.org",
}

WHITELIST_DOMAIN_SUFFIXES = {
    ".github.com",
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".android.com",
}

# File extensions that should NOT be considered domains/emails (noise reduction)
DOMAIN_EXCLUDE_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".css", ".js", ".json", ".xml", ".html", ".htm",
    ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".apk", ".dex", ".jar", ".so",
}

SUSPICIOUS_ASSET_EXTS = {".dex", ".jar", ".bin", ".dat", ".enc", ".payload", ".exe"}

PACKER_LIB_HINTS = {
    "libjiagu": "Potential packer/obfuscator (Qihoo Jiagu) hint",
    "libprotect": "Potential packer/protection library hint",
    "libdexprotect": "Potential DEX protection library hint",
    "libsecexe": "Potential security wrapper library hint",
    "bangcle": "Potential Bangcle packer hint",
}

# "High signal" dangerous permissions (static)
PERM_WEIGHTS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 6,
    "android.permission.SYSTEM_ALERT_WINDOW": 5,
    "android.permission.REQUEST_INSTALL_PACKAGES": 5,
    "android.permission.PACKAGE_USAGE_STATS": 3,
    "android.permission.WRITE_SETTINGS": 3,
    "android.permission.READ_SMS": 5,
    "android.permission.RECEIVE_SMS": 3,
    "android.permission.SEND_SMS": 5,
    "android.permission.RECEIVE_BOOT_COMPLETED": 2,
    "android.permission.QUERY_ALL_PACKAGES": 2,
    "android.permission.READ_CALL_LOG": 4,
    "android.permission.WRITE_CALL_LOG": 4,
    "android.permission.RECORD_AUDIO": 3,
    "android.permission.ACCESS_FINE_LOCATION": 2,
    "android.permission.ACCESS_COARSE_LOCATION": 1,
    "android.permission.READ_CONTACTS": 3,
    "android.permission.WRITE_CONTACTS": 3,
    # Common + usually benign-ish: keep very low
    "android.permission.CAMERA": 1,
    "android.permission.READ_EXTERNAL_STORAGE": 1,
    "android.permission.WRITE_EXTERNAL_STORAGE": 1,
    "android.permission.INTERNET": 0,  # don't score
}

# Sensitive broadcast actions (ONLY if receiver exported)
SUSPICIOUS_RECEIVER_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED": 4,
    "android.intent.action.LOCKED_BOOT_COMPLETED": 4,
    "android.provider.Telephony.SMS_RECEIVED": 6,
    "android.provider.Telephony.WAP_PUSH_RECEIVED": 5,
    "android.intent.action.PACKAGE_ADDED": 3,
    "android.intent.action.PACKAGE_REPLACED": 3,
    "android.intent.action.USER_PRESENT": 2,
    "android.intent.action.SCREEN_ON": 2,
    "android.intent.action.SCREEN_OFF": 2,
    "android.intent.action.NEW_OUTGOING_CALL": 5,
    "android.intent.action.PHONE_STATE": 4,
}

# Behavior indicators (static, high-signal first)
# NOTE: reflection by itself is low-signal in modern apps (libs/tooling).
HIGH_SIGNAL_BEHAVIOR = {
    "DexClassLoader": (6, "Dynamic code loading (DexClassLoader)"),
    "PathClassLoader": (3, "Dynamic class loading (PathClassLoader)"),
    "loadDex": (4, "Dex loading routine (loadDex)"),
    "Runtime.exec": (6, "Command execution via Runtime.exec"),
    "ProcessBuilder": (3, "Command execution via ProcessBuilder"),
    "addJavascriptInterface": (4, "WebView JS bridge (addJavascriptInterface)"),
    "X509TrustManager": (2, "Custom trust manager mention (X509TrustManager)"),
    "HostnameVerifier": (2, "Hostname verifier mention (HostnameVerifier)"),
}

LOW_SIGNAL_BEHAVIOR = {
    "java.lang.reflect": (1, "Reflection usage (java.lang.reflect)"),
    "Method.invoke": (1, "Reflection invocation (Method.invoke)"),
    "Class.forName": (1, "Reflection lookup (Class.forName)"),
    "isDebuggerConnected": (1, "Debugger detection (isDebuggerConnected)"),
    "android.os.Debug": (1, "Debug API usage (android.os.Debug)"),
    "Build.FINGERPRINT": (1, "Environment fingerprinting (Build.FINGERPRINT)"),
    "ro.kernel.qemu": (1, "Emulator detection hint (ro.kernel.qemu)"),
}

# IOC regexes
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


def _unique_sorted(items: List[str]) -> List[str]:
    return sorted(set([x for x in items if x]))


def _read_android_attr(el: ET.Element, name: str) -> Optional[str]:
    v = el.get(A + name)
    if v is not None:
        return v
    return el.get("android:" + name)


def _boolish(v: Optional[str]) -> Optional[bool]:
    if v is None:
        return None
    vv = str(v).strip().lower()
    if vv in {"true", "1", "yes"}:
        return True
    if vv in {"false", "0", "no"}:
        return False
    return None


def _limit_list(items: List[Any], limit: int) -> List[Any]:
    if limit <= 0:
        return items
    return items[:limit]


def _valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True
    except Exception:
        return False


def _domain_is_whitelisted(domain: str) -> bool:
    d = (domain or "").strip().lower()
    if not d:
        return False
    if d in WHITELIST_DOMAINS:
        return True
    for suf in WHITELIST_DOMAIN_SUFFIXES:
        if d.endswith(suf):
            return True
    return False


def extract_iocs_from_blob(text_blob: str) -> Dict[str, List[str]]:
    blob = text_blob or ""
    urls = _unique_sorted(URL_RE.findall(blob))

    # Emails: drop those where domain ends with file extension (.png etc.)
    emails_raw = EMAIL_RE.findall(blob)
    emails: List[str] = []
    for e in emails_raw:
        try:
            dom = e.split("@", 1)[1].lower()
            if any(dom.endswith(suf.lstrip(".")) for suf in []):
                pass
            # If domain ends with excluded suffix, treat as noise
            if any(dom.endswith(suf.lstrip(".")) for suf in []):
                continue
            if any(dom.endswith(suf.replace(".", "")) for suf in []):
                continue
            if any(dom.endswith(suf) for suf in [x.replace(".", "") for x in []]):
                continue
            if any(dom.endswith(suf) for suf in []):
                continue
            if any(dom.endswith(suf.strip(".")) for suf in []):
                continue
            # Better: if domain contains '.' and last part looks like an excluded extension:
            last = dom.split(".")[-1] if "." in dom else dom
            if ("." + last) in DOMAIN_EXCLUDE_SUFFIXES:
                continue
            emails.append(e)
        except Exception:
            continue
    emails = _unique_sorted(emails)

    ips_raw = IP_RE.findall(blob)
    ips = _unique_sorted([ip for ip in ips_raw if _valid_ipv4(ip)])

    domains = set()
    # standalone domain tokens
    for d in DOMAIN_RE.findall(blob):
        if d:
            dd = d.lower()
            if any(dd.endswith(suf) for suf in DOMAIN_EXCLUDE_SUFFIXES):
                continue
            domains.add(dd)

    # domains from urls
    for u in urls:
        u2 = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
        dom = u2.split("/")[0].split(":")[0].strip().lower()
        if dom and not any(dom.endswith(suf) for suf in DOMAIN_EXCLUDE_SUFFIXES):
            domains.add(dom)

    return {
        "urls": urls,
        "domains": _unique_sorted(list(domains)),
        "ips": ips,
        "emails": emails,
    }


def get_cert_fingerprint(apk: APK) -> Dict[str, Any]:
    fp = {
        "sha256_fingerprint": "unknown",
        "issuer": "unknown",
        "subject": "unknown",
        "signing": {
            "is_signed": None,
            "v1": None,
            "v2": None,
            "v3": None,
        },
    }

    try:
        if hasattr(apk, "is_signed"):
            fp["signing"]["is_signed"] = bool(apk.is_signed())
    except Exception:
        pass
    for k in ("is_signed_v1", "is_signed_v2", "is_signed_v3"):
        try:
            if hasattr(apk, k):
                fp["signing"][k.split("_")[-1]] = bool(getattr(apk, k)())
        except Exception:
            pass

    try:
        certs = apk.get_certificates()
        if certs:
            c = certs[0]
            cert_bytes = c.dump() if hasattr(c, "dump") else bytes(c)
            fp["sha256_fingerprint"] = hashlib.sha256(cert_bytes).hexdigest()
            if hasattr(c, "issuer"):
                fp["issuer"] = str(c.issuer)
            if hasattr(c, "subject"):
                fp["subject"] = str(c.subject)
    except Exception:
        pass

    return fp


@dataclass
class ComponentInfo:
    name: str
    type: str
    exported: Optional[bool]
    exported_inferred: bool
    enabled: Optional[bool]
    permission: Optional[str]
    process: Optional[str]
    intent_actions: List[str]


def _infer_exported(explicit_exported: Optional[bool], has_intent_filter: bool) -> Tuple[Optional[bool], bool]:
    """
    Heuristic consistent with legacy behavior:
    - If exported explicitly defined => use it
    - Else exported inferred true if intent-filter exists, else false
    """
    if explicit_exported is not None:
        return explicit_exported, False
    return (True if has_intent_filter else False), True


def parse_manifest_deep(apk: APK) -> Dict[str, Any]:
    """
    Deep manifest parse (components, intent-filters, app flags, sdk, cleartext, etc.).
    Best-effort across androguard versions.
    """
    out: Dict[str, Any] = {
        "manifest_parse_ok": False,
        "package": None,
        "sdk": {"min_sdk": None, "target_sdk": None},
        "app_flags": {
            "debuggable": None,
            "allow_backup": None,
            "uses_cleartext_traffic": None,
            "network_security_config": None,
        },
        "permissions": [],
        "features": [],
        "queries": [],
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        },
    }

    xml_text = None

    # Try multiple ways to get manifest XML
    try:
        if hasattr(apk, "get_android_manifest_axml"):
            axml = apk.get_android_manifest_axml()
            if axml is not None and hasattr(axml, "get_xml"):
                xml_bytes = axml.get_xml()
                if isinstance(xml_bytes, bytes):
                    xml_text = xml_bytes.decode("utf-8", errors="ignore")
                else:
                    xml_text = str(xml_bytes)
    except Exception:
        pass

    if not xml_text:
        try:
            if hasattr(apk, "get_android_manifest_xml"):
                m = apk.get_android_manifest_xml()
                if isinstance(m, bytes):
                    xml_text = m.decode("utf-8", errors="ignore")
                else:
                    xml_text = str(m)
        except Exception:
            pass

    if not xml_text:
        return out

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out

    out["manifest_parse_ok"] = True
    out["package"] = root.get("package")

    # uses-sdk
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        out["sdk"]["min_sdk"] = _read_android_attr(uses_sdk, "minSdkVersion")
        out["sdk"]["target_sdk"] = _read_android_attr(uses_sdk, "targetSdkVersion")

    # permissions
    perms = []
    for up in root.findall("uses-permission"):
        name = _read_android_attr(up, "name")
        if name:
            perms.append(name)
    for up in root.findall("uses-permission-sdk-23"):
        name = _read_android_attr(up, "name")
        if name:
            perms.append(name)
    out["permissions"] = _unique_sorted(perms)

    # uses-feature
    feats = []
    for uf in root.findall("uses-feature"):
        nm = _read_android_attr(uf, "name")
        if nm:
            feats.append(nm)
    out["features"] = _unique_sorted(feats)

    # queries (Android 11+)
    queries = []
    q = root.find("queries")
    if q is not None:
        for pkg in q.findall("package"):
            nm = _read_android_attr(pkg, "name")
            if nm:
                queries.append(nm)
    out["queries"] = _unique_sorted(queries)

    # application flags
    app = root.find("application")
    if app is not None:
        out["app_flags"]["debuggable"] = _boolish(_read_android_attr(app, "debuggable"))
        out["app_flags"]["allow_backup"] = _boolish(_read_android_attr(app, "allowBackup"))
        out["app_flags"]["uses_cleartext_traffic"] = _boolish(_read_android_attr(app, "usesCleartextTraffic"))
        out["app_flags"]["network_security_config"] = _read_android_attr(app, "networkSecurityConfig")

    def parse_components(tag: str, ctype: str) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        if app is None:
            return res
        for c in app.findall(tag):
            name = _read_android_attr(c, "name")
            if not name:
                continue

            exported_attr = _boolish(_read_android_attr(c, "exported"))
            enabled_attr = _boolish(_read_android_attr(c, "enabled"))
            perm_attr = _read_android_attr(c, "permission")
            proc_attr = _read_android_attr(c, "process")

            actions: List[str] = []
            has_if = False
            for intent_filter in c.findall("intent-filter"):
                has_if = True
                for action in intent_filter.findall("action"):
                    an = _read_android_attr(action, "name")
                    if an:
                        actions.append(an)

            exported_final, inferred = _infer_exported(exported_attr, has_if)

            info = ComponentInfo(
                name=name,
                type=ctype,
                exported=exported_final,
                exported_inferred=inferred,
                enabled=enabled_attr,
                permission=perm_attr,
                process=proc_attr,
                intent_actions=_unique_sorted(actions),
            )
            res.append({
                "name": info.name,
                "type": info.type,
                "exported": info.exported,
                "exported_inferred": info.exported_inferred,
                "enabled": info.enabled,
                "permission": info.permission,
                "process": info.process,
                "intent_actions": info.intent_actions,
            })
        return res

    out["components"]["activities"] = parse_components("activity", "activity") + parse_components("activity-alias", "activity-alias")
    out["components"]["services"] = parse_components("service", "service")
    out["components"]["receivers"] = parse_components("receiver", "receiver")

    # providers
    providers: List[Dict[str, Any]] = []
    if app is not None:
        for p in app.findall("provider"):
            nm = _read_android_attr(p, "name")
            if not nm:
                continue
            exported_attr = _boolish(_read_android_attr(p, "exported"))
            enabled_attr = _boolish(_read_android_attr(p, "enabled"))
            perm_attr = _read_android_attr(p, "permission")
            proc_attr = _read_android_attr(p, "process")
            authorities = _read_android_attr(p, "authorities")
            grant_uri = _boolish(_read_android_attr(p, "grantUriPermissions"))

            has_if = p.find("intent-filter") is not None
            actions: List[str] = []
            if has_if:
                for intent_filter in p.findall("intent-filter"):
                    for action in intent_filter.findall("action"):
                        an = _read_android_attr(action, "name")
                        if an:
                            actions.append(an)

            exported_final, inferred = _infer_exported(exported_attr, has_if)

            providers.append({
                "name": nm,
                "type": "provider",
                "exported": exported_final,
                "exported_inferred": inferred,
                "enabled": enabled_attr,
                "permission": perm_attr,
                "process": proc_attr,
                "authorities": authorities,
                "grantUriPermissions": grant_uri,
                "intent_actions": _unique_sorted(actions),
            })
    out["components"]["providers"] = providers

    return out


def list_apk_files(apk: APK) -> Dict[str, Any]:
    files = []
    try:
        files = list(apk.get_files() or [])
    except Exception:
        files = []

    dex_files = [f for f in files if f.lower().endswith(".dex")]
    native_libs = [f for f in files if f.startswith("lib/") and f.lower().endswith(".so")]
    assets = [f for f in files if f.startswith("assets/")]
    res_raw = [f for f in files if f.startswith("res/")]
    meta_inf = [f for f in files if f.startswith("META-INF/")]

    libs_by_abi: Dict[str, List[str]] = {}
    for lib in native_libs:
        parts = lib.split("/")
        abi = parts[1] if len(parts) >= 3 else "unknown"
        libs_by_abi.setdefault(abi, []).append(lib)

    libs_by_abi = {k: _unique_sorted(v) for k, v in libs_by_abi.items()}

    suspicious_assets = []
    for a in assets:
        low = a.lower()
        for ext in SUSPICIOUS_ASSET_EXTS:
            if low.endswith(ext):
                suspicious_assets.append(a)
                break

    packer_hints = []
    for lib in native_libs:
        low = lib.lower()
        for hint, desc in PACKER_LIB_HINTS.items():
            if hint in low:
                packer_hints.append(f"{lib} :: {desc}")

    return {
        "file_index": {
            "total_files": len(files),
            "dex_files": _unique_sorted(dex_files),
            "native_libs": _unique_sorted(native_libs),
            "native_libs_by_abi": libs_by_abi,
            "assets_files": _unique_sorted(assets),
            "res_files": _unique_sorted(res_raw),
            "meta_inf_files": _unique_sorted(meta_inf),
        },
        "suspicious_assets": _unique_sorted(suspicious_assets),
        "packer_hints": _unique_sorted(packer_hints),
    }


def _collect_strings_light(apk: APK) -> List[str]:
    strings: List[str] = []
    try:
        s = apk.get_strings()
        if s:
            strings.extend(list(s))
    except Exception:
        pass
    return strings


def _collect_strings_deep(apk_path: str, max_strings: int = 200_000) -> Dict[str, Any]:
    """
    Deep string & code-hint extraction using androguard.misc.AnalyzeAPK.
    Best-effort; if AnalyzeAPK fails, returns empty.
    """
    result = {
        "deep_ok": False,
        "dex_strings_count": 0,
        "class_names_count": 0,
        "method_refs_count": 0,
        "strings_sample": [],
        "class_names_sample": [],
        "method_refs_sample": [],
        "strings_blob_for_ioc": "",
        "code_hints": {
            "high_signal": [],
            "low_signal": [],
            "crypto_hints": [],
        },
        "obfuscation": {
            "class_name_short_ratio": None,
            "short_name_threshold": 3,
            "sample_suspicious_short_names": [],
        },
    }

    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
    except Exception:
        return result

    try:
        a2, ds, dx = AnalyzeAPK(apk_path)
    except Exception:
        return result

    strings_set = set()
    class_names_set = set()
    method_refs_set = set()

    # DEX strings + class names
    try:
        dex_list = []
        if isinstance(ds, list):
            dex_list = ds
        elif ds is not None:
            dex_list = [ds]

        for d in dex_list:
            if hasattr(d, "get_strings"):
                for st in d.get_strings() or []:
                    if st:
                        strings_set.add(str(st))
            if hasattr(d, "get_classes"):
                for c in d.get_classes() or []:
                    try:
                        cn = c.get_name()
                        if cn:
                            class_names_set.add(str(cn))
                    except Exception:
                        pass
    except Exception:
        pass

    # Method references
    try:
        if dx is not None and hasattr(dx, "get_methods"):
            for m in dx.get_methods():
                try:
                    mm = m.get_method()
                    if mm is None:
                        continue
                    cname = mm.get_class_name() or ""
                    mname = mm.get_name() or ""
                    desc = mm.get_descriptor() or ""
                    ref = f"{cname}->{mname}{desc}"
                    method_refs_set.add(ref)
                except Exception:
                    continue
    except Exception:
        pass

    # Obfuscation heuristic
    short_thresh = 3
    cleaned: List[str] = []
    for cn in list(class_names_set)[:120_000]:
        s = cn.strip()
        if s.startswith("L") and s.endswith(";"):
            s = s[1:-1]
        last = s.split("/")[-1] if "/" in s else s.split(".")[-1]
        cleaned.append(last)

    short_names = [x for x in cleaned if x and len(x) <= short_thresh]
    ratio = None
    if cleaned:
        ratio = len(short_names) / max(1, len(cleaned))

    merged_for_search = "\n".join(
        _limit_list(list(strings_set), max_strings)
        + _limit_list(list(method_refs_set), 60_000)
        + _limit_list(list(class_names_set), 60_000)
    )

    high_hits = []
    low_hits = []
    crypto_hits: List[str] = []

    crypto_keywords = [
        "AES", "GCM", "CBC", "RSA", "ECDSA", "HMAC", "PBKDF2", "scrypt",
        "MessageDigest", "SHA-1", "SHA1", "SHA-256", "SHA256", "MD5",
        "Cipher.getInstance", "SecretKeySpec", "IvParameterSpec",
        "KeyStore", "X509Certificate",
    ]

    for k, (w, desc) in HIGH_SIGNAL_BEHAVIOR.items():
        if k in merged_for_search:
            high_hits.append({"indicator": k, "weight": w, "description": desc})

    for k, (w, desc) in LOW_SIGNAL_BEHAVIOR.items():
        if k in merged_for_search:
            low_hits.append({"indicator": k, "weight": w, "description": desc})

    for kw in crypto_keywords:
        if kw in merged_for_search:
            crypto_hits.append(kw)

    result["deep_ok"] = True
    result["dex_strings_count"] = len(strings_set)
    result["class_names_count"] = len(class_names_set)
    result["method_refs_count"] = len(method_refs_set)

    result["strings_sample"] = _limit_list(sorted(strings_set), 200)
    result["class_names_sample"] = _limit_list(sorted(class_names_set), 200)
    result["method_refs_sample"] = _limit_list(sorted(method_refs_set), 200)

    result["strings_blob_for_ioc"] = merged_for_search[:2_000_000]
    result["code_hints"]["high_signal"] = high_hits
    result["code_hints"]["low_signal"] = low_hits
    result["code_hints"]["crypto_hints"] = _unique_sorted([str(x) for x in crypto_hits])

    result["obfuscation"]["class_name_short_ratio"] = ratio
    result["obfuscation"]["short_name_threshold"] = short_thresh
    result["obfuscation"]["sample_suspicious_short_names"] = _limit_list(sorted(set(short_names)), 80)

    return result


def get_exported_components_quick(apk: APK) -> Dict[str, List[str]]:
    """
    Legacy quick exported components extraction (best-effort).
    Deep parser is authoritative when available.
    """
    def exported_list(getter, tag_name: str):
        out = []
        try:
            comps = getter() or []
            for c in comps:
                try:
                    val = apk.get_element(tag_name, "exported", name=c)
                    if val == "true":
                        out.append(c)
                except Exception:
                    pass
        except Exception:
            pass
        return _unique_sorted(out)

    return {
        "exported_activities": exported_list(apk.get_activities, "activity"),
        "exported_services": exported_list(apk.get_services, "service"),
        "exported_receivers": exported_list(apk.get_receivers, "receiver"),
    }


def _summarize_components(manifest_deep: Dict[str, Any]) -> Dict[str, Any]:
    comps = (manifest_deep.get("components") or {}) if manifest_deep else {}
    all_components: List[Dict[str, Any]] = []
    for k in ("activities", "services", "receivers", "providers"):
        all_components.extend(comps.get(k, []) or [])

    exported = [c for c in all_components if c.get("exported") is True]
    exported_receivers = [c for c in (comps.get("receivers", []) or []) if c.get("exported") is True]
    exported_providers = [c for c in (comps.get("providers", []) or []) if c.get("exported") is True]
    exported_services = [c for c in (comps.get("services", []) or []) if c.get("exported") is True]

    receiver_action_hits = []
    for r in exported_receivers:
        acts = r.get("intent_actions") or []
        for a in acts:
            if a in SUSPICIOUS_RECEIVER_ACTIONS:
                receiver_action_hits.append({"receiver": r.get("name"), "action": a, "weight": SUSPICIOUS_RECEIVER_ACTIONS[a]})

    # Provider risk signals: exported + no permission can be risky (data exposure), but keep modest
    provider_risk = []
    for p in exported_providers:
        perm = p.get("permission")
        grant = p.get("grantUriPermissions")
        auth = (p.get("authorities") or "")
        if perm:
            continue
        # Grant URI perms can increase exposure
        if grant is True:
            provider_risk.append({"provider": p.get("name"), "reason": "exported provider + grantUriPermissions", "weight": 3})
        # Authorities that look generic/short (heuristic)
        if auth and len(auth) < 25:
            provider_risk.append({"provider": p.get("name"), "reason": "exported provider + short authorities", "weight": 2})

    # Service exposure: exported service without protection is suspicious-ish (rare)
    service_risk = []
    for s in exported_services:
        perm = s.get("permission")
        acts = s.get("intent_actions") or []
        if perm:
            continue
        if acts:
            service_risk.append({"service": s.get("name"), "reason": "exported service + intent-filter (no permission)", "weight": 3})
        else:
            service_risk.append({"service": s.get("name"), "reason": "exported service (no permission)", "weight": 2})

    return {
        "counts": {
            "activities": len(comps.get("activities", []) or []),
            "services": len(comps.get("services", []) or []),
            "receivers": len(comps.get("receivers", []) or []),
            "providers": len(comps.get("providers", []) or []),
            "exported_total": len(exported),
            "exported_receivers": len(exported_receivers),
            "exported_providers": len(exported_providers),
            "exported_services": len(exported_services),
        },
        "exported_components": _limit_list(
            [{
                "type": c.get("type"),
                "name": c.get("name"),
                "permission": c.get("permission"),
                "intent_actions": c.get("intent_actions", []),
            } for c in exported],
            120
        ),
        "receiver_action_hits": receiver_action_hits[:200],
        "provider_risk_hits": provider_risk[:200],
        "service_risk_hits": service_risk[:200],
    }


def _trust_adjustment(cert: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Returns (negative_points, reasons) where negative_points reduces total score.
    Very conservative: only apply for known trusted issuers.
    """
    reasons: List[str] = []
    if not cert:
        return 0, reasons

    signing = cert.get("signing") or {}
    if signing.get("is_signed") is not True:
        return 0, reasons

    issuer = str(cert.get("issuer") or "").lower()
    subject = str(cert.get("subject") or "").lower()

    # Strong trust: F-Droid signing
    if "fdroid.org" in issuer or "fdroid.org" in subject or "fdroid" in issuer or "fdroid" in subject:
        reasons.append("Trusted signature: F-Droid (risk reduced)")
        return 6, reasons  # reduce by 6

    # Mild trust: modern signing present (v2 or v3)
    if signing.get("v2") is True or signing.get("v3") is True:
        reasons.append("Modern APK signing detected (v2/v3) (risk slightly reduced)")
        return 2, reasons  # reduce by 2

    return 0, reasons


def score_apk_static_0_20(
    permissions: List[str],
    manifest_deep: Dict[str, Any],
    file_info: Dict[str, Any],
    iocs: Dict[str, List[str]],
    cert: Dict[str, Any],
    deep_code: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calibrated static risk score in range 0..20.
    Interpreted as: capability/exposure suspicion (NOT a malware verdict).
    """
    perms = set(permissions or [])
    reasons: List[str] = []
    breakdown: Dict[str, int] = {
        "permissions": 0,
        "exposure": 0,
        "behavior": 0,
        "network_iocs": 0,
        "packaging": 0,
        "config": 0,
        "trust_adjustment": 0,
    }

    score = 0

    # 1) Permissions (cap at 7)
    perm_score = 0
    perm_hits: List[str] = []
    for p in sorted(perms):
        w = PERM_WEIGHTS.get(p)
        if w is None:
            continue
        if w <= 0:
            continue
        perm_score += w
        perm_hits.append(f"{p} (+{w})")
    perm_score = min(7, perm_score)
    breakdown["permissions"] = perm_score
    if perm_score:
        score += perm_score
        reasons.append(f"Permission capability indicators (+{perm_score})")

    # 2) Exposure: exported receivers/providers/services only when risky (cap at 6)
    exposure_score = 0
    comp_summary = _summarize_components(manifest_deep or {})
    # exported receiver sensitive actions
    ra_hits = comp_summary.get("receiver_action_hits") or []
    if ra_hits:
        add = min(6, sum(int(x.get("weight", 0)) for x in ra_hits))
        add = min(add, 6)
        exposure_score += add
        reasons.append(f"Exported receiver with sensitive intents (+{add})")

    # exported providers risk hints (modest)
    pr_hits = comp_summary.get("provider_risk_hits") or []
    if pr_hits:
        add = min(4, sum(int(x.get("weight", 0)) for x in pr_hits))
        exposure_score += add
        reasons.append(f"Exported provider exposure hints (+{add})")

    # exported services risk hints
    sr_hits = comp_summary.get("service_risk_hits") or []
    if sr_hits:
        add = min(4, sum(int(x.get("weight", 0)) for x in sr_hits))
        exposure_score += add
        reasons.append(f"Exported service exposure hints (+{add})")

    exposure_score = min(6, exposure_score)
    breakdown["exposure"] = exposure_score
    score += exposure_score

    # 3) Config flags (cap at 3)
    cfg = (manifest_deep.get("app_flags") or {}) if manifest_deep else {}
    cfg_score = 0
    if cfg.get("debuggable") is True:
        cfg_score += 2
        reasons.append("App debuggable (+2)")
    if cfg.get("uses_cleartext_traffic") is True:
        cfg_score += 1
        reasons.append("Cleartext traffic allowed (+1)")
    # allowBackup is usually not a malware signal; keep tiny
    if cfg.get("allow_backup") is True:
        cfg_score += 1
        reasons.append("AllowBackup enabled (+1)")
    cfg_score = min(3, cfg_score)
    breakdown["config"] = cfg_score
    score += cfg_score

    # 4) Packaging: native libs, suspicious assets, packer hints (cap at 4)
    pack_score = 0
    idx = (file_info.get("file_index") or {}) if file_info else {}
    native_libs = idx.get("native_libs") or []
    suspicious_assets = file_info.get("suspicious_assets") or []
    packer_hints = file_info.get("packer_hints") or []

    if native_libs:
        pack_score += 1  # very common in legit apps
        reasons.append("Native libraries present (+1)")
    if suspicious_assets:
        pack_score += min(2, 1 + len(suspicious_assets) // 5)
        reasons.append(f"Suspicious asset payload candidates (+{min(2, 1 + len(suspicious_assets) // 5)})")
    if packer_hints:
        pack_score += 3
        reasons.append("Packer/protection library hints (+3)")

    pack_score = min(4, pack_score)
    breakdown["packaging"] = pack_score
    score += pack_score

    # 5) Network/IOCs (cap at 5) — ONLY if non-whitelisted / IPs / weird domains
    ioc_score = 0
    urls = iocs.get("urls") or []
    domains = iocs.get("domains") or []
    ips = iocs.get("ips") or []
    emails = iocs.get("emails") or []

    # IPs are always notable
    if ips:
        ioc_score += min(3, 1 + 2 * len(ips))
        reasons.append(f"Hardcoded IP(s) in strings (+{min(3, 1 + 2 * len(ips))})")

    # Domains: only count non-whitelisted
    nonwhite_domains = []
    for d in domains:
        dd = (d or "").strip().lower()
        if not dd:
            continue
        if any(dd.endswith(suf) for suf in DOMAIN_EXCLUDE_SUFFIXES):
            continue
        if _domain_is_whitelisted(dd):
            continue
        nonwhite_domains.append(dd)

    nonwhite_domains = _unique_sorted(nonwhite_domains)
    if nonwhite_domains:
        add = min(2, 1 + len(nonwhite_domains) // 10)
        ioc_score += add
        reasons.append(f"Non-whitelisted domain references (+{add})")

    # URLs: only count if domain non-whitelisted
    nonwhite_urls = []
    for u in urls:
        try:
            u2 = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
            dom = u2.split("/")[0].split(":")[0].strip().lower()
            if not dom:
                continue
            if _domain_is_whitelisted(dom):
                continue
            nonwhite_urls.append(u)
        except Exception:
            continue
    nonwhite_urls = _unique_sorted(nonwhite_urls)
    if nonwhite_urls:
        add = 1
        ioc_score += add
        reasons.append("Non-whitelisted URL(s) detected (+1)")

    # Emails: only count if domain non-whitelisted (rare)
    nonwhite_emails = []
    for e in emails:
        try:
            dom = e.split("@", 1)[1].lower()
            if ("." + dom.split(".")[-1]) in DOMAIN_EXCLUDE_SUFFIXES:
                continue
            if _domain_is_whitelisted(dom):
                continue
            nonwhite_emails.append(e)
        except Exception:
            continue
    nonwhite_emails = _unique_sorted(nonwhite_emails)
    if nonwhite_emails:
        ioc_score += 1
        reasons.append("Non-whitelisted email address(es) (+1)")

    ioc_score = min(5, ioc_score)
    breakdown["network_iocs"] = ioc_score
    score += ioc_score

    # 6) Behavior (cap at 8)
    beh_score = 0
    code_hints = (deep_code.get("code_hints") or {}) if deep_code else {}
    high_hits = code_hints.get("high_signal") or []
    low_hits = code_hints.get("low_signal") or []

    if high_hits:
        add = min(8, sum(int(x.get("weight", 0)) for x in high_hits))
        # clamp to 8
        beh_score += min(8, add)
        reasons.append(f"High-signal behavior indicators (+{min(8, add)})")

    # low-signal only adds if there are also high-signal OR other strong signals (permissions/exposure)
    if low_hits and (beh_score > 0 or perm_score >= 5 or exposure_score >= 4):
        add = min(2, sum(int(x.get("weight", 0)) for x in low_hits))
        beh_score += add
        reasons.append(f"Supporting low-signal indicators (+{add})")

    # Obfuscation: only tiny weight
    ob = deep_code.get("obfuscation") if deep_code else {}
    ratio = ob.get("class_name_short_ratio")
    if isinstance(ratio, float):
        if ratio >= 0.35:
            beh_score += 2
            reasons.append("High obfuscation signal (+2)")
        elif ratio >= 0.20:
            beh_score += 1
            reasons.append("Moderate obfuscation signal (+1)")

    beh_score = min(8, beh_score)
    breakdown["behavior"] = beh_score
    score += beh_score

    # 7) Trust adjustment (reduce score)
    trust_reduce, trust_reasons = _trust_adjustment(cert or {})
    if trust_reduce > 0:
        score -= trust_reduce
        breakdown["trust_adjustment"] = -trust_reduce
        reasons.extend(trust_reasons)

    # Clamp to 0..20
    score = max(0, min(SCORE_MAX, int(score)))

    # Severity mapping (4 levels, no "CRITICAL")
    if score <= 3:
        severity = "SAFE"
    elif score <= 7:
        severity = "LOW"
    elif score <= 12:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    # Make reasons clean + non-duplicative
    reasons = _unique_sorted(reasons)

    # Provide top modules
    ordered = sorted(breakdown.items(), key=lambda kv: abs(int(kv[1])), reverse=True)
    top_modules = [f"{k}: {v:+d}" for k, v in ordered if v != 0][:6]

    return {
        "score": score,                 # 0..20
        "score_max": SCORE_MAX,
        "risk_scale": "0-20",
        "severity": severity,           # SAFE/LOW/MEDIUM/HIGH
        "breakdown": breakdown,
        "top_modules": top_modules,
        "reasons": _limit_list(reasons, 12),
        "permission_hits": _limit_list(perm_hits, 200),
        "iocs_filtered": {
            "nonwhite_domains": _limit_list(nonwhite_domains, 50),
            "nonwhite_urls": _limit_list(nonwhite_urls, 50),
            "nonwhite_emails": _limit_list(nonwhite_emails, 50),
        },
    }


def analyze_apk(apk_path: str, deep: bool = True) -> Dict[str, Any]:
    # Ensure logging policy is applied even if caller forgot
    set_verbose(_VERBOSE)

    a = APK(apk_path)

    # Base metadata
    base_package = None
    base_app_name = None
    base_version_name = None
    base_version_code = None
    base_min_sdk = None
    base_target_sdk = None

    try:
        base_package = a.get_package()
    except Exception:
        pass
    try:
        base_app_name = a.get_app_name()
    except Exception:
        pass
    try:
        base_version_name = a.get_androidversion_name()
    except Exception:
        pass
    try:
        base_version_code = a.get_androidversion_code()
    except Exception:
        pass
    try:
        base_min_sdk = a.get_min_sdk_version()
    except Exception:
        pass
    try:
        base_target_sdk = a.get_target_sdk_version()
    except Exception:
        pass

    # Deep manifest parse (authoritative)
    manifest_deep = parse_manifest_deep(a)

    # Permissions: prefer deep manifest list if present
    perms = manifest_deep.get("permissions") or []
    if not perms:
        try:
            perms = list(a.get_permissions() or [])
        except Exception:
            perms = []
    perms = _unique_sorted([str(x) for x in perms])

    # Quick exported components (legacy)
    exported_quick = get_exported_components_quick(a)

    # File index
    file_info = list_apk_files(a)

    # Cert / signing info
    cert = get_cert_fingerprint(a)

    # Strings collection (light + deep)
    light_strings = _collect_strings_light(a)
    deep_code = {"deep_ok": False, "strings_blob_for_ioc": "", "code_hints": {"high_signal": [], "low_signal": [], "crypto_hints": []}, "obfuscation": {}}
    if deep:
        deep_code = _collect_strings_deep(apk_path)

    # IOC extraction blob
    blob_parts = []
    if light_strings:
        blob_parts.append("\n".join(light_strings[:60_000]))
    if deep_code.get("strings_blob_for_ioc"):
        blob_parts.append(str(deep_code["strings_blob_for_ioc"]))
    blob = "\n".join(blob_parts)

    iocs = extract_iocs_from_blob(blob)

    # Scoring (0–20)
    scoring = score_apk_static_0_20(
        permissions=perms,
        manifest_deep=manifest_deep,
        file_info=file_info,
        iocs=iocs,
        cert=cert,
        deep_code=deep_code,
    )

    comp_summary = _summarize_components(manifest_deep)

    return {
        "apk_path": apk_path,

        # Identity
        "package": base_package,
        "app_name": base_app_name,
        "version_name": str(base_version_name) if base_version_name is not None else None,
        "version_code": str(base_version_code) if base_version_code is not None else None,

        # SDK
        "min_sdk": manifest_deep.get("sdk", {}).get("min_sdk") or (str(base_min_sdk) if base_min_sdk is not None else None),
        "target_sdk": manifest_deep.get("sdk", {}).get("target_sdk") or (str(base_target_sdk) if base_target_sdk is not None else None),

        # Manifest + components
        "manifest_deep": manifest_deep,
        "components_summary": comp_summary,

        # Permissions
        "permissions": perms,

        # Backward-compat exported comps quick
        "exported_components": exported_quick,

        # File-level
        "file_forensics": file_info,

        # IOCs (raw)
        "iocs": iocs,

        # Cert/signing
        "certificate": cert,

        # Code hints (deep)
        "code_forensics": {
            "deep_ok": deep_code.get("deep_ok", False),
            "dex_strings_count": deep_code.get("dex_strings_count"),
            "class_names_count": deep_code.get("class_names_count"),
            "method_refs_count": deep_code.get("method_refs_count"),
            "code_hints": deep_code.get("code_hints", {}),
            "obfuscation": deep_code.get("obfuscation", {}),
            "strings_sample": deep_code.get("strings_sample", []),
            "class_names_sample": deep_code.get("class_names_sample", []),
            "method_refs_sample": deep_code.get("method_refs_sample", []),
        },

        # Scoring
        "scoring": scoring,

        # Semantics (so report UI doesn't claim "malware")
        "analysis_type": "static",
        "score_semantics": "Static risk (capability/exposure) 0-20; not a malware verdict",
    }
