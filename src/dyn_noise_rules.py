# src/dyn_noise_rules.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Set
from urllib.parse import urlparse


_DOMAIN_RX = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def extract_domains_from_urls(urls: List[str] | None) -> List[str]:
    out: Set[str] = set()
    for u in (urls or []):
        try:
            p = urlparse(u.strip())
            host = (p.hostname or "").strip().lower()
            if host:
                host = host[:-1] if host.endswith(".") else host
                out.add(host)
        except Exception:
            continue
    return sorted(out)


@dataclass
class DynNoiseRules:
    """
    Goal:
      - Mark well-known benign domains/emails as noise for scoring
      - Remove obvious SDK/framework/class-token noise that looks like domains
      - Still keep full raw IOC list in artifact for transparency
    """

    # Class/package prefixes to ignore (SDK/framework/ads/common libs)
    class_prefix_noise: List[str] = field(default_factory=lambda: [
        "android.",
        "androidx.",
        "kotlin.",
        "kotlinx.",
        "java.",
        "javax.",
        "sun.",
        "com.android.",
        "dalvik.",
        "org.jetbrains.",
        "org.intellij.",
        "org.json.",
        "org.w3c.",
        "org.xml.",
        "org.chromium.",
        "org.webkit.",
        "okhttp3.",
        "okio.",
        "retrofit2.",
        "rx.",
        "io.reactivex.",
        "com.google.",
        "com.firebase.",
        "com.crashlytics.",
        "com.sentry.",
        "com.squareup.",
        "com.bumptech.glide.",
        "com.facebook.",
        "com.adjust.",
        "com.appsflyer.",
        "com.mixpanel.",
        "com.flurry.",
        "com.segment.",
        "org.slf4j.",
        "ch.qos.logback.",
    ])

    # IMPORTANT: "domain-like" tokens that are actually class/package names.
    # If a "domain" starts with these, treat as benign noise for scoring.
    domain_prefix_noise: List[str] = field(default_factory=lambda: [
        "java.",
        "javax.",
        "android.",
        "androidx.",
        "kotlin.",
        "kotlinx.",
        "dalvik.",
        "okhttp3.",
        "okio.",
        "retrofit2.",
        "org.jetbrains.",
        "org.intellij.",
        "org.json.",
        "org.w3c.",
        "org.xml.",
        "org.chromium.",
        "org.webkit.",
        "com.android.",
        # common method-ish tokens that appear in your earlier reports:
        "inetaddress.",
        "socket.",
        "runtime.",
        "processbuilder.",
        "activity.",
        "httpurlconnection.",
        "webview.",
    ])

    # Domains we treat as benign (do NOT count in scoring)
    domain_allow_suffix: List[str] = field(default_factory=lambda: [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googlesyndication.com",
        "googleadservices.com",
        "doubleclick.net",
        "firebaseio.com",
        "crashlytics.com",
        "sentry.io",
        "github.com",
        "githubusercontent.com",
        "android.com",
        "play.google.com",
        "mozilla.org",
        "mozilla.com",
        "fdroid.org",
        "f-droid.org",
        "letsencrypt.org",
        "cloudflare.com",
        "cloudflare-dns.com",
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "tiktok.com",
        "youtube.com",
        "ytimg.com",
        "twitter.com",
        "x.com",
        "microsoft.com",
        "windows.net",
        "apple.com",
        "icloud.com",
        "amazonaws.com",
        # instrumentation-related benign docs
        "frida.re",
    ])

    # Exact domains you want to allow even if not suffix-matching
    domain_allow_exact: Set[str] = field(default_factory=lambda: {
        "www.google.com",
        "www.youtube.com",
        "www.instagram.com",
        "www.tiktok.com",
        "www.example.com",
        "support.google.com",
        "frida.re",
    })

    # Email allow patterns (crash reporting / placeholders / SDK)
    email_allow_rx: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r".+@sentry\.io$", re.IGNORECASE),
        re.compile(r".+@.*sentry\..+$", re.IGNORECASE),
        re.compile(r".+@crashlytics\..+$", re.IGNORECASE),
        re.compile(r".+@.*firebase\..+$", re.IGNORECASE),
        re.compile(r"^android@android\.com$", re.IGNORECASE),
        re.compile(r".+@.*\.example$", re.IGNORECASE),
    ])

    # Extra: some strings you consider always-noise in "classes"
    class_contains_noise: List[str] = field(default_factory=lambda: [
        "view",
        "widget",
        "layout",
        "drawable",
        "serializer",
        "deserializer",
        "adapter",
        "databinding",
        "workmanager",
        "recyclerview",
        "compose",
        "coroutine",
        "kotlin",
        "rxjava",
        "okhttp",
        "retrofit",
        "glide",
        "firebase",
        "crashlytics",
        "sentry",
    ])

    def is_noise_class(self, cls: str) -> bool:
        if not cls:
            return True
        c = cls.strip()
        if not c:
            return True

        lc = c.lower()

        for p in self.class_prefix_noise:
            if lc.startswith(p):
                return True

        if len(lc) <= 2:
            return True

        if "rro" in lc or "buildconfig" in lc or "auto_generated" in lc:
            return True

        dot_count = lc.count(".")
        if dot_count >= 1:
            for k in self.class_contains_noise:
                if k in lc:
                    return True

        return False

    def _normalize_domain(self, d: str) -> str:
        d = (d or "").strip().lower()
        if d.endswith("."):
            d = d[:-1]
        return d

    def is_benign_domain(self, domain: str) -> bool:
        d = self._normalize_domain(domain)
        if not d:
            return True

        # If it looks like a Java/SDK token, treat as benign noise.
        for pfx in self.domain_prefix_noise:
            if d.startswith(pfx):
                return True

        if d in self.domain_allow_exact:
            return True

        # if it doesn't look like a real domain, treat as benign
        if not _DOMAIN_RX.match(d):
            return True

        for suf in self.domain_allow_suffix:
            suf = suf.lower().strip()
            if d == suf or d.endswith("." + suf):
                return True

        return False

    def is_benign_email(self, email: str) -> bool:
        e = (email or "").strip()
        if not e or "@" not in e:
            return True
        for rx in self.email_allow_rx:
            if rx.match(e):
                return True
        return False

    def infer_benign_libs_from_classes(self, classes_total: Iterable[str]) -> List[str]:
        lc = " ".join((c or "").lower() for c in classes_total or [])
        found: List[str] = []

        def add(name: str, *keys: str):
            for k in keys:
                if k in lc:
                    found.append(name)
                    return

        add("AndroidX", "androidx.")
        add("Kotlin", "kotlin.")
        add("OkHttp", "okhttp")
        add("Retrofit", "retrofit")
        add("RxJava", "rxjava", "io.reactivex")
        add("Glide", "glide")
        add("Firebase", "firebase")
        add("Crashlytics", "crashlytics")
        add("Sentry", "sentry")
        add("Google Play Services", "com.google.android.gms", "play-services")
        add("Facebook SDK", "com.facebook")
        add("Compose", "compose")
        add("Frida", "frida")

        out = []
        seen = set()
        for x in found:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
