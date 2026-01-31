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
                # strip trailing dot
                host = host[:-1] if host.endswith(".") else host
                out.add(host)
        except Exception:
            continue
    return sorted(out)


@dataclass
class DynNoiseRules:
    """
    Goal:
      - Remove obvious SDK/framework class noise from 'classes' list
      - Mark well-known benign domains/emails as noise for scoring
      - Still keep full data in iocs_split for transparency
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
    ])

    # Exact domains you want to allow even if not suffix-matching
    domain_allow_exact: Set[str] = field(default_factory=lambda: {
        "www.google.com",
        "www.youtube.com",
        "www.instagram.com",
        "www.tiktok.com",
        "www.example.com",
        "support.google.com",
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

        # prefix noise (strong)
        for p in self.class_prefix_noise:
            if lc.startswith(p):
                return True

        # very short tokens are mostly junk
        if len(lc) <= 2:
            return True

        # internal generated / rro / build config
        if "rro" in lc or "buildconfig" in lc or "auto_generated" in lc:
            return True

        # contains-noise heuristic (weak) — only if token looks like framework-ish
        # (prevents filtering app-specific classes too aggressively)
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

        if d in self.domain_allow_exact:
            return True

        # if it doesn't look like a domain, treat as benign noise for scoring
        # (prevents "state." etc from becoming "domains")
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
        """
        Quick "what benign SDKs were observed" based on class tokens.
        Used only for reporting/debug.
        """
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

        # unique, stable order
        out = []
        seen = set()
        for x in found:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
