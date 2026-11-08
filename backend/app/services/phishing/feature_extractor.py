"""
Feature Extractor for Phishing Detection
========================================

Extracts the 30 phishing features used in backend/data/phishing.csv (minus
the Index and class columns) from a single URL.

All feature values follow the UCI / dataset encoding {-1, 0, 1}:

* -1 = legitimate / safe indicator
*  0 = suspicious / intermediate
*  1 = phishing / malicious indicator

Features that require external data (GoogleIndex, WebsiteTraffic, PageRank)
are returned as -1 (unknown / safe placeholder) until an external API key is
configured.  Any feature that cannot be resolved because of a network
timeout, DNS failure, or missing DOM defaults to -1 (safe) or 0 (neutral) --
never to 1 (phishing) -- so transient failures never trigger false positives.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import threading
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
try:
    import tldextract
except Exception:  # pragma: no cover - tldextract may not be installed
    tldextract = None  # type: ignore[assignment]

try:
    import whois  # python-whois
except Exception:  # pragma: no cover - whois may not be installed
    whois = None  # type: ignore[assignment]

try:
    import dns.resolver  # dnspython
except Exception:  # pragma: no cover - dnspython may not be installed
    dns = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Exact feature column order from phishing.csv (columns 2 through 31,
# excluding Index and class).
# ---------------------------------------------------------------------------
FEATURE_COLUMNS: list[str] = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport",
]

# Known URL-shortening services (hostnames only).
SHORTENING_SERVICES: set[str] = {
    "bit.ly", "bitly.is", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "rebrand.ly", "cutt.ly", "tiny.cc", "tr.im",
    "cli.gs", "bitly.com", "soo.gd", "s2r.co", "click.me", "po.st", "vt.tc",
    "lnkd.in", "db.tt", "qr.ae", "aty.my", "link.biz", "filoops.info",
    "url.ie", "1url.com", "tweez.me", "v.gd", "tr.im", "zip.net",
    "cut-url.com", "short.to", "1link.in", "nn.nk", "x.co", "prettylink.pro",
}

# Thresholds for percentage-based features.
RESOURCE_LOW = 22.0   # RequestURL / LinksPointingToPage low threshold (%)
RESOURCE_HIGH = 61.0  # RequestURL / LinksPointingToPage high threshold (%)
ANCHOR_LOW = 31.0     # AnchorURL low threshold (%)
ANCHOR_HIGH = 67.0    # AnchorURL high threshold (%)
SCRIPT_LOW = 17.0     # LinksInScriptTags low threshold (%)
SCRIPT_HIGH = 81.0    # LinksInScriptTags high threshold (%)

# URL length thresholds.
URL_SHORT = 54
URL_MEDIUM_MAX = 75

# Domain age thresholds (days).
DOMAIN_MIN_AGE_DAYS = 180   # AgeofDomain
DOMAIN_MIN_REG_LEN_DAYS = 365  # DomainRegLen

# HTTP timeout for page fetches (seconds) -- kept low for real-time API.
REQUEST_TIMEOUT = 3

# WHOIS / DNS lookup timeout (seconds).
WHOIS_TIMEOUT = 3
DNS_TIMEOUT = 3

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# ---------------------------------------------------------------------------
# URL parsing helper
# ---------------------------------------------------------------------------


class URLParts:
    """Cached parsed components of a URL."""

    def __init__(self, url: str) -> None:
        self.raw_url: str = url.strip()
        if not self.raw_url:
            raise ValueError("URL cannot be empty")

        # Normalise scheme.
        if "://" not in self.raw_url:
            self.raw_url = "http://" + self.raw_url

        parsed = urlparse(self.raw_url)
        self.scheme: str = parsed.scheme.lower() or "http"
        self.hostname: str = (parsed.hostname or "").lower()
        self.port: int | None = parsed.port
        self.path: str = parsed.path or "/"
        self.full_url: str = self.raw_url
        self.url_length: int = len(self.raw_url)

        # tldextract splits into subdomain / domain / suffix.
        # Fallback to urllib.parse if tldextract is unavailable.
        if tldextract is not None:
            extracted = tldextract.extract(self.raw_url)
            self.subdomain: str = (extracted.subdomain or "").lower()
            self.domain: str = (extracted.domain or "").lower()
            self.suffix: str = (extracted.suffix or "").lower()
        else:
            # Simple fallback: hostname is domain, no subdomain/suffix split.
            self.subdomain: str = ""
            self.domain: str = self.hostname
            self.suffix: str = ""
        self.registered_domain: str = (
            f"{self.domain}.{self.suffix}" if self.suffix else self.domain
        )

        # IP-address detection.
        self.is_ip: bool = False
        if self.hostname:
            try:
                ipaddress.ip_address(self.hostname)
                self.is_ip = True
            except ValueError:
                self.is_ip = False

# ---------------------------------------------------------------------------
# Page fetch helper (lazy, with safe defaults on failure)
# ---------------------------------------------------------------------------


class PageContext:
    """Lazily fetches a page and parses its HTML."""

    def __init__(self, url_parts: URLParts) -> None:
        self.url_parts = url_parts
        self._fetched: bool = False
        self.raw_text: str = ""
        self.soup: BeautifulSoup | None = None
        self.final_url: str = url_parts.raw_url
        self.status_code: int | None = None

    def fetch(self) -> None:
        if self._fetched:
            return
        self._fetched = True
        try:
            resp = requests.get(
                self.url_parts.raw_url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": _USER_AGENT},
                allow_redirects=True,
            )
            self.status_code = resp.status_code
            self.final_url = resp.url
            self.raw_text = resp.text or ""
            self.soup = BeautifulSoup(self.raw_text, "html.parser")
        except Exception:
            # Any network failure ? safe defaults; never propagate.
            self.raw_text = ""
            self.soup = BeautifulSoup("", "html.parser")
            self.final_url = self.url_parts.raw_url
            self.status_code = None


# ---------------------------------------------------------------------------
# WHOIS cache (per-process, avoids rate limiting)
# ---------------------------------------------------------------------------

_whois_cache: dict[str, dict[str, Any] | None] = {}
_whois_cache_lock = threading.Lock()


def _whois_lookup(domain: str) -> dict[str, Any] | None:
    """Look up WHOIS data with a hard timeout; returns None on any failure."""
    if not domain or whois is None:
        return None
    with _whois_cache_lock:
        if domain in _whois_cache:
            return _whois_cache[domain]

    result: dict[str, Any] = {}

    def _fetch() -> None:
        try:
            result["w"] = whois.whois(domain)
        except Exception as exc:  # noqa: BLE001
            result["exc"] = exc

    thread = threading.Thread(target=_fetch, daemon=True)
    thread.start()
    thread.join(timeout=WHOIS_TIMEOUT)

    if thread.is_alive():
        # Lookup timed out (e.g. whois server unreachable) -> treat as unknown.
        with _whois_cache_lock:
            _whois_cache[domain] = None
        return None

    if "exc" in result:
        with _whois_cache_lock:
            _whois_cache[domain] = None
        return None

    with _whois_cache_lock:
        _whois_cache[domain] = result.get("w")
    return result.get("w")


def _extract_date(value: Any) -> Any:
    """whois may return a single datetime or a list of datetimes."""
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------


class FeatureExtractor:
    """Computes all 30 phishing features for a URL."""

    def __init__(self, url: str) -> None:
        self.parts = URLParts(url)
        self.page = PageContext(self.parts)

    # -- URL lexical (no network) ------------------------------------------

    def _using_ip(self) -> int:
        """1 = raw IP address (phishing), -1 = domain name (safe)."""
        return 1 if self.parts.is_ip else -1

    def _long_url(self) -> int:
        """-1 = <54 chars (safe), 0 = 54-75 (suspicious), 1 = >75 (phishing)."""
        length = self.parts.url_length
        if length < URL_SHORT:
            return -1
        if length <= URL_MEDIUM_MAX:
            return 0
        return 1

    def _short_url(self) -> int:
        """1 = URL-shortening service (phishing), -1 = not (safe)."""
        return 1 if self.parts.hostname in SHORTENING_SERVICES else -1

    def _symbol_at(self) -> int:
        """1 = '@' present in URL (phishing), -1 = absent (safe)."""
        return 1 if "@" in self.parts.raw_url else -1

    def _redirecting(self) -> int:
        """1 = '//' appears after position 7 (phishing), -1 = not (safe)."""
        return 1 if "//" in self.parts.raw_url[7:] else -1

    def _prefix_suffix(self) -> int:
        """1 = hyphen in registered domain (phishing), -1 = none (safe)."""
        return 1 if "-" in self.parts.registered_domain else -1

    def _subdomains(self) -> int:
        """-1 = 0-1 dots (safe), 0 = 2 dots (suspicious), 1 = 3+ dots (phishing)."""
        dots = self.parts.subdomain.count(".") if self.parts.subdomain else 0
        if dots <= 1:
            return -1
        if dots == 2:
            return 0
        return 1

    def _https(self) -> int:
        """-1 = https scheme (safe), 1 = http/other (phishing)."""
        return -1 if self.parts.scheme == "https" else 1

    def _https_domain_url(self) -> int:
        """1 = 'https' literal in hostname (phishing), -1 = not (safe)."""
        return 1 if "https" in self.parts.hostname else -1

    # -- Domain & network ---------------------------------------------------

    def _domain_reg_len(self) -> int:
        """-1 = registration = 1 year / unknown (safe), 0 = < 1 year (suspicious)."""
        w = _whois_lookup(self.parts.registered_domain)
        if w is None:
            return -1
        try:
            creation = _extract_date(w.creation_date)
            expiration = _extract_date(w.expiration_date)
            if creation is None or expiration is None:
                return -1
            delta = (expiration - creation).days
            return -1 if delta >= DOMAIN_MIN_REG_LEN_DAYS else 0
        except Exception:
            return -1

    def _age_of_domain(self) -> int:
        """-1 = domain age = 180 days / unknown (safe), 0 = < 180 days (suspicious)."""
        w = _whois_lookup(self.parts.registered_domain)
        if w is None:
            return -1
        try:
            creation = _extract_date(w.creation_date)
            if creation is None:
                return -1
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (now - creation).days
            return -1 if age_days >= DOMAIN_MIN_AGE_DAYS else 0
        except Exception:
            return -1

    def _dns_recording(self) -> int:
        """-1 = DNS resolves (safe), 1 = does not resolve (phishing)."""
        host = self.parts.hostname
        if not host:
            return -1
        try:
            if dns is not None:
                dns.resolver.resolve(host, "A", lifetime=DNS_TIMEOUT)
                return -1
            socket.setdefaulttimeout(DNS_TIMEOUT)
            socket.gethostbyname(host)
            return -1
        except Exception:
            # Cannot confirm DNS record -- fail safe (legitimate) rather than
            # flagging a transient resolution failure as phishing.
            return -1

    # -- DOM & HTML content -------------------------------------------------

    def _favicon(self) -> int:
        """1 = external favicon (phishing), -1 = internal/empty/none (safe)."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        href = icon.get("href") if icon else None
        if not href:
            return -1
        try:
            href_parsed = urlparse(href)
            href_host = (href_parsed.hostname or "").lower()
            if not href_host:
                return -1
            return 1 if href_host != self.parts.hostname else -1
        except Exception:
            return -1

    def _non_std_port(self) -> int:
        """1 = non-standard port (phishing), -1 = 80/443/None (safe)."""
        port = self.parts.port
        if port is None:
            return -1
        if port in (80, 443):
            return -1
        return 1

    def _request_url(self) -> int:
        """% of embedded resources external; -1/0/1 by thresholds."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        tags = soup.find_all(["img", "script", "link", "iframe", "source"])
        if not tags:
            return -1
        external = 0
        for tag in tags:
            src = tag.get("src") or tag.get("href")
            if not src:
                continue
            try:
                src_parsed = urlparse(src)
                src_host = (src_parsed.hostname or "").lower()
                if src_host and src_host != self.parts.hostname:
                    external += 1
            except Exception:
                continue
        pct = (external / len(tags)) * 100
        if pct < RESOURCE_LOW:
            return -1
        if pct <= RESOURCE_HIGH:
            return 0
        return 1

    def _anchor_url(self) -> int:
        """% of <a href> external; -1/0/1 by thresholds."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        anchors = soup.find_all("a", href=True)
        if not anchors:
            return -1
        external = 0
        for a in anchors:
            href = a["href"]
            try:
                href_parsed = urlparse(href)
                href_host = (href_parsed.hostname or "").lower()
                if href_host and href_host != self.parts.hostname:
                    external += 1
            except Exception:
                continue
        pct = (external / len(anchors)) * 100
        if pct < ANCHOR_LOW:
            return -1
        if pct <= ANCHOR_HIGH:
            return 0
        return 1

    def _links_in_script_tags(self) -> int:
        """% of script tags with external src; -1/0/1 by thresholds."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        scripts = soup.find_all("script", src=True)
        if not scripts:
            return -1
        external = 0
        for s in scripts:
            src = s["src"]
            try:
                src_parsed = urlparse(src)
                src_host = (src_parsed.hostname or "").lower()
                if src_host and src_host != self.parts.hostname:
                    external += 1
            except Exception:
                continue
        pct = (external / len(scripts)) * 100
        if pct < SCRIPT_LOW:
            return -1
        if pct <= SCRIPT_HIGH:
            return 0
        return 1

    def _server_form_handler(self) -> int:
        """1 = empty/about:blank/external (phishing), 0 = relative (suspicious), -1 = same domain (safe)."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        forms = soup.find_all("form")
        if not forms:
            return -1
        action = forms[0].get("action", "") or ""
        action = action.strip().lower()
        if action in ("", "about:blank"):
            return 1
        try:
            parsed = urlparse(action)
            host = (parsed.hostname or "").lower()
            if not host:
                return 0  # relative URL
            if host == self.parts.hostname:
                return -1  # same domain
            return 1  # external domain
        except Exception:
            return -1

    def _info_email(self) -> int:
        """1 = email address in form fields/actions (phishing), -1 = none (safe)."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        search_text = ""
        for form in soup.find_all("form"):
            search_text += " " + str(form)
        if _EMAIL_RE.search(search_text):
            return 1
        return -1

    def _abnormal_url(self) -> int:
        """-1 = hostname matches final URL or appears in body (safe), 1 = abnormal (phishing)."""
        self.page.fetch()
        host = self.parts.hostname
        if not host:
            return -1
        final_host = (urlparse(self.page.final_url).hostname or "").lower()
        if host == final_host:
            return -1
        if host in self.page.raw_text:
            return -1
        return 1

    # -- JS & browser behaviour (regex on raw HTML) ------------------------

    def _website_forwarding(self) -> int:
        """1 = redirect detected (phishing), -1 = none (safe)."""
        self.page.fetch()
        text = self.page.raw_text
        patterns = [
            r'<meta[^>]+http-equiv=["\']refresh["\']',
            r'window\.location\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',
        ]
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return 1
        return -1

    def _status_bar_cust(self) -> int:
        """1 = window.status overridden (phishing), -1 = not (safe)."""
        self.page.fetch()
        text = self.page.raw_text
        if re.search(r"window\.status\s*=", text, re.IGNORECASE):
            return 1
        if re.search(r"status\s*=", text, re.IGNORECASE):
            return 1
        return -1

    def _disable_right_click(self) -> int:
        """1 = right-click disabled (phishing), -1 = enabled (safe)."""
        self.page.fetch()
        text = self.page.raw_text
        if re.search(r"oncontextmenu", text, re.IGNORECASE):
            return 1
        if re.search(r"event\.button\s*==\s*2", text):
            return 1
        return -1

    def _using_popup_window(self) -> int:
        """1 = window.open used (phishing), -1 = not (safe)."""
        self.page.fetch()
        text = self.page.raw_text
        if re.search(r"window\.open\s*\(", text, re.IGNORECASE):
            return 1
        return -1

    def _iframe_redirection(self) -> int:
        """1 = external iframe src (phishing), -1 = none / internal (safe)."""
        self.page.fetch()
        soup = self.page.soup
        if soup is None:
            return -1
        iframes = soup.find_all("iframe", src=True)
        for iframe in iframes:
            src = iframe["src"]
            try:
                src_parsed = urlparse(src)
                src_host = (src_parsed.hostname or "").lower()
                if src_host and src_host != self.parts.hostname:
                    return 1
            except Exception:
                continue
        return -1

    def _links_pointing_to_page(self) -> int:
        """Same % logic as RequestURL; -1/0/1 by thresholds."""
        return self._request_url()

    def _stats_report(self) -> int:
        """1 = suspicious site-report patterns (phishing), -1 = not (safe)."""
        self.page.fetch()
        text = self.page.raw_text
        suspicious = [
            "site:report",
            "phishing report",
            "suspicious site",
            "report this site",
            "unsafe website",
        ]
        for pat in suspicious:
            if re.search(pat, text, re.IGNORECASE):
                return 1
        return -1

    # Placeholder external-reputation features (no public API configured).
    def _google_index(self) -> int:
        """Placeholder: no free public Google index API ? -1 (safe unknown)."""
        return -1

    def _website_traffic(self) -> int:
        """Placeholder: no free public traffic API ? -1 (safe unknown)."""
        return -1

    def _pagerank(self) -> int:
        """Placeholder: Google PageRank discontinued ? -1 (safe unknown)."""
        return -1

    # -- Public orchestrator ------------------------------------------------

    def extract(self, encoding: str = "uci") -> dict[str, int]:
        """Return all 30 features as a dict in FEATURE_COLUMNS order."""
        raw: dict[str, int] = {
            "UsingIP": self._using_ip(),
            "LongURL": self._long_url(),
            "ShortURL": self._short_url(),
            "Symbol@": self._symbol_at(),
            "Redirecting//": self._redirecting(),
            "PrefixSuffix-": self._prefix_suffix(),
            "SubDomains": self._subdomains(),
            "HTTPS": self._https(),
            "DomainRegLen": self._domain_reg_len(),
            "Favicon": self._favicon(),
            "NonStdPort": self._non_std_port(),
            "HTTPSDomainURL": self._https_domain_url(),
            "RequestURL": self._request_url(),
            "AnchorURL": self._anchor_url(),
            "LinksInScriptTags": self._links_in_script_tags(),
            "ServerFormHandler": self._server_form_handler(),
            "InfoEmail": self._info_email(),
            "AbnormalURL": self._abnormal_url(),
            "WebsiteForwarding": self._website_forwarding(),
            "StatusBarCust": self._status_bar_cust(),
            "DisableRightClick": self._disable_right_click(),
            "UsingPopupWindow": self._using_popup_window(),
            "IframeRedirection": self._iframe_redirection(),
            "AgeofDomain": self._age_of_domain(),
            "DNSRecording": self._dns_recording(),
            "WebsiteTraffic": self._website_traffic(),
            "PageRank": self._pagerank(),
            "GoogleIndex": self._google_index(),
            "LinksPointingToPage": self._links_pointing_to_page(),
            "StatsReport": self._stats_report(),
        }

        if encoding == "ml":
            return {k: (1 if v == 1 else 0) for k, v in raw.items()}
        return raw


# ---------------------------------------------------------------------------
# Module-level public API
# ---------------------------------------------------------------------------


def extract_features(url: str, encoding: str = "uci") -> dict[str, int]:
    """
    Extract all 30 phishing features from a URL.

    Parameters
    ----------
    url : str
        Target URL.
    encoding : str, default "uci"
        ``"uci"`` returns values in ``{-1, 0, 1}`` (matches ``phishing.csv``).
        ``"ml"`` maps ``{-1, 0}`` to ``0`` and ``1`` to ``1``.

    Returns
    -------
    dict[str, int]
        Dictionary with exactly the 30 ``FEATURE_COLUMNS`` keys in CSV order.
        Never includes ``Index`` or ``class``.
    """
    extractor = FeatureExtractor(url)
    return extractor.extract(encoding=encoding)


def extract_features_dataframe(
    urls: list[str] | tuple[str, ...], encoding: str = "uci"
) -> "pd.DataFrame":
    """
    Extract features for a list of URLs and return a ``pandas.DataFrame``.

    Parameters
    ----------
    urls : list[str] | tuple[str, ...]
        List or tuple of target URLs. A bare string is rejected to prevent
        accidental character-by-character iteration.
    encoding : str, default "uci"
        ``"uci"`` or ``"ml"`` (see :func:`extract_features`).

    Returns
    -------
    pd.DataFrame
        DataFrame with columns exactly ``FEATURE_COLUMNS`` in order, one row
        per input URL.

    Raises
    ------
    TypeError
        If ``urls`` is a string or any non-list/tuple type.
    """
    import pandas as pd

    # Reject bare strings explicitly to avoid silent char-by-char iteration.
    if isinstance(urls, str):
        raise TypeError(
            "extract_features_dataframe() expects a list or tuple of URLs, "
            f"but received a str: '{urls}'. "
            "Wrap it in a list: extract_features_dataframe([url])"
        )

    if not isinstance(urls, (list, tuple)):
        raise TypeError(
            f"extract_features_dataframe() expects a list or tuple of URLs, "
            f"but received {type(urls).__name__}."
        )

    # Empty input ? empty DataFrame with correct schema.
    if len(urls) == 0:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    rows = [extract_features(u, encoding=encoding) for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
