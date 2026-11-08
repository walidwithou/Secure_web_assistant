"""
Temporary validation script for feature_extractor.py

Runs the extractor against safe and suspicious URLs and checks that:
  * every feature value is in {-1, 0, 1}
  * dict key order == FEATURE_COLUMNS (model input order)
  * safe URLs yield mostly -1 and are not flagged as phishing
  * clearly-suspicious URLs flag several phishing (1) features
  * "ml" encoding maps to {0, 1}

Run from the backend directory:
    python test_features.py
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.phishing.feature_extractor import (  # noqa: E402
    FEATURE_COLUMNS,
    extract_features,
)
from app.services.model_loader import model_service  # noqa: E402


SAFE_URLS = [
    "https://youtube.com/",
    "https://google.com/",
    "https://github.com/",
]

SUSPICIOUS_URLS = [
    "http://192.168.1.1/login",          # raw IP address
    "https://bit.ly/3xAbcDE",            # URL shortener
    "https://login@secure-paypal.com/",  # '@' symbol + hyphenated domain
    "https://secure-account-verify.com/",# hyphen in domain
]


def check_vector(d, url):
    errors = []
    if list(d.keys()) != FEATURE_COLUMNS:
        errors.append(f"{url}: key order != FEATURE_COLUMNS")
    for k, v in d.items():
        if v not in (-1, 0, 1):
            errors.append(f"{url}: {k}={v} not in {{-1,0,1}}")
    return errors


def summarize(d):
    return {
        "1": sum(1 for v in d.values() if v == 1),
        "0": sum(1 for v in d.values() if v == 0),
        "-1": sum(1 for v in d.values() if v == -1),
    }


def main() -> int:
    print("LOADING MODEL", flush=True)
    model_service.load()
    print("MODEL LOADED", flush=True)
    failures = 0

    print("=" * 70, flush=True)
    print("SAFE URLS (expect mostly -1, is_phishing=False, low risk)", flush=True)
    print("=" * 70, flush=True)
    for url in SAFE_URLS:
        print(f"EXTRACTING {url}", flush=True)
        d = extract_features(url, encoding="uci")
        print(f"EXTRACTED {url}", flush=True)
        errs = check_vector(d, url)
        s = summarize(d)
        vec = [d[name] for name in FEATURE_COLUMNS]
        try:
            print(f"PREDICTING {url}", flush=True)
            inf = model_service.predict(vec)
            print(f"PREDICTED {url}", flush=True)
            is_ph = bool(inf["prediction"] == 1)
            conf = float(inf["confidence"])
            prob = float(inf["phishing_probability"])
        except Exception as exc:  # noqa: BLE001
            is_ph, conf, prob = None, None, None
            errs.append(f"{url}: model prediction error: {exc}")

        print(f"\n{url}", flush=True)
        print(f"  counts  -1={s['-1']}  0={s['0']}  1={s['1']}", flush=True)
        print(f"  model   is_phishing={is_ph} confidence={conf} prob={prob}", flush=True)
        if errs:
            failures += 1
            print("  ERRORS:", errs, flush=True)
        else:
            print("  OK", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("SUSPICIOUS URLS (expect several 1 / phishing indicators)", flush=True)
    print("=" * 70, flush=True)
    for url in SUSPICIOUS_URLS:
        print(f"EXTRACTING {url}", flush=True)
        d = extract_features(url, encoding="uci")
        print(f"EXTRACTED {url}", flush=True)
        errs = check_vector(d, url)
        s = summarize(d)
        print(f"\n{url}", flush=True)
        print(f"  counts  -1={s['-1']}  0={s['0']}  1={s['1']}", flush=True)
        ones = [k for k, v in d.items() if v == 1]
        print(f"  phish(1) features: {ones}", flush=True)
        if errs:
            failures += 1
            print("  ERRORS:", errs, flush=True)
        else:
            print("  OK", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("ML ENCODING CHECK (expect values in {0, 1})", flush=True)
    print("=" * 70, flush=True)
    d = extract_features(SAFE_URLS[0], encoding="ml")
    bad = [k for k, v in d.items() if v not in (0, 1)]
    print(f"{SAFE_URLS[0]} -> bad values: {bad if bad else 'none'}", flush=True)
    if bad:
        failures += 1

    print("\n" + "=" * 70, flush=True)
    print(f"RESULT: {'ALL CHECKS PASSED' if failures == 0 else f'{failures} FAILURES'}", flush=True)
    print("=" * 70, flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
