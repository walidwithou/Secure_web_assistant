# Secure Web Assistant — Hackathon Project Plan

A browser extension backed by a Python API that (1) detects phishing pages with machine learning and (2) scans web applications for SQL injection and XSS vulnerabilities.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Tier 1 — Client (Browser Extension)](#2-tier-1--client-browser-extension)
3. [Tier 2 — Server (FastAPI Backend)](#3-tier-2--server-fastapi-backend)
4. [Tier 3 — Test Subjects & Validation](#4-tier-3--test-subjects--validation)
5. [Tools & Tech Stack](#5-tools--tech-stack)
6. [Project Structure](#6-project-structure)
7. [Key Considerations](#7-key-considerations)

---

## 1. Architecture Overview

| Tier | Component | Technology | Responsibility |
|------|-----------|------------|----------------|
| 1 | Client | Chrome Extension (Manifest V3) | UI, tab monitoring, DOM extraction, warning banners |
| 2 | Server | Python + FastAPI | Phishing ML inference, vulnerability scanning, REST API |
| 3 | Test targets | Juice Shop, DVWA, Metasploitable | Validation environments |

**Flow:** Popup/background worker → REST API (FastAPI) → phishing pipeline *or* scanner pipeline → results returned (sync for phishing, async job polling for scans).

---

## 2. Tier 1 — Client (Browser Extension)

### 2.1 Popup UI (`popup.html` / `popup.js`)
- Scan control buttons: **"Check Phishing"** and **"Run Web Scan"**.
- Tabbed results display:
  - Risk level badges
  - Detected vulnerabilities list
  - Confidence scores

### 2.2 Background Service Worker (`background.js`)
- Listens for tab URL changes.
- Manages REST API requests to the Python backend.
- Handles asynchronous job polling for long vulnerability scans.

### 2.3 Content Script (`content.js`)
- Extracts inline scripts, forms, and DOM details from the active tab when needed.
- Injects warning banners onto suspicious phishing pages.

---

## 3. Tier 2 — Server (FastAPI Backend)

### 3.1 Phishing Page Detector Pipeline

#### Feature Extractor (`feature_extractor.py`)

| Feature type | Features | Required Python libraries |
|--------------|----------|---------------------------|
| **URL Lexical** | UsingIP, LongURL, ShortURL, Symbol@, Redirecting//, PrefixSuffix-, SubDomains, HTTPS, HTTPSDomainURL | `urllib.parse`, `re`, `ipaddress`, `tldextract` |
| **Domain & Network** | DomainRegLen, AgeofDomain, DNSRecording, GoogleIndex, WebsiteTraffic, PageRank | `python-whois`, `dnspython`, `socket` |
| **DOM & HTML Content** | Favicon, NonStdPort, RequestURL, AnchorURL, LinksInScriptTags, ServerFormHandler, InfoEmail, AbnormalURL | `requests`, `beautifulsoup4` |
| **JS & Browser Behavior** | WebsiteForwarding, StatusBarCust, DisableRightClick, UsingPopupWindow, IframeRedirection, LinksPointingToPage, StatsReport | `selenium` or regex on raw response text |

#### Model Training & Evaluation (`train.py`)
1. Load an existing dataset to save time.
2. Train Random Forest / XGBoost classifiers.
3. Compute metrics: accuracy, precision, recall, ROC-AUC.
4. Serialize trained weights to `phishing_model.pkl`.

#### Inference Pipeline
- Load `phishing_model.pkl` in the API and analyze incoming URLs in real time.

### 3.2 Web Application Vulnerability Scanner

#### Crawler & Form Parser (`crawler.py`)
- Recursively discover internal links on the target domain.
- Extract HTML `<form>` inputs, action URLs, HTTP methods (GET/POST), and query parameters.
- Libraries: `requests`, `beautifulsoup4` + Selenium/Playwright.

**Hybrid crawling strategy:**

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Fast path | Fetch the page with `requests` and parse with BeautifulSoup. |
| 2 | Check & evaluate | Were forms, inputs, and links found? **Yes** (e.g., DVWA) → continue with fast parsing. **No**, or an empty SPA shell such as `<div id="app"></div>` (Angular/React apps like Juice Shop) → go to Phase 3. |
| 3 | Heavy path (fallback) | Launch a headless browser (Selenium or Playwright), render the JavaScript, capture the fully populated DOM, then hand it back to BeautifulSoup to extract forms and links. |

#### Payload Injection Engine (`injector.py`)
- **SQLi payloads:** syntax-breaking characters (`'`, `"`, `OR 1=1`, `UNION SELECT`).
- **XSS payloads:** script tags and event handlers (`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`).

#### Custom Heuristics Matcher (`heuristics.py`)
- **SQLi detection:** regex matching for database error messages (MySQL, PostgreSQL, SQLite, MSSQL).
- **XSS detection:** check whether injected payload tags are reflected unescaped in the response DOM.

#### OWASP ZAP Integration *(optional advanced fallback)*
- Connect to a ZAP daemon via the Python ZAP API client for automated active scanning.

### 3.3 REST API Layer (`main.py`)

**Endpoints**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/phishing/analyze` | Synchronous ML prediction |
| POST | `/api/v1/scan/start` | Initialize background crawl & vulnerability scan |
| GET | `/api/v1/scan/status/{job_id}` | Return scan progress and results |

**Middleware & schemas**
- CORS headers configured for the browser extension origin.
- Request/response validation via Pydantic schemas.

---

## 4. Tier 3 — Test Subjects & Validation

| Target | Stack | Purpose |
|--------|-------|---------|
| **OWASP Juice Shop** | Node.js / Angular SPA | Primary bench for client-side XSS detection, SPA crawling, API vulnerabilities |
| **DVWA** | PHP / MySQL | Validate custom SQLi error matching and form-parsing heuristics |
| **Metasploitable VM** | Vulnerable Linux VM | Advanced testing against hosted apps such as Mutillidae and DVWA |

> ⚠️ Only scan systems you own or have explicit permission to test. Use the local targets above.

---

## 5. Tools & Tech Stack

### Tier 1 — Client

| Tool | Role in the project |
|------|---------------------|
| **Manifest V3** (Chrome Extension APIs) | Defines how the service worker, popup, and content scripts are structured and communicate with the browser and backend. |
| **Vanilla JavaScript / HTML / CSS** | Popup UI, background event listeners, DOM extraction, and banner injection. |

### Tier 2 — Backend Frameworks

| Tool | Role in the project |
|------|---------------------|
| **FastAPI** | Hosts all `/api/v1/...` endpoints; chosen for built-in validation and speed. |
| **Pydantic** | Validates incoming JSON and structures outgoing responses using Python type hints. |

### Tier 2.1 — Phishing Pipeline Libraries

| Library | Type | Role |
|---------|------|------|
| `urllib.parse` | stdlib | Split URLs into scheme, netloc, path, query for lexical analysis. |
| `re` | stdlib | Detect malicious patterns (e.g., `@` in URLs, suspicious script tags). |
| `ipaddress` | stdlib | Detect raw IP addresses used instead of domain names. |
| `tldextract` | 3rd party | Isolate subdomain, domain, and TLD; catches spoofs like `google.com.phishing-site.com`. |
| `python-whois` | 3rd party | Fetch domain creation date and registration length to spot new, untrusted domains. |
| `dnspython` | 3rd party | Low-level DNS lookups to verify valid records. |
| `socket` | stdlib | Basic connectivity and IP resolution. |
| `requests` | 3rd party | Fetch page source for static analysis and crawling. |
| `beautifulsoup4` | 3rd party | Build a searchable DOM tree; extract forms, inputs, links. |
| `selenium` / Playwright | 3rd party | Headless rendering of JavaScript-heavy SPAs. |
| `scikit-learn` / `xgboost` | 3rd party | Train Random Forest / XGBoost and serialize to `phishing_model.pkl`. |

### Tier 2.2 — Vulnerability Scanner Libraries

| Library | Role |
|---------|------|
| `requests` + `beautifulsoup4` | Used together in `crawler.py` to map internal links and parse forms for traditional web apps. |
| `python-owasp-zap-v2.4` | Official Python client for OWASP ZAP; optional automated active-scan fallback. |

---

## 6. Project Structure

```text
secure-web-assistant/
│
├── extension/                          # Tier 1: Browser Extension (Manifest V3)
│   ├── manifest.json                   # Extension configuration & permissions
│   ├── icons/                          # Extension icons
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   ├── popup/                          # Popup UI
│   │   ├── popup.html                  # Scan buttons & results layout
│   │   ├── popup.js                    # UI logic & communication with background
│   │   └── popup.css                   # Risk badges & dashboard styling
│   ├── background/
│   │   └── background.js               # URL change listeners & API polling
│   └── content/
│       └── content.js                  # DOM extractor & warning banner injector
│
├── backend/                            # Tier 2: Python Backend (FastAPI)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # App entrypoint & middleware (CORS)
│   │   │
│   │   ├── api/                        # REST API endpoints
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       └── endpoints/
│   │   │           ├── __init__.py
│   │   │           ├── phishing.py     # POST /api/v1/phishing/analyze
│   │   │           └── scanner.py      # POST /api/v1/scan/start & GET /status/{id}
│   │   │
│   │   ├── core/                       # Configuration & security
│   │   │   ├── __init__.py
│   │   │   └── config.py               # App settings, environment variables
│   │   │
│   │   ├── schemas/                    # Pydantic schemas
│   │   │   ├── __init__.py
│   │   │   ├── phishing_schema.py      # Phishing request/response models
│   │   │   └── scanner_schema.py       # Scan request/response models
│   │   │
│   │   ├── models/                     # ML models & serialized weights
│   │   │   ├── __init__.py
│   │   │   ├── train.py                # Train RF/XGBoost on dataset
│   │   │   └── phishing_model.pkl      # Serialized trained model
│   │   │
│   │   └── services/                   # Core security & scanning logic
│   │       ├── __init__.py
│   │       ├── phishing/
│   │       │   ├── __init__.py
│   │       │   └── feature_extractor.py  # Lexical, WHOIS, DNS, DOM features
│   │       └── scanner/
│   │           ├── __init__.py
│   │           ├── crawler.py          # requests/BS4 + Selenium/Playwright hybrid
│   │           ├── injector.py         # SQLi & XSS payload injection
│   │           └── heuristics.py       # DB error matching & DOM reflection check
│   │
│   ├── tests/                          # Unit & integration tests
│   │   ├── test_phishing.py
│   │   └── test_scanner.py
│   │
│   ├── requirements.txt                # fastapi, uvicorn, pydantic, scikit-learn, ...
│   └── Dockerfile                      # Optional: containerize the API
│
├── targets/                            # Tier 3: Local test environments
│   ├── README.md                       # Running DVWA & Juice Shop via Docker
│   └── docker-compose.yaml             # Optional compose file for test targets
│
├── README.md                           # Main documentation & setup guide
└── .gitignore                          # Exclude .pkl, venvs, node_modules, etc.
```

---

## 7. Key Considerations

- **Asynchronous communication:** Use `chrome.alarms` in the service worker to poll scan jobs, so the browser doesn't terminate the worker mid-scan.
- **Crawler error handling:** SPAs and vulnerable apps often return HTTP 500 errors or cause infinite redirect loops. `crawler.py` must include robust **depth limits** and **exception trapping**.
