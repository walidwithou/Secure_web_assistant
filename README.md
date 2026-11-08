# Secure_web_assistant
A Multi function browser extension that detectes website vulnerability and phishing potential 





## Starting the server

From the backend directory:

```powershell
cd \backend

# 1. Install dependencies (once)
pip install -r requirements.txt

# 2. Start with Uvicorn (development)
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The app will load `model.pkl` **once** at startup (via FastAPI lifespan) and listen on `http://127.0.0.1:8000`.

**Production (Gunicorn):**
```powershell
gunicorn -c gunicorn_conf.py app.main:app
```

**Health check:**
```powershell
curl http://127.0.0.1:8000/health
# → {"status":"ok","model_loaded":true}
```

---

## Example request

**Endpoint:** `POST /api/v1/phishing/analyze`

```powershell
curl -X POST http://127.0.0.1:8000/api/v1/phishing/analyze `
  -H "Content-Type: application/json" `
  -d '{
    "url": "https://example.com",
    "html_content": "<html><body>...</body></html>"
  }'
```

*(Note: `html_content` is optional and accepted for future use; the current feature extractor fetches the DOM from the URL itself.)*

### Example response (legitimate site)

```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence_score": 1.0,
  "risk_level": "LOW",
  "features_extracted": {
    "UsingIP": 0,
    "LongURL": 0,
    "ShortURL": 0,
    "Symbol@": 0,
    "Redirecting//": 0,
    "PrefixSuffix-": 0,
    "SubDomains": 0,
    "HTTPS": 1,
    "DomainRegLen": -1,
    "Favicon": 1,
    "NonStdPort": 1,
    "HTTPSDomainURL": -1,
    "RequestURL": 1,
    "AnchorURL": 0,
    "LinksInScriptTags": -1,
    "ServerFormHandler": -1,
    "InfoEmail": 1,
    "AbnormalURL": 1,
    "WebsiteForwarding": 0,
    "StatusBarCust": 1,
    "DisableRightClick": 1,
    "UsingPopupWindow": 1,
    "IframeRedirection": 1,
    "AgeofDomain": -1,
    "DNSRecording": -1,
    "WebsiteTraffic": 0,
    "PageRank": -1,
    "GoogleIndex": 1,
    "LinksPointingToPage": 1,
    "StatsReport": 1
  }
}
```

### Response field meanings
| Field | Meaning |
|-------|---------|
| `is_phishing` | `true` if phishing detected, `false` otherwise |
| `confidence_score` | Model confidence for the predicted class (`0.0`–`1.0`) |
| `risk_level` | `"LOW"` (<0.5), `"MEDIUM"` (0.5–0.79), `"HIGH"` (≥0.8) |
| `features_extracted` | The 30 UCI-encoded features keyed by column name |

### Error examples
- **Bad URL** → `HTTP 400` with validation detail
- **Inference failure** → `HTTP 500`
