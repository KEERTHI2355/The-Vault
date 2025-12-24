# 🗝️ The Vault

### A secure, zero-knowledge, one-time secret sharing application. Create self-destructing messages that can only be read once.


![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![SQL](https://img.shields.io/badge/SQL-Queries-blue?logo=postgresql)
![Streamlit](https://img.shields.io/badge/Streamlit-1.34-red.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)
![API](https://img.shields.io/badge/API-Backend-blue?logo=fastapi)
![Web Development](https://img.shields.io/badge/Web%20Development-Frontend%2FBackend-blue?logo=google-chrome)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)


## 📋 Table of Contents

- [Features](#-features)
- [Architecture Overview](#-architecture-overview)
- [Security Model](#-security-model)
- [How It Works](#-how-it-works)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Security Considerations](#-security-considerations)
- [Development](#-development)


## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Zero-Knowledge** | Server never stores encryption keys - cannot read your secrets |
| 🔥 **One-Time Read** | Secrets are permanently destroyed after viewing |
| ⏱️ **Auto-Expiry** | Unread secrets automatically expire (5 min to 24 hours) |
| 🔑 **Password Protection** | Optional additional authentication layer |
| � **Message Copy Control** | Enable/disable message copying on a per-secret basis |
| �🚦 **Rate Limiting** | Built-in protection against abuse (30 req/min) |
| 💾 **Dual Storage** | Redis (recommended) or SQLite fallback |
| 🎨 **Modern UI** | Clean, responsive Streamlit interface |


## 🏗️ Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           THE VAULT SYSTEM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐         ┌─────────────────┐         ┌──────────────┐  │
│  │             │         │                 │         │              │  │
│  │  STREAMLIT  │◄───────►│    FASTAPI      │◄───────►│   STORAGE    │  │
│  │  FRONTEND   │  HTTP   │    BACKEND      │  Async  │  Redis/SQL   │  │
│  │  (UI/UX)    │         │   (REST API)    │         │              │  │
│  │             │         │                 │         │              │  │
│  └─────────────┘         └────────┬────────┘         └──────────────┘  │
│        │                          │                                     │
│        │                          │                                     │
│        │                 ┌────────▼────────┐                           │
│        │                 │                 │                           │
│        │                 │   UTILS.PY      │                           │
│        │                 │  ┌───────────┐  │                           │
│        │                 │  │ Fernet    │  │                           │
│        │                 │  │ Crypto    │  │                           │
│        │                 │  └───────────┘  │                           │
│        │                 │  ┌───────────┐  │                           │
│        │                 │  │ Password  │  │                           │
│        │                 │  │ Hashing   │  │                           │
│        │                 │  └───────────┘  │                           │
│        │                 │  ┌───────────┐  │                           │
│        │                 │  │ Secret    │  │                           │
│        │                 │  │ Store     │  │                           │
│        │                 │  └───────────┘  │                           │
│        │                 │                 │                           │
│        │                 └─────────────────┘                           │
│        │                                                                │
│        └────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONFIG.PY ─── Pydantic Settings ─── Environment Variables (.env)      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | File | Role |
|-----------|------|------|
| **Frontend** | `frontend.py` | User interface, form handling, link generation |
| **Backend** | `backend.py` | REST API, request validation, business logic |
| **Utils** | `utils.py` | Encryption, password hashing, storage abstraction |
| **Config** | `config.py` | Centralized settings management |


## 🔒 Security Model

### The Zero-Knowledge Approach

The Vault implements a **zero-knowledge** security model. This means:

```text
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT THE SERVER STORES                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ✅ Encrypted Blob      →  Gibberish without the key          │
│   ✅ Secret UUID         →  Random identifier                  │
│   ✅ Expiration Time     →  When to auto-delete                │
│   ✅ Password Hash       →  One-way hash (optional)            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                  WHAT THE SERVER NEVER STORES                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ❌ Original Message    →  Never touches disk                 │
│   ❌ Encryption Key      →  Only in the shareable link         │
│   ❌ Password (plain)    →  Only the hash is stored            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Details

| Algorithm | Purpose | Strength |
|-----------|---------|----------|
| **Fernet** | Symmetric encryption | AES-128-CBC + HMAC-SHA256 |
| **SHA-256** | Password hashing | 256-bit with random salt |
| **UUID4** | Secret identification | 122 bits of randomness |


## 🔄 How It Works

### Step-by-Step Flow Diagram

```text
  SENDER                          SERVER                         DATABASE
    │                               │                               │
    │   1. POST /generate           │                               │
    │   {text: "secret"}            │                               │
    │──────────────────────────────►│                               │
    │                               │                               │
    │                               │  2. Generate Fernet Key       │
    │                               │     Key = Fernet.generate()   │
    │                               │                               │
    │                               │  3. Encrypt Message           │
    │                               │     Blob = encrypt(text, Key) │
    │                               │                               │
    │                               │  4. Generate UUID             │
    │                               │     ID = uuid4()              │
    │                               │                               │
    │                               │  5. Store ONLY encrypted blob │
    │                               │────────────────────────────────►
    │                               │     {ID: Blob, TTL}           │
    │                               │                               │
    │   6. Return ID + Key          │                               │
    │◄──────────────────────────────│                               │
    │   {uuid: ID, key: Key}        │                               │
    │                               │                               │
    │   ════════════════════════════════════════════════════════════
    │   KEY IS NOT STORED ON SERVER - ONLY IN THE RETURNED RESPONSE
    │   ════════════════════════════════════════════════════════════
    │                               │                               │
    │                               │                               │
 RECIPIENT                          │                               │
    │                               │                               │
    │   7. POST /retrieve/{ID}      │                               │
    │   {key: Key}                  │                               │
    │──────────────────────────────►│                               │
    │                               │                               │
    │                               │  8. Fetch encrypted blob      │
    │                               │◄────────────────────────────────
    │                               │                               │
    │                               │  9. DELETE from database      │
    │                               │────────────────────────────────►
    │                               │     (Burn after reading)      │
    │                               │                               │
    │                               │ 10. Decrypt with provided key │
    │                               │     text = decrypt(Blob, Key) │
    │                               │                               │
    │  11. Return decrypted text    │                               │
    │◄──────────────────────────────│                               │
    │   {decrypted_message: text}   │                               │
    │                               │                               │
    ▼                               ▼                               ▼
```

### 🗺️ User Journey

#### Creating a Secret

```text
┌──────────────────────────────────────────────────────────────┐
│  1. USER ENTERS SECRET                                       │
│     ┌────────────────────────────────────────────┐           │
│     │  "My API key is: sk-abc123..."             │           │
│     └────────────────────────────────────────────┘           │
│                          │                                   │
│                          ▼                                   │
│  2. OPTIONALLY SETS PASSWORD & EXPIRY                        │
│     ┌─────────────────┐  ┌─────────────────┐                 │
│     │ Password: ***   │  │ Expires: 1 hour │                 │
│     └─────────────────┘  └─────────────────┘                 │
│                          │                                   │
│                          ▼                                   │
│  3. CLICKS "GENERATE SECURE LINK"                            │
│     ┌────────────────────────────────────────────┐           │
│     │  🔐 Generate Secure Link                   │           │
│     └────────────────────────────────────────────┘           │
│                          │                                   │
│                          ▼                                   │
│  4. RECEIVES ONE-TIME LINK                                   │
│     ┌────────────────────────────────────────────┐           │
│     │  http://localhost:8501/?uuid=xxx&key=yyy   │           │
│     └────────────────────────────────────────────┘           │
│                          │                                   │
│                          ▼                                   │
│  5. SHARES LINK WITH RECIPIENT                               │
│     (via email, chat, etc.)                                  │
└──────────────────────────────────────────────────────────────┘
```

#### Viewing a Secret

```text
┌──────────────────────────────────────────────────────────────┐
│  1. RECIPIENT CLICKS LINK                                    │
│     Browser opens: http://localhost:8501/?uuid=xxx&key=yyy   │
│                          │                                   │
│                          ▼                                   │
│  2. AUTO-NAVIGATED TO "VIEW SECRET" TAB                      │
│     (Link parameters auto-detected)                          │
│                          │                                   │
│                          ▼                                   │
│  3. IF PASSWORD-PROTECTED, ENTERS PASSWORD                   │
│     ┌─────────────────────────────────────────┐              │
│     │  🔒 Enter Password: [__________]        │              │
│     └─────────────────────────────────────────┘              │
│                          │                                   │
│                          ▼                                   │
│  4. CLICKS "REVEAL SECRET"                                   │
│     ┌─────────────────────────────────────────┐              │
│     │  👁️ Reveal Secret                       │              │
│     └─────────────────────────────────────────┘              │
│                          │                                   │
│                          ▼                                   │
│  5. SECRET IS DISPLAYED & DESTROYED                          │
│     ┌─────────────────────────────────────────┐              │
│     │  My API key is: sk-abc123...            │              │
│     │                                         │              │
│     │  ⚠️ This message has been PERMANENTLY   │              │
│     │     DESTROYED. Copy it now!             │              │
│     └─────────────────────────────────────────┘              │
└──────────────────────────────────────────────────────────────┘
```


## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- Redis (optional - falls back to SQLite)

### Installation

```bash
# Navigate to project directory
cd Vault

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env    # Windows
cp .env.example .env      # Linux/Mac
```

### Running the Application

**Terminal 1 - Start Backend:**

```bash
python backend.py
```

**Terminal 2 - Start Frontend:**

```bash
streamlit run frontend.py
```

**Access Points:**

| Service | URL |
|---------|-----|
| Frontend UI | [http://localhost:8501](http://localhost:8501) |
| API Documentation | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Health Check | [http://localhost:8000/health](http://localhost:8000/health) |


## ⚙️ Configuration

Environment variables can be set in a `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | API server bind address |
| `API_PORT` | `8000` | API server port |
| `FRONTEND_URL` | `http://localhost:8501` | Base URL for share links |
| `REDIS_URL` | `None` | Redis connection string (optional) |
| `SQLITE_PATH` | `vault.db` | SQLite database file path |
| `MAX_SECRET_LENGTH` | `50000` | Maximum characters per secret |
| `MAX_TTL_MINUTES` | `1440` | Maximum expiration (24 hours) |
| `RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `RATE_LIMIT_REQUESTS` | `30` | Requests per minute per IP |


## 📡 API Reference

### Health Check

```http
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "storage_backend": "sqlite",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0"
}
```

### Generate Secret

```http
POST /generate
Content-Type: application/json

{
  "text": "my secret message",
  "ttl_minutes": 60,
  "password": "optional-password",
  "copy_enabled": true
}
```

**Response:**

```json
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "key": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==",
  "expires_in": 3600,
  "password_protected": false,
  "copy_enabled": true
}
```

### Check Secret

```http
GET /check/{secret_id}
```

**Response:**

```json
{
  "exists": true,
  "password_protected": false
}
```

### Retrieve Secret

```http
POST /retrieve/{secret_id}
Content-Type: application/json

{
  "key": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==",
  "password": "optional-password"
}
```

**Response (Success):**

```json
{
  "decrypted_message": "my secret message",
  "copy_enabled": true
}
```

**Error Responses:**

| Status | Meaning |
|--------|---------|
| `404` | Secret not found or expired |
| `400` | Invalid decryption key |
| `401` | Password required or incorrect |
| `429` | Rate limit exceeded |


## 🧪 Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_api.py -v

# Run specific test class
pytest tests/test_api.py::TestGenerateEndpoint -v
```

**Test Coverage:**

- `test_utils.py` - 11 tests for encryption and password hashing
- `test_api.py` - 15 tests for all API endpoints


## 📁 Project Structure

```text
Vault/
├── backend.py           # FastAPI REST API application
├── frontend.py          # Streamlit web interface
├── utils.py             # Core utilities (encryption, storage)
├── config.py            # Pydantic settings configuration
├── requirements.txt     # Python package dependencies
├── .env.example         # Environment variables template
├── README.md            # This documentation
├── CODE.md              # Detailed code documentation
├── vault.db             # SQLite database (auto-created)
└── tests/
    ├── __init__.py      # Test package marker
    ├── test_utils.py    # Unit tests for utilities
    └── test_api.py      # Integration tests for API
```


## 🛡️ Security Considerations

### Strengths

| Feature | Benefit |
|---------|---------|
| Zero-Knowledge | Server operators cannot read secrets |
| Forward Secrecy | Each secret has a unique key |
| Burn After Reading | Immediate deletion after retrieval |
| Time-Limited | Auto-expiration prevents indefinite storage |
| Rate Limiting | Prevents brute-force attacks |

### Limitations

| Limitation | Mitigation |
|------------|------------|
| Link exposure = secret exposure | Use password protection |
| Browser history stores links | Use incognito/private browsing |
| No audit trail | By design for privacy |
| Transport security | Always use HTTPS in production |

### Production Recommendations

1. **Deploy with HTTPS** - Use a reverse proxy (nginx/Caddy) with TLS
2. **Use Redis** - Better atomicity and performance than SQLite
3. **Add Security Headers** - CSP, HSTS, X-Frame-Options
4. **Monitor Rate Limits** - Watch for abuse patterns
5. **Regular Backups** - For Redis/database (encrypted data only)


## 🔧 Development

### Code Style

```bash
# Format code
black .

# Sort imports
isort .

# Type checking
mypy .

# Linting
flake8 .
```

### Adding Features

1. Add core logic to `utils.py`
2. Create/update API endpoints in `backend.py`
3. Update UI components in `frontend.py`
4. Write tests in `tests/`
5. Update documentation


## 📄 License

MIT License - See LICENSE file for details.


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Write tests for new functionality
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing`)
6. Open a Pull Request


## 👤 Author

**K Keerthi**  
Data Science Engineering Student  
Aspiring Python Developer / Data Analyst

---

<p align="center">
  🛠 Built by <a href="https://github.com/KEERTHI2355">@Keerthi2355</a> 
  <br>
  <a href="#-the-vault">Back to Top</a>
</p>
