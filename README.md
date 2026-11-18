# GitOps Secret Shield 🛡️

> **Preventing Credential Leaks with Automated Pre-Commit Detection, GitHub Webhooks, and Automated Credential Rotation.**

---

## 📌 Project Overview

**GitOps Secret Shield** is an end-to-end automated DevSecOps security system designed to prevent exposed credentials from entering version control and to instantly remediate accidental leaks.

The system delivers a **multi-layered defense strategy**:
1. **Shift-Left Local Defense**: A local Git pre-commit hook inspects staged code using **TruffleHog** and a high-precision regex engine to **block commits** containing secrets before they ever leave the developer's workstation.
2. **Centralized GitOps Cloud Defense**: If a developer bypasses local hooks (`--no-verify`), **GitHub Webhooks** trigger the **FastAPI Backend**, validating HMAC signatures and scanning pushed commits to initiate automated revocation and rotation via **HashiCorp Vault**.

---

## 🏗️ System Architecture & Workflow

```mermaid
flowchart TD
    subgraph Developer Workstation ["🖥️ Local Developer Environment"]
        Dev["Developer Writes Code"]
        GitAdd["git add ."]
        GitCommit["git commit"]
        PreCommitHook["Git Pre-Commit Hook\n(.git/hooks/pre-commit)"]
        Scanner["TruffleHog Docker / Python Scanner"]
        Block["🚫 Commit BLOCKED\n(Secret Found)"]
        Allow["✅ Commit ALLOWED\n(Code Clean)"]

        Dev --> GitAdd --> GitCommit --> PreCommitHook --> Scanner
        Scanner -->|Secret Detected| Block
        Scanner -->|No Secrets| Allow
    end

    subgraph GitOps Cloud Layer ["☁️ GitOps & Centralized Cloud Layer"]
        GitPush["git push origin main"]
        GitHub["GitHub Repository"]
        Webhook["GitHub Webhook Event\n(X-Hub-Signature-256)"]
        FastAPI["FastAPI Backend\n(/webhooks/github)"]
        HMAC["HMAC-SHA256 Signature Verification"]
        Vault["HashiCorp Vault\n(Secret Revocation & Rotation)"]

        Allow --> GitPush --> GitHub --> Webhook --> FastAPI --> HMAC
        HMAC -->|Verified Event| Vault
    end
```

---

## 🚀 Key Features

- **Pre-Commit Secret Blocking**: Prevents sensitive keys, passwords, and tokens from being committed to Git history.
- **Dual-Engine Detection**:
  - Containerized **TruffleHog** scanner (`trufflesecurity/trufflehog:latest`).
  - Native Python fallback scanner with regex pattern matching.
- **Supported Credential Detectors**:
  - AWS Access Keys (`AKIA...`)
  - GitHub Personal Access Tokens (Classic `ghp_...` & Fine-grained `github_pat_...`)
  - Stripe Secret Keys (`sk_live_...`)
  - Slack API Tokens (`xoxb-...`, `xoxp-...`)
  - OpenAI API Keys (`sk-proj-...`)
  - Google API Keys (`AIzaSy...`)
  - Database Connection URIs (PostgreSQL, MongoDB, MySQL credentials)
  - Cryptographic Private Keys (RSA, EC, DSA, OpenSSH)
  - JSON Web Tokens (JWT)
- **Secure GitHub Webhook Receiver**: Verifies cryptographic HMAC-SHA256 signatures (`X-Hub-Signature-256`) before parsing push events.
- **Masked Security Logging**: Secrets are never logged in plain text; sensitive data is safely masked (e.g. `AKIA...MPLE`).

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| **Backend API** | Python 3.10+, FastAPI, Uvicorn |
| **Security Scanning** | TruffleHog v3, Python Regex Engine |
| **Version Control & Hooks** | Git Hooks (Shell Script), GitHub Webhooks |
| **Secret Management** | HashiCorp Vault *(In Progress)* |
| **Database** | PostgreSQL *(In Progress)* |
| **Containerization** | Docker, Docker Desktop |
| **Frontend Dashboard** | React.js *(Planned)* |

---

## 📂 Project Structure

```text
GitOps-Secret-Shield/
├── .git/hooks/
│   └── pre-commit              # Automated pre-commit security scanner script
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py             # FastAPI entrypoint & router registration
│   │   ├── config/
│   │   │   ├── __init__.py
│   │   │   └── settings.py     # Environment variable configuration
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   └── webhook.py      # GitHub Webhook API endpoint (/webhooks/github)
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── scanner_service.py # Core secret detection engine
│   │   │   ├── github_service.py  # HMAC signature verification & GitHub API
│   │   │   └── vault_service.py   # HashiCorp Vault credential rotation
│   │   └── models/
│   │       ├── __init__.py
│   │       └── incident.py     # Incident & leak audit data models
│   ├── .env.example            # Template for environment variables
│   └── requirements.txt        # Python backend dependencies
├── .gitignore
└── README.md
```

---

## ⚙️ Installation & Setup Guide

### 1. Prerequisites
Ensure you have the following installed on your machine:
- [Python 3.10+](https://www.python.org/downloads/)
- [Git](https://git-scm.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) *(running)*

---

### 2. Clone the Repository
```bash
git clone https://github.com/sanjeewa618/GitOps-Secret-Shield.git
cd GitOps-Secret-Shield
```

---

### 3. Setup Backend Virtual Environment
Navigate to the `backend` directory and create a virtual environment:

#### On Windows (PowerShell):
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

#### On Linux / macOS:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 4. Configure Environment Variables
Copy the `.env.example` file to create your local `.env`:

```powershell
# In the backend directory
Copy-Item .env.example .env
```

Open `.env` and configure your settings:
```env
ENVIRONMENT=development
GITHUB_WEBHOOK_SECRET=your_local_test_secret_change_me
GITHUB_TOKEN=ghp_your_github_personal_access_token_here

VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root

DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/secret_shield
```

---

### 5. Setup the Git Pre-Commit Hook (Local Defense)
The repository includes a pre-commit hook located at `.git/hooks/pre-commit`.

If you just cloned the repository, ensure the hook file is executable:
```bash
# On Linux / macOS / Git Bash
chmod +x .git/hooks/pre-commit
```

#### Test Pre-Commit Detection Locally:
1. **Try committing a dummy secret**:
   ```powershell
   "GITHUB_TOKEN = 'ghp_' + 'TEST_DUMMY_SECRET_KEY_1234567890'" | Out-File -Encoding utf8 test_secret.txt
   git add test_secret.txt
   git commit -m "test: commit fake secret"
   ```
   **Result:** The commit will be **blocked** automatically:
   ```text
   ======================================
          GITOPS SECRET SHIELD
          Secret Detection Scan
   ======================================
   🚨 [SECURITY ALERT] Exposed secret(s) detected in staged files!
      - GitHub Personal Access Token (CRITICAL) in test_secret.txt: ghp_...wxyz
   🚫 Git commit has been BLOCKED by GitOps Secret Shield.
   ```

2. **Clean up test file**:
   ```powershell
   git reset HEAD test_secret.txt
   Remove-Item test_secret.txt
   ```

---

### 6. Run the FastAPI Backend Server
Start the development server from the `backend` folder:

```powershell
python -m uvicorn app.main:app --reload
```

Once running, access:
- **API Status**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### 7. Testing the GitHub Webhook Endpoint
The backend exposes `POST /webhooks/github` which requires an `X-Hub-Signature-256` header signed with `GITHUB_WEBHOOK_SECRET`.

You can test this endpoint using Python:
```python
import hmac, hashlib, json, requests

secret = "your_local_test_secret_change_me"
payload = {
    "repository": {"full_name": "sanjeewa618/GitOps-Secret-Shield"},
    "pusher": {"name": "developer"},
    "commits": [{"id": "abc1234", "message": "commit message"}]
}
body = json.dumps(payload).encode("utf-8")
signature = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

headers = {
    "X-Hub-Signature-256": signature,
    "X-GitHub-Event": "push",
    "Content-Type": "application/json"
}

response = requests.post("http://127.0.0.1:8000/webhooks/github", data=body, headers=headers)
print(response.json())
```

---

## 🗺️ Project Roadmap

- [x] Initial Repository Architecture
- [x] Modular FastAPI Backend Setup
- [x] Docker TruffleHog Pre-Commit Hook Integration
- [x] Multi-Credential Secret Detection Engine (AWS, GitHub, Stripe, DB, Private Keys)
- [x] GitHub Webhook Receiver with HMAC-SHA256 Verification
- [ ] Automated Repository Scanning on Webhook Push Events
- [ ] HashiCorp Vault Integration (Credential Revocation & Automated Rotation)
- [ ] PostgreSQL Audit Database & Event Logging
- [ ] React.js Security Monitoring Dashboard

---

## 📄 License
This project is developed for educational and security research purposes as part of a 6th Semester University Project.
