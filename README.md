# GitOps Secret Shield 🛡️

> **Enterprise DevSecOps Platform: Preventing Credential Leaks with Pre-Commit Detection, GitHub Webhooks, PostgreSQL Audit Logging, HashiCorp Vault Integration, Automated Credential Rotation & Cyber Security Dashboard.**

---

## 📌 Project Overview

**GitOps Secret Shield** is an end-to-end automated DevSecOps platform built to detect exposed credentials across Git repositories, persist security incident audit logs, securely store replacements in HashiCorp Vault, and automate credential rotation with zero developer friction.

The system enforces a **5-layer defense strategy**:
1. **Shift-Left Pre-Commit Protection**: Local Git hooks inspect staged code with **TruffleHog Docker** and a high-precision Python regex engine to block commits containing secrets.
2. **Centralized GitOps Webhook Detection**: If local hooks are bypassed (`--no-verify`), **GitHub Webhooks** trigger the **FastAPI Backend**, verify HMAC-SHA256 signatures, and inspect changed files and commit diffs.
3. **PostgreSQL Incident Audit Logging**: Every finding is recorded idempotently with a unique incident ID (`INC-YYYYMMDD-XXXX`), status tracking, and strict secret masking (never storing raw credentials).
4. **HashiCorp Vault KV v2 Integration**: Replacement credentials are encrypted and version-controlled at structured paths (`secret/data/gitops-secret-shield/{repo}/{incident_id}`).
5. **Automated Credential Rotation & SOC Dashboard**: Supported credentials (PostgreSQL) are rotated automatically with 32-character high-entropy passwords, while unsupported credentials route to manual remediation playbooks on an interactive React dashboard.

---

## 🏗️ System Architecture & Workflow

```mermaid
flowchart TD
    subgraph Layer1 ["🖥️ Layer 1: Developer Workstation"]
        Dev["Developer Writes Code"]
        GitCommit["git commit"]
        Hook[".git/hooks/pre-commit\n(TruffleHog + Python Engine)"]
        Block["🚫 Commit Blocked\n(Secret Found)"]
        Allow["✅ Commit Allowed\n(Code Clean)"]

        Dev --> GitCommit --> Hook
        Hook -->|Secret Detected| Block
        Hook -->|Clean| Allow
    end

    subgraph Layer2 ["☁️ Layer 2: Centralized GitOps Webhook"]
        GitPush["git push origin main"]
        GitHub["GitHub Repository"]
        Webhook["GitHub Webhook Event\n(X-Hub-Signature-256)"]
        FastAPI["FastAPI Backend\n(/webhooks/github)"]
        Scanner["Scanner Service\n(Regex & Diff Inspection)"]

        Allow --> GitPush --> GitHub --> Webhook --> FastAPI --> Scanner
    end

    subgraph Layer3 ["🗄️ Layer 3: Database Audit Logging"]
        Postgres[("PostgreSQL 16\nPort 5434\n(secret_shield)")]
        IncidentService["Incident Audit Service\n(Idempotent Deduplication)"]
        Masking["Secret Masking Engine\n(AKIA...MPLE)"]

        Scanner --> Masking --> IncidentService --> Postgres
    end

    subgraph Layer4_5 ["🔒 Layers 4 & 5: Vault & Automated Rotation"]
        RotService["Rotation Service\n(Modular Providers)"]
        PGProvider["PostgreSQL Provider\n(32-char Random Password)"]
        ManualFallback["Manual Remediation\n(AWS / GitHub / Stripe)"]
        Vault[("HashiCorp Vault KV v2\nPort 8200")]
        Dashboard["React Security Dashboard\n(/dashboard/)"]

        IncidentService --> RotService
        RotService -->|PostgreSQL URI| PGProvider
        RotService -->|Unsupported| ManualFallback
        PGProvider -->|ALTER ROLE & Save| Vault
        Postgres <--> Dashboard
        Vault <--> Dashboard
    end
```

---

## 🚀 Key Modules & Completed Phases

### Phase 1: PostgreSQL Incident Audit Logging
- **Model & Schema**: `incidents` table with `id`, `incident_id` (`INC-YYYYMMDD-XXXX`), `repository`, `commit_sha`, `author`, `detector_name`, `secret_masked`, `file_path`, `line_number`, `severity`, `status`, `remediation_status`, `vault_secret_path`, `created_at`, `updated_at`.
- **Deduplication Engine**: Composite unique constraint on `(repository, commit_sha, detector_name, file_path, line_number)` ensures duplicate webhook deliveries return the existing incident without creating duplicates.
- **REST API Endpoints**:
  - `GET /api/v1/incidents`: Filter by repository, status, severity with pagination.
  - `GET /api/v1/incidents/stats`: Aggregate security metrics.
  - `GET /api/v1/incidents/{incident_id}`: Incident details.
  - `PATCH /api/v1/incidents/{incident_id}`: Status updates.

### Phase 2: HashiCorp Vault Integration
- **KV v2 Engine**: Runs via Docker Compose on port 8200 in development mode.
- **Structured Secret Path**: `secret/data/gitops-secret-shield/{repository}/{incident_id}`.
- **Vault Service (`app.services.vault_service`)**:
  - `check_health()`: Live health check API (`GET /api/v1/vault/health`).
  - `store_replacement_secret()`: Writes versioned replacement credentials.
  - `get_secret()`: Retrieves decrypted secret metadata.
  - `revoke_secret()`: Soft-deletes compromised versions.

### Phase 3: Automated Credential Rotation
- **Modular Provider Architecture**: `BaseRotationProvider` interface allows plugging in new credential providers.
- **PostgreSQL Rotation Provider (`app.providers.postgres_provider`)**:
  - Generates 32-character high-entropy cryptographic password.
  - Updates PostgreSQL user role via parameterized query.
  - Stores new credentials into HashiCorp Vault KV v2.
  - Sets incident status to `rotated`.
- **Manual Remediation Fallback**: Unsupported providers (AWS, GitHub PAT, Stripe, OpenAI) automatically set incident status to `manual_remediation_required` and generate step-by-step remediation commands.
- **On-Demand Rotation API**: `POST /api/v1/incidents/{incident_id}/rotate`.

### Phase 4: React Security Dashboard
- **Cyber SOC UI**: Built with React 18, Vite, and dark cybersecurity styling.
- **Tabs**:
  1. **Security Overview**: Total leaks, critical metrics, rotation queue, and end-to-end architecture flow.
  2. **Incident Audit Log**: Filterable table with status badges and search.
  3. **Credential Auto-Rotation Console**: Interactive one-click rotation trigger.
  4. **HashiCorp Vault Inspector**: Structured path explorer and decrypted credential preview.
- **Deployment**: Integrated directly into FastAPI (`http://localhost:8000/dashboard/`) and also runnable standalone (`cd frontend && npm run dev`).

---

## 🛠️ Quick Start Guide

### Prerequisites
- Python 3.11+
- Docker Engine & Docker Compose
- Node.js v18+ & npm

### 1. Start Infrastructure (PostgreSQL & HashiCorp Vault)
```powershell
docker compose up -d
```
Verify running containers:
```powershell
docker ps --filter "name=secret-shield"
```
- PostgreSQL: `localhost:5434`
- HashiCorp Vault: `http://localhost:8200` (Token: `root`)

### 2. Configure Environment (`backend/.env`)
```ini
ENVIRONMENT=development
GITHUB_WEBHOOK_SECRET=your_local_test_secret_change_me
GITHUB_TOKEN=your_github_personal_access_token
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5434/secret_shield
```

### 3. Start FastAPI Backend
```powershell
cd backend
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="backend"
uvicorn app.main:app --reload --port 8000
```
- API Base: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`
- Security Dashboard: `http://localhost:8000/dashboard/`

### 4. Optional: Run Standalone React Frontend (Dev Server)
```powershell
cd frontend
npm run dev
```
- React Dev Server: `http://localhost:5173`

---

## 🧪 Verification & Testing

Run the full end-to-end test suite:
```powershell
$env:PYTHONPATH="backend"
python backend/test_full_suite.py
```

Expected output:
```text
============================================================
      GITOPS SECRET SHIELD - COMPREHENSIVE E2E VERIFICATION
============================================================

[STEP 1] System Health Checks
  ✓ FastAPI Backend: Healthy
  ✓ HashiCorp Vault: Healthy (v1.15.6)

[STEP 2] Webhook Secret Detection & Masking
  ✓ Secret Detected: Database Credentials URI
  ✓ Masked Secret: post...host
  ✓ Generated Incident ID: INC-20261119-9AD9E2

[STEP 3] Idempotent Webhook Deduplication
  ✓ Duplicate push recognized without duplicate DB records. Reused: INC-20261119-9AD9E2

[STEP 4] Automated Credential Rotation (PostgreSQL Provider)
  ✓ Rotation executed: rotated
  ✓ Stored in Vault: secret/data/gitops-secret-shield/sanjeewa618/gitops-secret-shield/INC-20261119-9AD9E2

[STEP 5] Cryptographic Verification in Vault KV v2
  ✓ Decrypted Vault Payload: User=app_rotated_role, DB=secret_shield

[STEP 6] Manual Remediation Fallback (Unsupported Provider)
  ✓ Gracefully routed to manual remediation: INC-20261119-F5E866

[STEP 7] React Security Dashboard Availability
  ✓ React Frontend Dashboard served successfully at /dashboard/
  ✓ Dashboard Statistics: Total=5, Critical=5

============================================================
   ALL PHASES (1, 2, 3, 4) VERIFIED AND 100% OPERATIONAL!   
============================================================
```

---

## 📁 Project Structure

```text
GitOps-Secret-Shield/
├── .git/hooks/pre-commit             # Shift-left Git hook (TruffleHog + Python)
├── docker-compose.yml                # PostgreSQL 16 (5434) & Vault 1.15 (8200)
├── README.md                         # Project documentation
├── backend/
│   ├── app/
│   │   ├── config/settings.py        # Centralized settings & environment vars
│   │   ├── database/                 # SQLAlchemy 2.0 Base & session pool
│   │   ├── models/incident.py        # PostgreSQL Incident ORM model
│   │   ├── schemas/incident.py       # Pydantic schemas & response models
│   │   ├── services/
│   │   │   ├── scanner_service.py    # Regex secret detector & masking
│   │   │   ├── github_service.py     # HMAC verification & GitHub REST API
│   │   │   ├── incident_service.py   # PostgreSQL CRUD & deduplication
│   │   │   ├── vault_service.py      # HashiCorp Vault KV v2 client
│   │   │   └── rotation_service.py   # Credential rotation orchestrator
│   │   ├── providers/
│   │   │   ├── base.py               # Provider abstract base class
│   │   │   └── postgres_provider.py  # PostgreSQL automated rotation provider
│   │   ├── routes/
│   │   │   ├── webhook.py            # GitHub webhook push receiver
│   │   │   └── incidents.py          # Incidents & Vault REST API
│   │   └── main.py                   # FastAPI app with static frontend mount
│   ├── test_phase1.py                # Phase 1 verification tests
│   ├── test_phase2_3.py              # Phase 2 & 3 verification tests
│   └── test_full_suite.py            # Comprehensive E2E test suite
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Header.jsx            # Brand & live health pills
    │   │   ├── Overview.jsx          # Metrics & DevSecOps pipeline flow
    │   │   ├── IncidentList.jsx      # Incident audit log with filters
    │   │   ├── RotationConsole.jsx   # One-click auto-rotation console
    │   │   ├── VaultViewer.jsx       # HashiCorp Vault KV v2 inspector
    │   │   └── IncidentDetailModal.jsx# Incident detail & remediation drawer
    │   ├── services/api.js           # REST API client
    │   ├── App.jsx                   # Main layout & navigation
    │   └── main.jsx                  # React entry point
    ├── vite.config.js                # Vite build config
    └── package.json                  # Frontend dependencies
```

---

## 🛡️ Security Best Practices Enforced
- **Zero Raw Secrets in Logs or DB**: All detected credentials are automatically masked (`AKIA...MPLE`) before persistence.
- **Fine-grained GitHub Token**: Dedicated GitHub Personal Access Token for read and comment actions.
- **HMAC-SHA256 Signature Verification**: Constant-time comparison (`hmac.compare_digest`) prevents timing attacks.
- **Strict Role Isolation**: Automated rotation rotates credentials without exposing admin database passwords.
- **Safe Vault Storage**: Versioned KV v2 secrets engine prevents accidental overwrites and maintains historical auditability.
