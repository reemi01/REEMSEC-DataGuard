# REEMSEC DataGuard — Backend

FastAPI backend for sensitive-data and secret exposure scanning.

## Setup (Windows PowerShell)

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `JWT_SECRET_KEY` to a long, unique random value. Never commit `.env`.

## Create the first administrator

```powershell
py -m app.create_admin
```

Follow the prompts to create the admin account.

## Run the API

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

API docs: http://127.0.0.1:8001/docs
Health check: http://127.0.0.1:8001/health

## Frontend

Serve `frontend/index.html` using a local static server and configure the API URL as `http://127.0.0.1:8001`.

## Notes

- The default database is SQLite at `data/reemsec.db`; back it up before upgrades.
- `scan-directory` is intentionally restricted to the backend project root.
- This package is a setup/release-preparation update, not a production deployment certification. Run the full test and security review before public deployment.
