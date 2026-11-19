@echo off
title GitOps Secret Shield Backend
echo ==============================================
echo    Starting GitOps Secret Shield Backend...
echo ==============================================
cd /d "%~dp0backend"
set PYTHONPATH=%~dp0backend
echo Dashboard will be available at: http://localhost:8000/dashboard/
echo Swagger Docs: http://localhost:8000/docs
echo.
".\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8000
pause
