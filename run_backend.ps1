Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   Starting GitOps Secret Shield Backend...   " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan

Set-Location "$PSScriptRoot\backend"
$env:PYTHONPATH = "$PSScriptRoot\backend"

Write-Host "Dashboard will be available at: http://localhost:8000/dashboard/" -ForegroundColor Yellow
Write-Host "Swagger Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor Gray

& ".\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8000
