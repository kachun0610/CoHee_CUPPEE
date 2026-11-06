@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  python -m venv .venv
  .venv\Scripts\python -m pip install -r requirements.txt
)
echo Starting CoHee CUPPEE at http://127.0.0.1:5050
.venv\Scripts\python app.py
pause
