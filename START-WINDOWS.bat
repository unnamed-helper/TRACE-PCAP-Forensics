@echo off
title TRACE backend
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
echo Starting TRACE on http://127.0.0.1:8765  (local only, no internet needed)
start "" http://127.0.0.1:8765/
%PY% backend.py
pause
