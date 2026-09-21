@echo off
title AI Search Visibility Agent v2
echo Starting AI Search Visibility Agent v2...
cd /d "%~dp0"
start http://localhost:8000
python agent.py
pause