@echo off
echo ==========================
echo 啟動 AI 詐騙分析系統
echo ==========================

cd /d C:\Users\a0976\OneDrive\Desktop\ai_scan_web

echo 啟動 Flask...
start cmd /k python app.py

timeout /t 3

echo 啟動 ngrok...
start cmd /k python -m pyngrok.ngrok http 5000

echo ==========================
echo 全部啟動完成！
echo ==========================
pause