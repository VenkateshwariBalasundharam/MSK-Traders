@echo off
timeout /t 60 /nobreak > nul
cd /d "D:\web development\MSK-Traders"
pm2 resurrect
"C:\Program Files\Tailscale\tailscale.exe" funnel --bg 3000
exit