$py = ".\venv\Scripts\python.exe"
& $py seed_lab.py --reset-logs
$srv = Start-Process $py -ArgumentList "mock_server.py" -PassThru -WindowStyle Hidden
Start-Sleep 1
try {
    & $py agent.py ($args -join " ")
    & $py verdict.py
}
finally { Stop-Process -Id $srv.Id -Force }