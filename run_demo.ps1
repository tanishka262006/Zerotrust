Remove-Item audit.log -ErrorAction SilentlyContinue
$procs = @()
$procs += Start-Process python -ArgumentList "apps/private_app.py hr 8081" -PassThru -WindowStyle Hidden
$procs += Start-Process python -ArgumentList "apps/private_app.py finance 8082" -PassThru -WindowStyle Hidden
$procs += Start-Process python -ArgumentList "broker.py" -PassThru -WindowStyle Hidden
Start-Sleep 1
$procs += Start-Process python -ArgumentList "connector.py connector-1" -PassThru -WindowStyle Hidden
Start-Sleep 1
python attacks.py
Write-Host "`n--- audit.log (last 12) ---"
Get-Content audit.log -Tail 12
$procs | Stop-Process -Force
