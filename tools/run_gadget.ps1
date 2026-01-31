param(
  [Parameter(Mandatory=$true)][string]$Apk,
  [Parameter(Mandatory=$true)][string]$Pkg,
  [Parameter(Mandatory=$true)][string]$GadgetSo,
  [int]$Port = 27042,
  [int]$Duration = 40,
  [switch]$StopFridaServer
)

Set-StrictMode -Version Latest

function Fail($m) { throw $m }

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = (Resolve-Path (Join-Path $projectRoot ".venv\Scripts\python.exe")).Path
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"

Write-Host "[*] Project root: $projectRoot"
Write-Host "[*] Using python: $python"
Write-Host "[*] Using adb: $adb"

if (!(Test-Path $python)) { Fail "Python venv not found: $python" }
if (!(Test-Path $adb)) { Fail "adb not found: $adb" }
if (!(Test-Path $Apk)) { Fail "APK not found: $Apk" }
if (!(Test-Path $GadgetSo)) { Fail "Gadget .so/.xz not found: $GadgetSo" }

# Make SDK visible to python tool (zipalign/apksigner)
if (-not $env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT = "$env:LOCALAPPDATA\Android\Sdk" }

# Get device serial robustly
Write-Host "`n[*] Device:"
& $adb devices -l

$raw = & $adb devices 2>$null
$lines = @($raw | Select-String "device$" | ForEach-Object { $_.Line })
if ($lines.Length -lt 1) { Fail "No adb device found." }

$Serial = ($lines[0] -split "\s+")[0]
Write-Host "`n[*] Using device serial: $Serial"

if ($StopFridaServer) {
  Write-Host "`n[*] Stopping frida-server (if running) ..."
  & $adb -s $Serial shell "killall frida-server 2>/dev/null || true" | Out-Null
}

# Repack (redirect stderr->stdout so warnings don't stop the script)
$repackScript = (Join-Path $projectRoot "tools\repack_with_gadget.py")
if (!(Test-Path $repackScript)) { Fail "Missing repack script: $repackScript" }

Write-Host "`n[*] Repacking with Frida Gadget on port $Port ..."

$pyOut = & $python $repackScript `
  --apk $Apk `
  --gadget_so $GadgetSo `
  --port $Port 2>&1

$pyText = ($pyOut | Out-String)
Write-Host $pyText

$match = [regex]::Match($pyText, "OUTPUT_APK=(.+)")
if (-not $match.Success) { Fail "Repack failed: could not find OUTPUT_APK in repack output." }

$outApk = $match.Groups[1].Value.Trim()
if (!(Test-Path $outApk)) { Fail "Repacked APK not found on disk: $outApk" }

Write-Host "`n[OK] Repacked APK => $outApk"

# Install repacked APK
Write-Host "`n[*] Uninstalling $Pkg (ignore failures) ..."
& $adb -s $Serial uninstall $Pkg | Out-Null

Write-Host "[*] Installing repacked APK ..."
& $adb -s $Serial install -r "$outApk" | Out-Host

# Forward port
Write-Host "[*] Forwarding tcp:$Port -> tcp:$Port"
& $adb -s $Serial forward --remove "tcp:$Port" 2>$null | Out-Null
& $adb -s $Serial forward "tcp:$Port" "tcp:$Port" | Out-Host

# Launch app and get PID
Write-Host "[*] Launching app: $Pkg"
& $adb -s $Serial shell "monkey -p $Pkg -c android.intent.category.LAUNCHER 1" | Out-Null
Start-Sleep -Seconds 1

$pid = (& $adb -s $Serial shell "pidof $Pkg").Trim()
if (-not $pid) {
  Write-Host "[!] App PID not found. App likely crashed. Dumping logcat hints..."
  & $adb -s $Serial logcat -d | Select-String -Pattern "FATAL EXCEPTION|AndroidRuntime|frida|gadget|cybershadow|$Pkg" -CaseSensitive:$false | Select-Object -Last 120
  Fail "App crashed or did not start. Check logcat above."
}

Write-Host "[*] PID: $pid"

# Quick endpoint sanity check
Write-Host "`n[*] Checking Gadget endpoint (frida-ps) ..."
$psOut = & frida-ps -H "127.0.0.1:$Port" 2>&1
Write-Host ($psOut | Out-String)

Write-Host "`n[*] Attaching via Gadget endpoint: 127.0.0.1:$Port (Duration hint: $Duration sec)"
Write-Host "[*] Command:"
Write-Host "    frida -H 127.0.0.1:$Port -p $pid -l `"$projectRoot\src\cybershadow_dyn.js`""

# Run hooks
$fridaOut = & frida -H "127.0.0.1:$Port" -p $pid -l (Join-Path $projectRoot "src\cybershadow_dyn.js") 2>&1
Write-Host ($fridaOut | Out-String)

Write-Host "[DONE] If you still get 'connection closed', check logcat immediately after this point:"
Write-Host "       adb -s $Serial logcat -d | findstr /i `"FATAL EXCEPTION AndroidRuntime frida gadget cybershadow $Pkg`""
