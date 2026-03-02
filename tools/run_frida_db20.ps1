param(
  [Parameter(Mandatory=$true)] [string]$Serial,
  [Parameter(Mandatory=$true)] [string]$ListCsv,
  [string]$GadgetVer = "17.6.2"
)

$ErrorActionPreference="Stop"
$ADB="$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$PY=".\.venv\Scripts\python.exe"

if(!(Test-Path $ListCsv)){ throw "List not found: $ListCsv" }

$PATCH_DIR = Join-Path (Split-Path $ListCsv -Parent) "patched"
$LOG_DIR   = Join-Path (Split-Path $ListCsv -Parent) "logs"
mkdir $PATCH_DIR -Force | Out-Null
mkdir $LOG_DIR   -Force | Out-Null

function Restart-Adb {
  & $ADB kill-server | Out-Null
  & $ADB start-server | Out-Null
  Start-Sleep 3
}

function Forward-Frida {
  & $ADB -s $Serial forward --remove-all | Out-Null
  & $ADB -s $Serial forward tcp:27042 tcp:27042 | Out-Null
  & $ADB -s $Serial forward tcp:27043 tcp:27043 | Out-Null
}

function Wait-AppPid([string]$pkg, [int]$sec=25){
  for($i=0;$i -lt $sec;$i++){
    # IMPORTANT: pidof may return nothing => $null, so normalize safely
    $raw = & $ADB -s $Serial shell "pidof $pkg 2>/dev/null || true" 2>$null
    $appPid = ($raw -join "").Trim()
    if($appPid){ return $appPid }
    Start-Sleep 1
  }
  return ""
}

function Find-NewObjectionApk([string]$dir, [datetime]$since) {
  if(!(Test-Path $dir)){ return "" }
  $c = Get-ChildItem $dir -File -Filter "*.apk" -ErrorAction SilentlyContinue |
       Where-Object { $_.LastWriteTime -ge $since.AddSeconds(-2) -and $_.Name -match "objection" } |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 1
  if($c){ return $c.FullName }
  return ""
}

$items = Import-Csv $ListCsv
foreach($it in $items){

  $case = $it.case_dir
  $pkg  = $it.package
  $apk  = $it.apk_path
  $tag  = $it.tag

  $log = Join-Path $LOG_DIR ("run_{0}.log" -f $tag)

  try {
    Write-Host "`n=== $tag | $pkg ===" -ForegroundColor Cyan

    if(!(Test-Path $apk)){
      Write-Host "[skip] apk not found: $apk" -ForegroundColor Red
      continue
    }

    Forward-Frida
    & $ADB -s $Serial uninstall $pkg | Out-Null

    # ---- PATCH ----
    $patchLog = Join-Path $LOG_DIR ("patch_{0}.log" -f $tag)
    $patchStart = Get-Date
    $srcDir = Split-Path $apk -Parent

    Push-Location $srcDir
    $outLines = @()
    try {
      # -2 => use aapt2 (fixes many resource rebuild issues)
      $outLines = & objection patchapk --source "$apk" --gadget-version $GadgetVer -2 2>&1
      $outLines | Tee-Object -FilePath $patchLog | Out-Host
    } catch {
      $_ | Out-String | Add-Content $patchLog
    } finally {
      Pop-Location
    }

    # 1) parse destination from output (most reliable)
    $gen = ""
    $m = $outLines | Select-String -Pattern 'Copying final apk .* to (.+?\.apk)\s' | Select-Object -Last 1
    if($m -and $m.Matches.Count -gt 0){
      $cand = $m.Matches[0].Groups[1].Value.Trim()
      if($cand -and (Test-Path $cand)){ $gen = $cand }
    }

    # 2) fallback: look for *.objection.apk in source dir / patch dir
    if(-not $gen){ $gen = Find-NewObjectionApk $srcDir $patchStart }
    if(-not $gen){ $gen = Find-NewObjectionApk $PATCH_DIR $patchStart }

    if(-not $gen){
      Write-Host "[skip] patch failed (no output). See log: $patchLog" -ForegroundColor Red
      continue
    }

    $patched = Join-Path $PATCH_DIR ("{0}.objection.apk" -f $tag)
    Copy-Item $gen $patched -Force

    # ---- INSTALL ----
    $inst = & $ADB -s $Serial install -r "$patched" 2>&1
    if($LASTEXITCODE -ne 0){
      Write-Host "[skip] install failed. See patch log: $patchLog" -ForegroundColor Red
      $inst | Tee-Object -FilePath $log | Out-Host
      continue
    }

    # ---- START ----
    & $ADB -s $Serial shell "monkey -p $pkg -c android.intent.category.LAUNCHER 1" | Out-Null
    Start-Sleep 2

    $appPid = Wait-AppPid $pkg 25
    if(-not $appPid){
      Write-Host "[warn] no app pid for $pkg (crash/blocked). Uninstall & continue." -ForegroundColor Yellow
      & $ADB -s $Serial uninstall $pkg | Out-Null
      continue
    }

    # ---- HFIF FRIDA DYNAMIC ----
    $ok=$false
    for($try=1;$try -le 2;$try++){
      & $PY -m src.main apk-dynamic --case "$case" --package "$pkg" --tag "$tag" --serial "$Serial" `
        --preflight 60 --capture 90 --drive monkey+allow --monkey-events 2000 --throttle-ms 80 `
        --endpoint 127.0.0.1:27042 --gadget-name Gadget --script .\src\cybershadow_dyn.js

      if($LASTEXITCODE -eq 0){ $ok=$true; break }

      Write-Host "[warn] apk-dynamic failed (try=$try) -> restart adb and retry" -ForegroundColor Yellow
      Restart-Adb
      Forward-Frida
    }

    if($ok){
      try {
        & $PY -m src.main memlite --case "$case" --package "$pkg" --tag "$tag" --serial "$Serial" | Out-Null
      } catch {
        Write-Host "[warn] memlite failed/absent (skip)" -ForegroundColor Yellow
      }

      & $PY -m src.main case-report --case "$case" --risk-mode latest | Out-Null
      Write-Host "[OK] done: $case" -ForegroundColor Green
    } else {
      Write-Host "[FAIL] dynamic failed: $case (see patch log: $patchLog)" -ForegroundColor Red
    }

    # uninstall to avoid Gadget port conflicts
    & $ADB -s $Serial uninstall $pkg | Out-Null

  } catch {
    Write-Host "[ERROR] unexpected failure for $tag | $pkg. Continuing..." -ForegroundColor Red
    ($_ | Out-String) | Add-Content $log
    continue
  }
}