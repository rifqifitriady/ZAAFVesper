# Live validation, Windows (v0.3 workstream B): install Sysmon and
# ZAAFVesper the way packaging/windows/README.md says, from pinned,
# hash-checked downloads. Runs on a throw-away GitHub runner as an
# elevated administrator. Every download is checked before it is used.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Pinned([string]$Url, [string]$Out, [string]$Sha256) {
  Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing
  $h = (Get-FileHash -Algorithm SHA256 $Out).Hash.ToLowerInvariant()
  if ($h -ne $Sha256) { throw "$Url : SHA-256 $h, pinned $Sha256 (the download changed; update the pin after review)" }
  Write-Host "ok $Out $h"
}

$work = Join-Path $env:RUNNER_TEMP 'zv'
New-Item -ItemType Directory -Force $work | Out-Null

# 1. Sysmon (Sysinternals publishes one current build; the pin fails loudly when it changes).
Get-Pinned 'https://download.sysinternals.com/files/Sysmon.zip' "$work\Sysmon.zip" $env:SYSMON_ZIP_SHA256
Expand-Archive -Force "$work\Sysmon.zip" "$work\sysmon"
$sig = Get-AuthenticodeSignature "$work\sysmon\Sysmon64.exe"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  throw "Sysmon64.exe signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
}
Write-Host "Sysmon64.exe $((Get-Item "$work\sysmon\Sysmon64.exe").VersionInfo.FileVersion) signed by $($sig.SignerCertificate.Subject)"

# 2. sysmon-modular configuration: an asset of the release built from the
#    pinned commit. The tag must point to that full commit, then the file's
#    hash must match.
$ref = git ls-remote https://github.com/olafhartong/sysmon-modular.git "refs/tags/$env:SYSMON_MODULAR_TAG"
if (-not $ref -or ($ref -split '\s+')[0] -ne $env:SYSMON_MODULAR_COMMIT) {
  throw "sysmon-modular tag $env:SYSMON_MODULAR_TAG resolves to '$ref', pinned commit $env:SYSMON_MODULAR_COMMIT"
}
Get-Pinned $env:SYSMON_CONFIG_URL "$work\sysmonconfig.xml" $env:SYSMON_CONFIG_SHA256
& "$work\sysmon\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml" | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Sysmon64 -i exit $LASTEXITCODE" }
Get-Service Sysmon64 | Format-List Name, Status | Out-Host

# 3. ZAAFVesper, as in packaging/windows/README.md (steps 3 to 5).
$pf = 'C:\Program Files\ZAAFVesper'
New-Item -ItemType Directory -Force $pf | Out-Null
Copy-Item build\zaafvesper.exe "$pf\zaafvesper.exe"
Copy-Item configs\zaafvesper.yml "$pf\zaafvesper.yml"
Copy-Item -Recurse configs\config.d "$pf\config.d"
Copy-Item -Recurse rules "$pf\rules"
icacls $pf | Out-Host
New-Item -ItemType Directory -Force 'C:\ProgramData\ZAAFVesper' | Out-Null
icacls 'C:\ProgramData\ZAAFVesper' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Host
icacls 'C:\ProgramData\ZAAFVesper' | Out-Host
$bin = "`"$pf\zaafvesper.exe`" run --config `"$pf\zaafvesper.yml`" --rules `"$pf\rules`" --output-dir C:\ProgramData\ZAAFVesper\logs --no-console --no-yara"
sc.exe create ZAAFVesper start= demand obj= LocalSystem binPath= $bin | Out-Host
sc.exe start ZAAFVesper | Out-Host
$log = 'C:\ProgramData\ZAAFVesper\logs\service.log'
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep 2
  if ((Test-Path $log) -and (Select-String -Quiet -Path $log -Pattern 'subscribed to')) { break }
}
sc.exe query ZAAFVesper | Out-Host
if (Test-Path $log) { Get-Content $log | Out-Host } else { Write-Host "no $log" }
if (-not ((Test-Path $log) -and (Select-String -Quiet -Path $log -Pattern 'subscribed to'))) {
  throw 'ZAAFVesper did not subscribe to the Sysmon channel (see the service log above)'
}
