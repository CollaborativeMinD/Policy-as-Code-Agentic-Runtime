$ErrorActionPreference = "Stop"
$policy = py -3.13 -c "import json,tomllib;print(json.dumps(tomllib.load(open('release/policy.toml','rb'))['scan']))" | ConvertFrom-Json
if ($LASTEXITCODE) { throw "Scanner policy unavailable" }
$version = $policy.scanner_version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid scanner version" }
$work = New-Item -ItemType Directory (Join-Path $env:RUNNER_TEMP ("trivy-" + [guid]::NewGuid().ToString("N")))
$zip = Join-Path $work "trivy.zip"
Invoke-WebRequest -UseBasicParsing "https://github.com/aquasecurity/trivy/releases/download/v$version/trivy_${version}_windows-64bit.zip" -OutFile $zip
if ((Get-FileHash $zip).Hash -ne $policy.windows_zip_sha256) { throw "Scanner archive failed verification" }
Expand-Archive $zip $work
(Join-Path $work "trivy.exe")
