# intergate tunnel for Windows, without installing anything: downloads the
# intergate client matching {{.Dashboard}}, checks it against the release's
# SHA256SUMS, runs it and deletes it when it ends. In PowerShell:
#
#   & ([scriptblock]::Create((irm {{.URL}}))) SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT] [-i KEY]
#
# --cache (first) keeps the client in %LOCALAPPDATA%\intergate\<version> to
# start faster next time. INTERGATE_DOWNLOAD_URL replaces GitHub with a
# directory holding intergate-windows-<arch>.zip and SHA256SUMS. Keys come
# from the OpenSSH Authentication Agent (ssh-add) or %USERPROFILE%\.ssh.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'jgermade/intergate'
$Version = '{{.Version}}'
$Server = '{{.Server}}'
$HostKey = '{{.HostKey}}'

$rest = @($args)
$cache = $false
if ($rest.Count -gt 0 -and $rest[0] -eq '--cache') {
	$cache = $true
	$rest = @($rest | Select-Object -Skip 1)
}
if ($rest.Count -eq 0) {
	throw 'intergate: usage: SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT]'
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
	'AMD64' { $arch = 'amd64' }
	'ARM64' { $arch = 'arm64' }
	default { throw "intergate: there is no intergate build for $arch" }
}
$target = "windows-$arch"
$asset = "intergate-$target.zip"

# The server's own version, so the client speaks its language; a server
# built from source asks for the latest release.
if ($env:INTERGATE_VERSION) { $Version = $env:INTERGATE_VERSION }
$Version = $Version.TrimStart('v')
if ($env:INTERGATE_DOWNLOAD_URL) {
	$base = $env:INTERGATE_DOWNLOAD_URL.TrimEnd('/')
} elseif ($Version) {
	$base = "https://github.com/$Repo/releases/download/v$Version"
} else {
	$base = "https://github.com/$Repo/releases/latest/download"
}

$dir = $null
if ($cache -and $Version) { $dir = Join-Path $env:LOCALAPPDATA "intergate\$Version" }
$exe = $null
if ($dir) { $exe = Join-Path $dir "intergate-$target\intergate.exe" }

$tmp = $null
try {
	if (-not $exe -or -not (Test-Path $exe)) {
		[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
		$tmp = Join-Path ([IO.Path]::GetTempPath()) ('intergate-' + [guid]::NewGuid())
		New-Item -ItemType Directory -Path $tmp | Out-Null
		Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
		Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
		$line = Get-Content (Join-Path $tmp 'SHA256SUMS') |
			Where-Object { $f = ($_ -split '\s+')[1]; $f -eq $asset -or $f -eq "*$asset" } |
			Select-Object -First 1
		if (-not $line) { throw "intergate: SHA256SUMS does not list $asset" }
		$want = ($line -split '\s+')[0]
		$got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $asset)).Hash
		if ($got -ne $want) { throw "intergate: $asset does not match its checksum" }
		$into = $tmp
		if ($dir) { $into = $dir }
		Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $into -Force
		$exe = Join-Path $into "intergate-$target\intergate.exe"
	}
	if (-not (Test-Path $exe)) { throw "intergate: $asset has no intergate.exe in it" }
	& $exe tunnel --server $Server --host-key $HostKey @rest
} finally {
	if ($tmp) { Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue }
}
