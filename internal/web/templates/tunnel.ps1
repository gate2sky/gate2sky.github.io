# gate2net tunnel for Windows, without installing anything: downloads the
# gate2net client matching {{.Dashboard}}, checks it against the release's
# SHA256SUMS, runs it and deletes it when it ends. In PowerShell:
#
#   & ([scriptblock]::Create((irm {{.URL}}))) SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT] [-i KEY]
#
# --cache (first) keeps the client in %LOCALAPPDATA%\gate2net\<version> to
# start faster next time. GATE2NET_DOWNLOAD_URL replaces GitHub with a
# directory holding gate2net-windows-<arch>.zip and SHA256SUMS. Keys come
# from the OpenSSH Authentication Agent (ssh-add) or %USERPROFILE%\.ssh.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'gate2net/gate2net.github.io'
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
	throw 'gate2net: usage: SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT]'
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
	'AMD64' { $arch = 'amd64' }
	'ARM64' { $arch = 'arm64' }
	default { throw "gate2net: there is no gate2net build for $arch" }
}
$target = "windows-$arch"
$asset = "gate2net-$target.zip"

# The server's own version, so the client speaks its language; a server
# built from source asks for the latest release.
if ($env:GATE2NET_VERSION) { $Version = $env:GATE2NET_VERSION }
$Version = $Version.TrimStart('v')
if ($env:GATE2NET_DOWNLOAD_URL) {
	$base = $env:GATE2NET_DOWNLOAD_URL.TrimEnd('/')
} elseif ($Version) {
	$base = "https://github.com/$Repo/releases/download/v$Version"
} else {
	$base = "https://github.com/$Repo/releases/latest/download"
}

$dir = $null
if ($cache -and $Version) { $dir = Join-Path $env:LOCALAPPDATA "gate2net\$Version" }
$exe = $null
if ($dir) { $exe = Join-Path $dir "gate2net-$target\gate2net.exe" }

$tmp = $null
try {
	if (-not $exe -or -not (Test-Path $exe)) {
		[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
		$tmp = Join-Path ([IO.Path]::GetTempPath()) ('gate2net-' + [guid]::NewGuid())
		New-Item -ItemType Directory -Path $tmp | Out-Null
		Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
		Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
		$line = Get-Content (Join-Path $tmp 'SHA256SUMS') |
			Where-Object { $f = ($_ -split '\s+')[1]; $f -eq $asset -or $f -eq "*$asset" } |
			Select-Object -First 1
		if (-not $line) { throw "gate2net: SHA256SUMS does not list $asset" }
		$want = ($line -split '\s+')[0]
		$got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $asset)).Hash
		if ($got -ne $want) { throw "gate2net: $asset does not match its checksum" }
		$into = $tmp
		if ($dir) { $into = $dir }
		Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $into -Force
		$exe = Join-Path $into "gate2net-$target\gate2net.exe"
	}
	if (-not (Test-Path $exe)) { throw "gate2net: $asset has no gate2net.exe in it" }
	& $exe tunnel --server $Server --host-key $HostKey @rest
} finally {
	if ($tmp) { Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue }
}
