param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

if (-not (Test-Path -LiteralPath $InputPath)) {
    Write-Error "DLL not found: $InputPath"
    exit 1
}

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$bytes = [System.IO.File]::ReadAllBytes($InputPath)
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("#pragma once")
[void]$sb.AppendLine("#include <cstddef>")
[void]$sb.AppendLine("#include <cstdint>")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("static const std::uint8_t k_embedded_dll[] = {")

for ($i = 0; $i -lt $bytes.Length; $i++) {
    if (($i % 16) -eq 0) {
        [void]$sb.Append("    ")
    }
    [void]$sb.Append(("0x{0:X2}" -f $bytes[$i]))
    if ($i -lt $bytes.Length - 1) {
        [void]$sb.Append(",")
    }
    if ((($i % 16) -eq 15) -or ($i -eq $bytes.Length - 1)) {
        [void]$sb.AppendLine("")
    }
    else {
        [void]$sb.Append(" ")
    }
}

[void]$sb.AppendLine("};")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("static const std::size_t k_embedded_dll_size = sizeof(k_embedded_dll);")

$text = $sb.ToString()
if (Test-Path -LiteralPath $OutputPath) {
    $old = [System.IO.File]::ReadAllText($OutputPath)
    if ($old -eq $text) {
        exit 0
    }
}

[System.IO.File]::WriteAllText($OutputPath, $text)
Write-Host ("Embedded {0} bytes -> {1}" -f $bytes.Length, $OutputPath)
