param(
    [string]$OutDir = "C:\Users\亦已哉\Desktop\harness\plugins\dsh-plugin-vet\assets"
)
Add-Type -AssemblyName System.Drawing

function New-TerminalShot {
    param(
        [string]$Path,
        [string]$Title,
        [string[]]$Lines,
        [int]$Width = 900,
        [int]$LineHeight = 22
    )
    $font = New-Object System.Drawing.Font("Consolas", 12)
    $titleFont = New-Object System.Drawing.Font("Consolas", 13, [System.Drawing.FontStyle]::Bold)
    $pad = 18
    $titleH = 34
    $height = $titleH + $pad * 2 + $Lines.Count * $LineHeight + 10

    $bmp = New-Object System.Drawing.Bitmap($Width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.Clear([System.Drawing.Color]::FromArgb(255, 13, 17, 23))

    # title bar
    $bar = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 22, 27, 34))
    $g.FillRectangle($bar, 0, 0, $Width, $titleH)
    $titleBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 230, 237, 243))
    $g.DrawString($Title, $titleFont, $titleBrush, $pad, 7)

    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 230, 237, 243))
    $green = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 63, 185, 80))
    $orange = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 219, 135, 40))
    $red = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 248, 81, 73))
    $dim = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 139, 148, 158))

    $y = $titleH + $pad
    foreach ($line in $Lines) {
        if ($line -match '^\[HIGH\]') { $c = $red }
        elseif ($line -match '^\[MEDIUM\]') { $c = $orange }
        elseif ($line -match '^\[SAFE\]|PASS|safe=') { $c = $green }
        elseif ($line -match '^# |^>') { $c = $dim }
        else { $c = $brush }
        $g.DrawString($line, $font, $c, $pad, $y)
        $y += $LineHeight
    }
    $g.Dispose()
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "saved: $Path"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- shot 1: overall report (real output) ---
$report = @(
    "# Plugin vet - 4 third-party plugin(s) scanned",
    "safe=4 low=0 medium=0 high=0",
    "",
    "[SAFE] dsh-plugin-credential-guard@0.1.0 (score 0)",
    "    (no malicious-pattern hits)",
    "[SAFE] dsh-plugin-pwsh-utf8@0.1.0 (score 0)",
    "    (no malicious-pattern hits)",
    "[SAFE] dsh-plugin-search-gate@0.1.0 (score 0)",
    "    (no malicious-pattern hits)",
    "[SAFE] dsh-plugin-security-audit@0.1.0 (score 0)",
    "    (no malicious-pattern hits)",
    "",
    "> heuristic scan only: a clean result is not a security guarantee",
    "> runtime-dynamic code is NOT in scope - static scan cannot see it",
    "> official @deepseek-ai/* packages are exempt by name"
)
New-TerminalShot -Path (Join-Path $OutDir "shot-report.png") -Title "dsh-plugin-vetting - /plugin-vet report" -Lines $report

# --- shot 2: detailed package row with findings / coverage / deps / runtime surface ---
$detail = @(
    "[HIGH] dsh-plugin-some-plugin@1.2.0 (score 12) [REVIEW: dynamic code execution present]",
    "    - network-fetch: makes fetch network requests @ lib/index.js:8",
    "    - credential-env: reads credential-like env vars @ lib/index.js:11",
    "    - eval: dynamic code execution - requires manual review @ lib/index.js:21",
    "    suggest narrowing (not suspicion):",
    "      - sloppy-home-read: reads under user home with broad patterns @ lib/index.js:4",
    "    lifecycle scripts: install, prepare | deps: 3 declared, 2 nested scanned, 1 unchecked",
    "    coverage: 47 source file(s), 1200 line(s) scanned",
    "    runtime surface: child_process x2, fetch x1, eval x1"
)
New-TerminalShot -Path (Join-Path $OutDir "shot-detail.png") -Title "dsh-plugin-vetting - package detail" -Lines $detail

# --- shot 3: runtime gate + baseline ---
$gate = @(
    "config.gate: \"deny-unvetted\"",
    "    - tool calls from plugins registered after install are refused",
    "      unless allowlisted (tools/pre-execute surface)",
    "",
    "official-package hash baseline (default on)",
    "    - @deepseek-ai/* content hashed against baseline.json",
    "    - mismatch => exemption revoked, tampering warning",
    "",
    "OFFICIAL-PACKAGE MISMATCH: @deepseek-ai/dsh-base content differs",
    "from the recorded baseline (possible supply-chain tampering) - exemption revoked"
)
New-TerminalShot -Path (Join-Path $OutDir "shot-gate.png") -Title "dsh-plugin-vetting - tool gate & hash baseline" -Lines $gate
