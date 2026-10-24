<#
  Prestige detection validation harness
  Authors: MEOW & KHATOXD
  Reference: PRESTIGE-CLIENT-2026

  WHAT THIS DOES
    Runs the detection logic against real samples and against a corpus of
    clean Windows binaries, then prints a PASS/FAIL summary.

  USAGE
    powershell -ExecutionPolicy Bypass -File .\validate.ps1
    powershell -ExecutionPolicy Bypass -File .\validate.ps1 -Launcher "C:\path\Prestige Launcher.exe"
    powershell -ExecutionPolicy Bypass -File .\validate.ps1 -FPOnly -MaxFP 300

  NOTE
    This is a self-contained simulator of the YARA `condition` logic so it
    runs on any box without a yara binary. If you have yara64.exe installed,
    set -YaraPath and it will run the real engine too.
#>

param(
    [string]$Launcher = "C:\Users\siria\Downloads\Prestige Launcher.exe",
    [string]$Module   = "C:\Users\siria\Desktop\CHEAT DETECTED\prestige detection\prestige_module.bin",
    [string]$Corpus   = "C:\Windows\System32",
    [int]$MaxFP       = 700,
    [switch]$FPOnly,
    [string]$YaraPath = ""
)

$ErrorActionPreference = "SilentlyContinue"
$fail = 0; $pass = 0

function Check([string]$name, [bool]$cond, [string]$detail) {
    if ($cond) { $script:pass++; Write-Output ("  [PASS] {0}  {1}" -f $name, $detail) }
    else       { $script:fail++; Write-Output ("  [FAIL] {0}  {1}" -f $name, $detail) }
}

function Load-Bin($p) {
    if (-not (Test-Path $p)) { return $null }
    $b = [IO.File]::ReadAllBytes($p)
    [pscustomobject]@{ Bytes=$b; Ascii=[Text.Encoding]::ASCII.GetString($b)
                       Wide=[Text.Encoding]::Unicode.GetString($b); Size=$b.Length }
}
function Has($d,[string]$s,[string]$m="both"){
    if ($m -eq "ascii") { return $d.Ascii.Contains($s) }
    if ($m -eq "wide")  { return $d.Wide.Contains($s) }
    return ($d.Ascii.Contains($s) -or $d.Wide.Contains($s))
}
function Cnt($d,$arr,[string]$m="both"){ $n=0; foreach($x in $arr){ if(Has $d $x $m){$n++} }; $n }

# ---- rule string sets (must mirror prestige_disk.yar / prestige_memory.yar) ----
$E  = @('Download corrupted (bad MZ).','Download corrupted (not a 64-bit DLL).',
        'Download corrupted (truncated).','Download corrupted (bad PE offset).',
        'Download corrupted (bad PE signature).','Missing dependency for the Prestige module:',
        'Unresolved import in the Prestige module.','The Prestige module refused to initialize.',
        'The Prestige module missing its entry point.',
        'The Prestige module reported an initialization failure.',
        'Could not download Prestige.','Your antivirus is blocking requests to the Prestige API.',
        'Your internet provider is blocking requests to the Prestige API.')
$ID = @('Prestige Launcher','PrestigeLauncher','Prestige Software Development','Prestige Launcher.exe')
$N  = @('api.prestigeclient.vip','/launcherDownload')
$PDB= @('Prestige-Injection\Dependencies\cryptopp','C:\Users\Admin\source\repos\Prestige-Injection')
$S  = @('PRESTIGE_CMM_DEBUG_STAY','Active - waiting for Prestige to unload.',
        'Done - no Prestige memory left in the game.',
        'Prestige could not map the secure payload into this target.',
        'Prestige Injection is ready','Inject Prestige Client','no Prestige memory remains',
        'The complete Prestige experience with manual mapping')
$VM = @('.vm_sec','.vlizer')
$U  = @('wiping the last traces','no Prestige memory remains','waiting for Prestige to unload',
        'module-manager-clean','module-shutdown')

# new anchors added after full extraction (version resource / manifest / Authenticode)
$VR1 = 'Copyright (C) 2026 Prestige Software Development. All rights reserved.'
$MF1 = 'name="Prestige Launcher" version="1.2.3.0" processorArchitecture="amd64"'
# real DER byte patterns, verified present in the sample
$CT_CN  = [byte[]](0x03,0x55,0x04,0x03,0x0C,0x1D,0x50,0x72,0x65,0x73,0x74,0x69,0x67,0x65,0x20,0x53,
                   0x6F,0x66,0x74,0x77,0x61,0x72,0x65,0x20,0x44,0x65,0x76,0x65,0x6C,0x6F,0x70,0x6D,0x65,0x6E,0x74)
$CT_SER = [byte[]](0x64,0xB9,0x69,0x25,0x18,0xA7,0x1E,0x22,0x97,0x5B,0xCB,0x85,0x52,0x0F,0x1F,0x20)

function Find-Bytes($hay, [byte[]]$nd) {
    if ($null -eq $hay -or $hay.Length -lt $nd.Length) { return $false }
    for ($i=0; $i -le ($hay.Length - $nd.Length); $i++) {
        $ok = $true
        for ($j=0; $j -lt $nd.Length; $j++) { if ($hay[$i+$j] -ne $nd[$j]) { $ok=$false; break } }
        if ($ok) { return $true }
    }
    return $false
}

function Rule-Launcher($d) {
    if ($null -eq $d) { return $false }
    $mz = $d.Bytes[0] -eq 0x4D -and $d.Bytes[1] -eq 0x5A
    $sz = $d.Size -lt (400*1024)
    $ne = Cnt $d $E ascii; $nid = Cnt $d $ID; $nn = Cnt $d $N; $nu = Cnt $d $U ascii
    $vr1h = ($d.Ascii.Contains($VR1) -or $d.Wide.Contains($VR1))
    $mf1h = $d.Ascii.Contains($MF1)
    $ct1h = (Find-Bytes $d.Bytes $CT_CN) -or (Find-Bytes $d.Bytes $CT_SER)
    return ($mz -and $sz -and ($ne -ge 4 -or (($ne -ge 3) -and ($nid -ge 1)) -or
            (($nid -ge 2) -and ($nn -ge 1)) -or
            (($nu -ge 2) -and ($nid -ge 1)) -or
            ($vr1h -and ($nid -ge 1)) -or
            $mf1h -or
            ($ct1h -and ($nid -ge 1))))
}
function Rule-Module($d) {
    if ($null -eq $d) { return $false }
    $mz = $d.Bytes[0] -eq 0x4D -and $d.Bytes[1] -eq 0x5A
    $npdb=Cnt $d $PDB; $ns=Cnt $d $S ascii; $nvm=Cnt $d $VM ascii; $nn=Cnt $d $N; $nu=Cnt $d $U ascii
    return ($mz -and ($npdb -ge 1 -or $ns -ge 2 -or (($ns -ge 1) -and ($nvm -ge 1)) -or
            (($nn -ge 1) -and ($ns -ge 1)) -or (($nu -ge 2) -and ($ns -ge 1))))
}

Write-Output ""
Write-Output "=========================================================="
Write-Output "  Prestige detection validation - MEOW & KHATOXD"
Write-Output "  reference: PRESTIGE-CLIENT-2026"
Write-Output "=========================================================="

if (-not $FPOnly) {
    Write-Output ""
    Write-Output "--- 1. TRUE POSITIVES (must fire on the real samples) ---"
    $L = Load-Bin $Launcher
    $M = Load-Bin $Module
    Check "launcher file present"      ($null -ne $L) $Launcher
    Check "module file present"        ($null -ne $M) $Module
    if ($L) { Check "Prestige_Launcher fires"      (Rule-Launcher $L) "expect TRUE" }
    if ($M) { Check "Prestige_Client_Module fires" (Rule-Module   $M) "expect TRUE" }

    Write-Output ""
    Write-Output "--- 2. NO CROSS-CONTAMINATION ---"
    if ($L) { Check "module rule does NOT hit launcher" (-not (Rule-Module $L)) "expect FALSE" }
    if ($M) { Check "launcher rule does NOT hit module" (-not (Rule-Launcher $M)) "expect FALSE" }

    if ($L) {
        Write-Output ""
        Write-Output "--- 3. ENCODING CHECK ---"
        $nnA = Cnt $L $N ascii
        Check "host/endpoint visible as ASCII (should be 0 => proves ascii wide is required)" ($nnA -eq 0) "ascii-only matches=$nnA/2"
        $nnW = 0; foreach($x in $N){ if($L.Wide.Contains($x)){$nnW++} }
        Check "host/endpoint visible as UTF-16" ($nnW -eq 2) "utf16 matches=$nnW/2"
    }
}

Write-Output ""
Write-Output "--- 4. FALSE POSITIVES (corpus of clean binaries) ---"
$files = @(Get-ChildItem -Path $Corpus -Include *.exe,*.dll -Recurse -File -ErrorAction SilentlyContinue |
           Sort-Object Length | Select-Object -First $MaxFP)
$scanned=0; $fp=0
foreach ($f in $files) {
    $b=[IO.File]::ReadAllBytes($f.FullName)
    if ($b.Length -lt 4 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { continue }
    $scanned++
    $d=[pscustomobject]@{ Bytes=$b; Ascii=[Text.Encoding]::ASCII.GetString($b)
                          Wide=[Text.Encoding]::Unicode.GetString($b); Size=$b.Length }
    if (Rule-Launcher $d) { $fp++; Write-Output ("    FP (launcher) : {0}" -f $f.Name) }
    if (Rule-Module   $d) { $fp++; Write-Output ("    FP (module)   : {0}" -f $f.Name) }
}
Check "zero false positives on clean corpus" ($fp -eq 0) ("{0} files, {1} evals, {2} FP" -f $scanned, ($scanned*2), $fp)

# ---- optional: run the real yara engine if available ----
if ($YaraPath -ne "" -and (Test-Path $YaraPath)) {
    Write-Output ""
    Write-Output "--- 5. REAL YARA ENGINE ---"
    $ydir = Join-Path $PSScriptRoot "yara"
    foreach ($sample in @($Launcher, $Module)) {
        if (-not (Test-Path $sample)) { continue }
        foreach ($yf in Get-ChildItem $ydir -Filter *.yar) {
            $out = & $YaraPath $yf.FullName $sample 2>&1
            if ($out -match "Prestige") { Write-Output ("    matched {0} -> {1}" -f (Split-Path $sample -Leaf), $yf.Name) }
        }
    }
}

Write-Output ""
Write-Output "=========================================================="
Write-Output ("  RESULT: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -eq 0) { Write-Output "  STATUS: READY FOR SUBMISSION" } else { Write-Output "  STATUS: FIX FAILURES BEFORE SENDING" }
Write-Output "=========================================================="
