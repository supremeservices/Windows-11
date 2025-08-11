<# 
.SYNOPSIS
  Safely upgrade to Windows 11 using the Installation Assistant with pre-checks.

.NOTES
  Run from elevated PowerShell (Run as Administrator).
#>

# === Config ===
$dir  = 'C:\temp\win11'
$url  = 'https://go.microsoft.com/fwlink/?linkid=2171764'  # Windows 11 Installation Assistant
$file = Join-Path $dir 'Windows11InstallationAssistant.exe'
$log  = Join-Path $dir 'upgrade.log'

# === Helpers ===
function Write-Info($msg){ Write-Host "[INFO] $msg" }
function Write-Fail($msg){ Write-Error "[FAIL] $msg" }

function Test-IsAdmin {
  $current = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  return $current.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-PendingReboot {
  # Checks common reboot flags (not exhaustive but useful)
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
  )
  foreach ($p in $paths){
    if (Test-Path $p){
      if ($p -like '*Session Manager*'){
        $val = (Get-ItemProperty -Path $p -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($val){ return $true }
      } else {
        return $true
      }
    }
  }
  return $false
}

function Test-SecureBootEnabled {
  try {
    # Returns $true on UEFI with Secure Boot enabled; throws on BIOS/unsupported
    return [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
  } catch {
    return $false
  }
}

function Test-TPM20 {
  try {
    $tpm = Get-Tpm
    if (-not $tpm.TpmPresent){ return $false }
    # SpecVersion can contain multiple values like "2.0, 1.3"
    return ($tpm.SpecVersion -match '\b2\.0\b')
  } catch {
    return $false
  }
}

function Get-GB([ulong]$bytes){ [Math]::Round($bytes / 1GB, 2) }

function Test-Requirements {
  $ok = $true
  $results = [ordered]@{}

  # Admin
  $results.Admin = Test-IsAdmin
  if (-not $results.Admin){ $ok = $false; Write-Fail "Run this script as Administrator."; }

  # 64-bit OS
  $results.OS64Bit = [Environment]::Is64BitOperatingSystem
  if (-not $results.OS64Bit){ $ok = $false; Write-Fail "Windows 11 requires a 64-bit OS/CPU."; }

  # Base OS build (Windows 10 2004+ recommended for smoother in-place upgrade)
  try {
    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $build = [int]$cv.CurrentBuild
    $results.MinBuild19041 = ($build -ge 19041)
    if (-not $results.MinBuild19041){
      Write-Info "Current build $build < 19041; upgrade may still work but is not recommended."
    }
  } catch {
    $results.MinBuild19041 = $false
  }

  # RAM >= 4 GB (baseline requirement)
  $ram = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
  $results.RAMGB = Get-GB $ram
  if ($results.RAMGB -lt 4){
    $ok = $false; Write-Fail "RAM check failed: ${($results.RAMGB)} GB < 4 GB."
  }

  # System disk: total >= 64 GB and free >= 20 GB (practical free space threshold)
  $sysDrive = $env:SystemDrive.TrimEnd('\')
  $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
  $results.DiskTotalGB = Get-GB $disk.Size
  $results.DiskFreeGB  = Get-GB $disk.FreeSpace
  if ($results.DiskTotalGB -lt 64){
    $ok = $false; Write-Fail "Disk size check failed: ${($results.DiskTotalGB)} GB total < 64 GB."
  }
  if ($results.DiskFreeGB -lt 20){
    $ok = $false; Write-Fail "Free space check failed: ${($results.DiskFreeGB)} GB free < 20 GB."
  }

  # TPM 2.0 and Secure Boot enabled
  $results.TPM20 = Test-TPM20
  if (-not $results.TPM20){ $ok = $false; Write-Fail "TPM 2.0 not detected."; }

  $results.SecureBoot = Test-SecureBootEnabled
  if (-not $results.SecureBoot){ $ok = $false; Write-Fail "Secure Boot is not enabled or system not UEFI."; }

  # Internet connectivity (basic HTTPS reachability)
  try {
    $net = Test-NetConnection -ComputerName 'download.microsoft.com' -Port 443 -WarningAction SilentlyContinue
    $results.Internet = $net.TcpTestSucceeded
    if (-not $results.Internet){ $ok = $false; Write-Fail "No HTTPS connectivity to download.microsoft.com:443."; }
  } catch {
    $results.Internet = $false
    $ok = $false; Write-Fail "Connectivity test failed."
  }

  # Pending reboot
  $results.PendingReboot = Test-PendingReboot
  if ($results.PendingReboot){ $ok = $false; Write-Fail "A reboot is pending. Please reboot and re-run."; }

  [PSCustomObject]@{ Passed = $ok; Details = $results }
}

# === Main ===
if (-not (Test-Path $dir)){ New-Item -Path $dir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $log -Append -ErrorAction SilentlyContinue | Out-Null

Write-Info "Running Windows 11 readiness checks..."
$check = Test-Requirements
$check | Format-List | Out-String | Write-Host

if (-not $check.Passed){
  Stop-Transcript | Out-Null
  exit 1
}

Write-Info "All prerequisite checks passed."

# Use TLS 1.2 explicitly for reliability with older .NET
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

Write-Info "Downloading Windows 11 Installation Assistant..."
try {
  Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
} catch {
  Write-Fail "Download failed: $($_.Exception.Message)"
  Stop-Transcript | Out-Null
  exit 2
}

if (-not (Test-Path $file)){
  Write-Fail "Downloaded file not found at $file."
  Stop-Transcript | Out-Null
  exit 3
}

Write-Info "Starting silent upgrade..."
$arguments = @(
  '/QuietInstall',
  '/SkipEULA',
  '/auto upgrade',
  '/dynamicupdate enable',
  "/copylogs `"$dir`""
) -join ' '

try {
  $p = Start-Process -FilePath $file -ArgumentList $arguments -PassThru -Wait
  Write-Info "Installer exited with code $($p.ExitCode). Logs are in $dir"
  Stop-Transcript | Out-Null
  exit $p.ExitCode
} catch {
  Write-Fail "Failed to start installer: $($_.Exception.Message)"
  Stop-Transcript | Out-Null
  exit 4
}
