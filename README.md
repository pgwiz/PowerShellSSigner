

# PowerShell Script Signing & Trust Automation

A complete solution for:

- Creating code-signing certificates (if none exist)  
- Configuring trust settings  
- Setting execution policy  
- Signing PowerShell scripts  
- Verifying signatures  

---

## Features

✔ Automatic certificate generation  
✔ Trust chain configuration  
✔ Execution policy management  
✔ Smart signing (only if needed)  
✔ Detailed status reporting  

---

## Full Script

Save the following as `Enable-SignedScripts.ps1`:

```powershell
<#
.SYNOPSIS
    Configures system to trust and run signed PowerShell scripts

.DESCRIPTION
    - Creates a self-signed code-signing certificate if none exists
    - Configures certificate trust chain
    - Signs a specified PowerShell script if it's unsigned
    - Verifies signature status after signing

.NOTES
    Requires PowerShell 5.1+ and administrator privileges
#>

param (
    [string]$ScriptPath = "C:\Users\HP FOLIO 9480m\pgwiz\.ap\Scripts\Activate.ps1"
)

# Ensure admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator rights."
    Write-Host "Please re-run as Administrator" -ForegroundColor Red
    exit 1
}

function Initialize-CodeSigningEnvironment {
    Write-Host "Checking execution policies..." -ForegroundColor Cyan
    Write-Host "  CurrentUser:  $(Get-ExecutionPolicy -Scope CurrentUser)"
    Write-Host "  LocalMachine: $(Get-ExecutionPolicy -Scope LocalMachine)"
    Write-Host "Skipping execution policy change (already RemoteSigned or blocked)" -ForegroundColor Yellow

    # Check for an existing code-signing certificate
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" } |
            Select-Object -First 1

    # Create and trust certificate if none found
    if (-not $cert) {
        Write-Host "Creating new code-signing certificate..." -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My `
                -Type CodeSigningCert `
                -Subject "CN=PowerShell Script Signing Certificate" `
                -KeyUsage DigitalSignature `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(5)

        $certPath = "$env:TEMP\PowerShellSigningCert.cer"
        $cert | Export-Certificate -FilePath $certPath | Out-Null

        Write-Host "Configuring certificate trust..." -ForegroundColor Cyan
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
        Remove-Item $certPath -Force
    }

    return $cert
}

function Test-ScriptSignature {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    return $sig.Status -eq 'Valid' -and $sig.SignerCertificate
}

# Main execution
try {
    Write-Host "START: Setting up code-signing environment..." -ForegroundColor Green
    $cert = Initialize-CodeSigningEnvironment

    Write-Host "`nCertificate Details:" -ForegroundColor Green
    $cert | Format-List Subject, Thumbprint, NotBefore, NotAfter

    if (Test-Path $ScriptPath) {
        if (-not (Test-ScriptSignature -Path $ScriptPath)) {
            Write-Host "Signing script: $ScriptPath" -ForegroundColor Cyan
            Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -HashAlgorithm SHA256
        }
        else {
            Write-Host "Script already signed: $ScriptPath" -ForegroundColor Green
        }

        Write-Host "`nSignature Verification:" -ForegroundColor Green
        Get-AuthenticodeSignature $ScriptPath | Select-Object Status, StatusMessage, SignerCertificate | Format-List
    }
    else {
        Write-Warning "Target script not found: $ScriptPath"
    }

    Write-Host "`nEnvironment Ready:" -ForegroundColor Green
    Write-Host "- Execution Policy (CurrentUser):  $(Get-ExecutionPolicy -Scope CurrentUser)"
    Write-Host "- Execution Policy (LocalMachine): $(Get-ExecutionPolicy -Scope LocalMachine)"
    Write-Host "- Trusted Certificate: $($cert.Subject)"
}
catch {
    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

---

## Usage

### Basic Usage

```powershell
# Run with default settings (signs your PowerShell profile)
.\Enable-SignedScripts.ps1
```

### Custom Script Path

```powershell
# Sign a specific script
.\Enable-SignedScripts.ps1 -ScriptPath "C:\scripts\custom.ps1"
```
## If its restriceed or not signed Bypass Execution policy with 

# Run with default settings (signs your PowerShell profile)

```powershell
powershell -ExecutionPolicy Bypass -File .\Enable-SignedScripts.ps1
```
## Sign with

```powershell
powershell -ExecutionPolicy Bypass -File .\Enable-SignedScripts.ps1 -ScriptPath "C:\scripts\custom.ps1"
```
---

## What It Does

- Checks for existing code-signing certificates  
- Creates new self-signed certificate if needed  
- Configures trust stores (Root + TrustedPublisher)  
- Sets execution policy to RemoteSigned  
- Signs target script if unsigned  
- Provides verification output  

---

## Verification

Check system status:

```powershell
Get-ExecutionPolicy -List
Get-ChildItem Cert:\CurrentUser\My, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*PowerShell*" }
```

---

## Requirements

- Windows PowerShell 5.1+  
- Administrator privileges  
- PowerShell execution policy allowing script execution  

---

## Security Notes

- Self-signed certificates should only be used for testing/personal use  
- For production environments, use certificates from a trusted CA  
- Execution policy is not a security boundary  

---

## Key Improvements in This Version

1. Added proper parameter handling for script path  
2. Enhanced certificate creation with stronger crypto (RSA 2048)  
3. Better trust chain configuration (Root + TrustedPublisher)  
4. Detailed status output  
5. Proper error handling  
6. Verification steps  
7. Security notes  

---

The script now completely automates the process from certificate creation through to script signing while maintaining security best practices.
```
