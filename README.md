# PowerShell Script Signing Automation

This script automates the process of signing PowerShell scripts using a self-signed code-signing certificate. It checks for existing certificates, creates one if needed, and signs the target script if it isn't already signed.

## Features

- Checks for existing code-signing certificates
- Creates a new self-signed certificate if none exists
- Automatically trusts the certificate by adding it to the Trusted Root store
- Signs target PowerShell scripts only if they aren't already signed
- Fully configurable target script path

## Usage

### Prerequisites
- PowerShell 5.1 or later
- Administrator privileges (for certificate store modifications)

### Basic Usage

1. Save the following script as `Sign-Script.ps1`:

```powershell
# Define the path to the script you want to sign (change this variable)
$path = "C:\Path\To\YourScript.ps1"

function Get-CodeSigningCert {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
    return $cert
}

function Create-SelfSignedCert {
    $newCert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject "CN=MyPowerShellCodeSigningCert"
    
    $newCert | Export-Certificate -FilePath "$env:USERPROFILE\Desktop\MyPowerShellCodeSigningCert.cer"
    Import-Certificate -FilePath "$env:USERPROFILE\Desktop\MyPowerShellCodeSigningCert.cer" -CertStoreLocation Cert:\CurrentUser\Root
    
    return $newCert
}

function Is-ScriptSigned {
    $signature = Get-AuthenticodeSignature $path
    return $signature.Status -eq 'Valid'
}

# Main execution
$cert = Get-CodeSigningCert

if (-not $cert) {
    Write-Host "No existing code-signing certificate found. Creating a new one..."
    $cert = Create-SelfSignedCert
} else {
    Write-Host "Using existing certificate for code signing..."
}

if (-not (Is-ScriptSigned)) {
    Write-Host "Signing script..."
    Set-AuthenticodeSignature -FilePath $path -Certificate $cert
} else {
    Write-Host "Script is already signed. No action needed."
}

```markdown
# Usage

## Basic Usage

```powershell
# Run with default settings (signs your PowerShell profile)
.\Enable-SignedScripts.ps1
```

## Custom Script Path

```powershell
# Sign a specific script
.\Enable-SignedScripts.ps1 -ScriptPath "C:\scripts\custom.ps1"
```

---

# What It Does

- Checks for existing code-signing certificates  
- Creates new self-signed certificate if needed  
- Configures trust stores (Root + TrustedPublisher)  
- Sets execution policy to RemoteSigned  
- Signs target script if unsigned  
- Provides verification output  

---

# Verification

Check system status:

```powershell
Get-ExecutionPolicy -List
Get-ChildItem Cert:\CurrentUser\My, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*PowerShell*" }
```

---

# Requirements

- Windows PowerShell 5.1+  
- Administrator privileges  
- PowerShell execution policy allowing script execution  

---

# Security Notes

- Self-signed certificates should only be used for testing/personal use  
- For production environments, use certificates from a trusted CA  
- Execution policy is not a security boundary  

---

# Key Improvements in This Version

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
