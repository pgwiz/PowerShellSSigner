Here's the complete markdown documentation for your script signing solution, combining both versions with clear organization:

```markdown
# PowerShell Script Signing Automation

## Overview

A comprehensive solution for managing PowerShell script signing with two implementation options:

1. **Basic Version**: Simple certificate creation and script signing
2. **Advanced Version**: Complete environment configuration with trust chain setup

## Basic Signing Script

```powershell
<#
.SYNOPSIS
    Basic script signing solution for PowerShell
.DESCRIPTION
    - Checks for existing code-signing certificate
    - Creates self-signed certificate if needed
    - Signs target PowerShell script
.NOTES
    File Name      : Basic-ScriptSigner.ps1
    Requires       : PowerShell 5.1+
#>

# Define the path to the script you want to sign
$path = "F:\VSsetup\TerminalTheme\PowershellScriptSigner\omyposh.ps1"

# Function to check if the certificate exists
function Get-CodeSigningCert {
    $cert = Get-ChildItem Cert:\CurrentUser\My | 
            Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
    return $cert
}

# Function to create new self-signed certificate
function Create-SelfSignedCert {
    $newCert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My `
            -Type CodeSigningCert `
            -Subject "CN=MyPowerShellCodeSigningCert"
    
    # Configure trust
    $newCert | Export-Certificate -FilePath "$env:USERPROFILE\Desktop\MyPowerShellCodeSigningCert.cer"
    Import-Certificate -FilePath "$env:USERPROFILE\Desktop\MyPowerShellCodeSigningCert.cer" `
                      -CertStoreLocation Cert:\CurrentUser\Root
    
    return $newCert
}

# Set execution policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Check if script is signed
function Is-ScriptSigned {
    $signature = Get-AuthenticodeSignature $path
    return $signature.Status -eq 'Valid'
}

# Main execution
$cert = Get-CodeSigningCert

if (-not $cert) {
    Write-Host "Creating new code-signing certificate..."
    $cert = Create-SelfSignedCert
} else {
    Write-Host "Using existing certificate..."
}

if (-not (Is-ScriptSigned)) {
    Write-Host "Signing script..."
    Set-AuthenticodeSignature -FilePath $path -Certificate $cert
} else {
    Write-Host "Script already signed."
}
```

### Basic Version Features

- Simple certificate management
- Automatic script signing
- Execution policy configuration
- Lightweight implementation

## Advanced Signing Solution

```powershell
<#
.SYNOPSIS
    Complete PowerShell script signing environment setup
.DESCRIPTION
    - Creates self-signed cert if none exists
    - Configures full trust chain
    - Sets execution policies
    - Signs target script
    - Provides verification
.NOTES
    File Name      : Advanced-ScriptSigner.ps1
    Requires       : PowerShell 5.1+, Administrator rights
#>

param (
    [string]$ScriptPath = "$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
)

# Admin check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Administrator rights required"
    exit 1
}

function Initialize-CodeSigningEnvironment {
    # Execution policies
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

    # Certificate handling
    $cert = Get-ChildItem Cert:\CurrentUser\My | 
            Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" } |
            Select-Object -First 1

    if (-not $cert) {
        $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My `
                -Type CodeSigningCert `
                -Subject "CN=PowerShell Script Signing Certificate" `
                -KeyUsage DigitalSignature `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(5)
        
        $certPath = "$env:TEMP\PowerShellSigningCert.cer"
        $cert | Export-Certificate -FilePath $certPath | Out-Null
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
        Remove-Item $certPath
    }
    return $cert
}

function Test-ScriptSignature {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    return $sig.Status -eq 'Valid'
}

# Main process
try {
    $cert = Initialize-CodeSigningEnvironment
    
    if (Test-Path $ScriptPath) {
        if (-not (Test-ScriptSignature -Path $ScriptPath)) {
            Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -HashAlgorithm SHA256
        }
        Get-AuthenticodeSignature $ScriptPath | Select-Object Status, StatusMessage, SignerCertificate | Format-List
    }
    else {
        Write-Warning "Script not found: $ScriptPath"
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
```

### Advanced Version Features

- Complete trust chain configuration (Root + TrustedPublisher)
- Stronger cryptography (RSA 2048)
- System-wide execution policies
- Detailed error handling
- Comprehensive verification
- Parameterized script path

## Usage Guide

### For Basic Version

1. Set your script path in `$path` variable
2. Run script:
   ```powershell
   .\Basic-ScriptSigner.ps1
   ```

### For Advanced Version

1. Run with default profile path:
   ```powershell
   .\Advanced-ScriptSigner.ps1
   ```
2. Or specify custom path:
   ```powershell
   .\Advanced-ScriptSigner.ps1 -ScriptPath "C:\scripts\custom.ps1"
   ```

## Verification Commands

```powershell
# Check execution policies
Get-ExecutionPolicy -List

# Verify certificate trust
Get-ChildItem Cert:\CurrentUser\My, Cert:\CurrentUser\Root | 
    Where-Object { $_.Subject -like "*PowerShell*" } |
    Format-List Subject, Thumbprint, NotAfter

# Check script signature
Get-AuthenticodeSignature "your_script.ps1" | Format-List
```

## Security Recommendations

1. **Certificate Types**:
   - Use self-signed certs only for testing
   - Production environments should use CA-issued certificates

2. **Execution Policies**:
   - `RemoteSigned` balances security and usability
   - `AllSigned` provides stricter security but requires all scripts be signed

3. **Certificate Management**:
   - Regularly rotate certificates (annual recommended)
   - Keep private keys secure
   - Revoke compromised certificates immediately

## Troubleshooting

**Issue**: "UnknownError" in signature status  
**Solution**:  
```powershell
# Re-import certificate to trusted stores
$cert | Export-Certificate -FilePath "$env:TEMP\temp.cer"
Import-Certificate -FilePath "$env:TEMP\temp.cer" -CertStoreLocation Cert:\CurrentUser\Root
```

**Issue**: Script won't run after signing  
**Solution**: Verify:
1. Certificate is in TrustedPublisher store
2. Execution policy is properly set
3. Certificate hasn't expired

## Version Comparison

| Feature                | Basic Version | Advanced Version |
|------------------------|---------------|------------------|
| Certificate Creation   | ✓             | ✓ (Stronger)     |
| Trust Chain Setup      | Basic         | Complete         |
| Execution Policy       | CurrentUser   | System-wide      |
| Error Handling         | Minimal       | Comprehensive    |
| Admin Rights Required  | No            | Yes              |
| Verification Output    | No            | Yes              |
| Recommended Use Case   | Personal      | Enterprise       |
```

This documentation provides:
1. Clear separation between basic and advanced versions
2. Complete script code blocks
3. Usage instructions for both versions
4. Verification methods
5. Security recommendations
6. Troubleshooting guide
7. Feature comparison table

The markdown is ready to add to your GitHub repository's README.md file.
