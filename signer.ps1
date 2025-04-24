# Define the path to the script you want to sign (you can change this variable)
$path = "F:\VSsetup\TerminalTheme\PowershellScriptSigner\omyposh.ps1"

# Function to check if the certificate exists
function Get-CodeSigningCert {
    # Try to get a code-signing certificate
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
    return $cert
}

# Function to create a new self-signed certificate if one doesn't exist
function Create-SelfSignedCert {
    # Create a new self-signed certificate for code signing
    $newCert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject "CN=MyPowerShellCodeSigningCert"
    
    # Export and import the certificate to the Trusted Root Certification Authorities store
    $newCert | Export-Certificate -FilePath "C:\Users\muger\Desktop\MyPowerShellCodeSigningCert.cer"
    Import-Certificate -FilePath "C:\Users\muger\Desktop\MyPowerShellCodeSigningCert.cer" -CertStoreLocation Cert:\CurrentUser\Root
    
    return $newCert
}

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser


# Check if the script is already signed
function Is-ScriptSigned {
    $signature = Get-AuthenticodeSignature $path
    return $signature.Status -eq 'Valid'
}

# Main script execution
$cert = Get-CodeSigningCert

# If no certificate found, create a new one
if (-not $cert) {
    Write-Host "No existing code-signing certificate found. Creating a new one..."
    $cert = Create-SelfSignedCert
} else {
    Write-Host "Using existing certificate for code signing..."
}

# Check if the script is already signed
if (-not (Is-ScriptSigned)) {
    Write-Host "Signing script..."
    Set-AuthenticodeSignature -FilePath $path -Certificate $cert
} else {
    Write-Host "Script is already signed. No action needed."
}

# SIG # Begin signature block
# MIIFkQYJKoZIhvcNAQcCoIIFgjCCBX4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU31wy1iTOHiL5buBErQNsE3Gl
# T/qgggMgMIIDHDCCAgSgAwIBAgIQH2ZOSt3VSYZLZMoYCdggLTANBgkqhkiG9w0B
# AQsFADAmMSQwIgYDVQQDDBtNeVBvd2VyU2hlbGxDb2RlU2lnbmluZ0NlcnQwHhcN
# MjUwNDI0MTM0NDUyWhcNMjYwNDI0MTQwNDUyWjAmMSQwIgYDVQQDDBtNeVBvd2Vy
# U2hlbGxDb2RlU2lnbmluZ0NlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQDhpsd+R8A46BnrmI2+saYKrdvhIBymWcqgVoDiBO3YgwUrMaGNQx8zpHcA
# 1sciJ7AD695lSRtFXHmuwscUClAxlZ71F0U+u7fiVDHkq4+9Mij1ejgu6Yxf4x58
# Yv9Po08kJ4msgeqnN/saqBtFF4x8keQTUxGeG1H3mNsyxxalXAe6zPMlpzL1szBy
# JV6jeeI4IaQZ6qwWLxDESmdd4XKVLeX58zvumzL1H8DaV9YOeulcukbtFz/ng5SD
# nEmnonoaBslNp9RWJkEhZJhiyox8cmKTYUmFOXgEVSbUiJNQylUK4zgishnhtnuk
# BY2Gs3QdwyIVdxPgYmu0WeDhKVSVAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPmVVtOXUmxd+EEgWTeQc6v7
# txYwDQYJKoZIhvcNAQELBQADggEBAAZOUB+SFdHVtGGid6yQ7SbgBik26sbuh+XG
# YoyugSuKh8MQtnc2nA7cfBm/1VRmFyjoK6MMqUrHRUGkAnI3jyZOKgPfa546Rq9N
# 8HprOC+0luHToI058vVD58L6uTwVl5IKvxFQYGUZZ1Z74P8Gwli05q6wv6jN81Cv
# oH6oCsly/j4rsGNQ7IaMtsz3JjhgauDDeGpygqFZ0l33Oa48F8/i4vHRWyZ4AMFk
# I12w7tMKuDw2NOvSo/XWwal6GTkaNnwZg6FARVcL8xRKZDEK21Yf4Ge2igNYnVKu
# mWNUGVaCnqkoXgqUUw3kejdlEMChjcqrVKEDvCWq+gJ/B5zOsXwxggHbMIIB1wIB
# ATA6MCYxJDAiBgNVBAMMG015UG93ZXJTaGVsbENvZGVTaWduaW5nQ2VydAIQH2ZO
# St3VSYZLZMoYCdggLTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUE/qxcoM4E5q+dKSWwC8CJm47
# DgEwDQYJKoZIhvcNAQEBBQAEggEARKEun5FMNLngz29shaYOZHtex4fqxFMplBQL
# uVbnv2oE0WD0ipBRmsw0aj2m1hInyVJWdgYX6jpbWf53LogfUBpjbn+6UduYIwGv
# 7r74/LVTg0BNaOpOcALctopcuDo1ILBYiYNqxeYeDJv9v8rWtideZWUYv4SnBOxm
# LvxEXpV7fmDIPkBp6xNDPCDqEAQuzUCnO4h200XpEwgqv5l2fe24zTeg1uzB6bna
# pf+oRKQ4kvQbSB/CrhWewt4y91keKABd8tGuBoQFtfJ7KzdjTkR7+ulpKIY9Nat5
# uGcrJ+1VA/pnwZkPhqfkzVPl3dA0vkS/UFzjQ5n3x/ZLsPBl7A==
# SIG # End signature block

# Import your certificate to Trusted Publishers store
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
$cert | Export-Certificate -FilePath "$env:TEMP\MyCert.cer"
Import-Certificate -FilePath "$env:TEMP\MyCert.cer" -CertStoreLocation Cert:\CurrentUser\TrustedPublisher
