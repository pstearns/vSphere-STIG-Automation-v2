# =========================================================================
# NAME: CredentialManagement.psm1
# DESCRIPTION: Stores vCenter credentials in a true AES-256 encrypted vault.
#              Includes an interactive menu for admins to manage passwords.
# =========================================================================

$Script:KeyPath = "/usr/share/stigs/orchestration_overlay/conf/vault.key"

# ===============================
# Region: True AES-256 Encryption
# ===============================

function Ensure-EncryptionKey {
    if (-not (Test-Path $Script:KeyPath)) {
        Write-Host "Generating new AES encryption key at $Script:KeyPath"
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.GenerateKey()
        $keyBytes = $aes.Key
        [System.IO.File]::WriteAllBytes($Script:KeyPath, $keyBytes)
        if ($IsLinux) { bash -c "chmod 600 $Script:KeyPath" }
    }
    return [System.IO.File]::ReadAllBytes($Script:KeyPath)
}

function Protect-String {
    param ([string]$PlainText)
    
    $Key = Ensure-EncryptionKey
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $Key
    $Aes.GenerateIV()
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $Encryptor = $Aes.CreateEncryptor()
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    
    $FinalPayload = New-Object Byte[] ($Aes.IV.Length + $EncryptedBytes.Length)
    [Array]::Copy($Aes.IV, 0, $FinalPayload, 0, $Aes.IV.Length)
    [Array]::Copy($EncryptedBytes, 0, $FinalPayload, $Aes.IV.Length, $EncryptedBytes.Length)
    
    $Aes.Dispose()
    return $FinalPayload
}

function Unprotect-String {
    param ([byte[]]$Payload)
    try {
        $Key = Ensure-EncryptionKey
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.Key = $Key
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $IV = New-Object Byte[] 16
        [Array]::Copy($Payload, 0, $IV, 0, 16)
        $Aes.IV = $IV
        
        $CipherBytes = New-Object Byte[] ($Payload.Length - 16)
        [Array]::Copy($Payload, 16, $CipherBytes, 0, $CipherBytes.Length)
        
        $Decryptor = $Aes.CreateDecryptor()
        $DecryptedBytes = $Decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
        $Aes.Dispose()
        
        return [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
    } catch {
        Write-Error "Failed to decrypt vault. The encryption key may be missing or mismatched."
        return $null
    }
}

# ===============================
# Region: Vault I/O
# ===============================

function Set-SecureFilePermissions {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) {
        New-Item -ItemType File -Path $FilePath -Force | Out-Null
    }
    if ($IsLinux) { bash -c "chmod 600 $FilePath" }
}

function Export-CredentialFile {
    param([PSObject]$Data, [string]$FilePath)
    $jsonContent = $Data | ConvertTo-Json -Depth 10 -Compress
    $encryptedBytes = Protect-String -PlainText $jsonContent
    [System.IO.File]::WriteAllBytes($FilePath, $encryptedBytes)
    if ($IsLinux) { bash -c "chmod 600 $FilePath" }
}

function Import-CredentialFile {
    param([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return @{} }
        $encryptedBytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($encryptedBytes.Length -eq 0) { return @{} }
        
        $jsonContent = Unprotect-String -Payload $encryptedBytes
        if ([string]::IsNullOrWhiteSpace($jsonContent)) { return @{} }
        return $jsonContent | ConvertFrom-Json
    } catch {
        Write-Warning "Unable to import or decrypt the credential file."
        return @{}
    }
}

# ===============================
# Region: Credential Conversion
# ===============================

function ConvertTo-StorableCredential {
    [CmdletBinding()]
    param([PSCredential]$Cred)
    return @{
        UserName = $Cred.UserName
        Password = $Cred.GetNetworkCredential().Password
    }
}

# ====================================
# Region: Credential Storage Functions
# ====================================

function Get-vCenterCredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Import-CredentialFile -FilePath $FilePath
    if (-not $credentials.vCenters) { $credentials = @{ vCenters = @() } }
    elseif (-not ($credentials.vCenters -is [array])) { $credentials.vCenters = @($credentials.vCenters) }
    return $credentials
}

function Set-vCenterCredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSObject]$Credentials, [Parameter(Mandatory)][string]$FilePath)
    Export-CredentialFile -Data $Credentials -FilePath $FilePath
}

function Add-vCenterCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FQDN,
        [Parameter(Mandatory)][PSCredential]$AdminCred,
        [Parameter(Mandatory)][PSCredential]$RootCred,
        [Parameter(Mandatory)][PSCredential]$EsxiCred,
        [Parameter(Mandatory)][string]$FilePath
    )
    $credentials = Get-vCenterCredentialStore -FilePath $FilePath
    $existing = $credentials.vCenters | Where-Object { $_.FQDN -eq $FQDN }
    
    if ($existing) {
        Write-Output "An entry for '$FQDN' already exists."
        return $false
    }

    $credentials.vCenters += @{
        FQDN      = $FQDN
        AdminCred = ConvertTo-StorableCredential -Cred $AdminCred
        RootCred  = ConvertTo-StorableCredential -Cred $RootCred
        EsxiCred  = ConvertTo-StorableCredential -Cred $EsxiCred
    }
    
    Set-vCenterCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "New credential entry for '$FQDN' safely encrypted and added to vault."
    return $true
}

function Update-vCenterCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FQDN,
        [Parameter(Mandatory)][string]$FilePath,
        [PSCredential]$NewAdminCred,
        [PSCredential]$NewRootCred,
        [PSCredential]$NewEsxiCred
    )
    $credentials = Get-vCenterCredentialStore -FilePath $FilePath
    $entry = $credentials.vCenters | Where-Object { $_.FQDN -eq $FQDN }
    
    if (-not $entry) {
        Write-Warning "No entry found for '$FQDN'."
        return $false
    }

    if ($NewAdminCred) { $entry.AdminCred = ConvertTo-StorableCredential -Cred $NewAdminCred }
    if ($NewRootCred)  { $entry.RootCred  = ConvertTo-StorableCredential -Cred $NewRootCred }
    if ($NewEsxiCred)  { $entry.EsxiCred  = ConvertTo-StorableCredential -Cred $NewEsxiCred }

    Set-vCenterCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "Credential entry for '$FQDN' updated securely."
    return $true
}

function Remove-vCenterCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FQDN, [Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Get-vCenterCredentialStore -FilePath $FilePath
    $origCount = $credentials.vCenters.Count
    $credentials.vCenters = @($credentials.vCenters | Where-Object { $_.FQDN -ne $FQDN })
    
    if ($credentials.vCenters.Count -eq $origCount) {
        Write-Warning "No credential entry for '$FQDN' was found to remove."
        return $false
    }
    
    Set-vCenterCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "Credential entry for '$FQDN' removed."
    return $true
}

function Get-vCenterCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FQDN, [Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Get-vCenterCredentialStore -FilePath $FilePath
    $entry = $credentials.vCenters | Where-Object { $_.FQDN -eq $FQDN }
    
    if ($entry) {
        $adminCredential = New-Object PSCredential $entry.AdminCred.UserName, (ConvertTo-SecureString $entry.AdminCred.Password -AsPlainText -Force)
        $rootCredential  = New-Object PSCredential $entry.RootCred.UserName,  (ConvertTo-SecureString $entry.RootCred.Password -AsPlainText -Force)
        $esxiCredential  = New-Object PSCredential $entry.EsxiCred.UserName,  (ConvertTo-SecureString $entry.EsxiCred.Password -AsPlainText -Force)
        
        return [PSCustomObject]@{
            FQDN      = $entry.FQDN
            AdminCred = $adminCredential
            RootCred  = $rootCredential
            EsxiCred  = $esxiCredential
        }
    }
    Write-Warning "No credential entry found for '$FQDN'."
    return $null
}

# ================================
# Region: Menu / Interactive Mode
# ================================
function Show-CredentialMenu {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)

    do {
        Clear-Host
        Write-Output "============================="
        Write-Output "  vCenter Credential Manager"
        Write-Output "============================="
        Write-Output "1. Add credentials"
        Write-Output "2. Modify credentials"
        Write-Output "3. Remove credentials"
        Write-Output "4. View credentials"
        Write-Output "5. Exit"
        Write-Output "====================="
        $choice = Read-Host "Select an option (1-5)"

        switch ($choice) {
            "1" {
                $fqdn = Read-Host "Enter the FQDN"
                $credentials = Get-vCenterCredentialStore -FilePath $FilePath
                $existing = $credentials.vCenters | Where-Object { $_.FQDN -eq $fqdn }
                if ($existing) {
                    Write-Output "An entry for '$fqdn' already exists."
                    $modifyChoice = Read-Host "Do you want to modify the existing entry? (Y/N)"
                    if ($modifyChoice -match "^[Yy]") {
                        $newAdminCred = Get-Credential -Message "Enter new VCSA Admin Credentials (suggestion: administrator@vsphere.local)"
                        $newRootCred = Get-Credential -Message "Enter new VCSA Root Password" -UserName "root"
                        $newEsxiCred = Get-Credential -Message "Enter new ESXi Root Password" -UserName "root"
                        Update-vCenterCredential -FQDN $fqdn -FilePath $FilePath -NewAdminCred $newAdminCred -NewRootCred $newRootCred -NewEsxiCred $newEsxiCred
                        Pause
                    } else {
                        Write-Output "No changes made. Returning to menu."
                        Pause
                    }
                } else {
                    $adminCred = Get-Credential -Message "Enter VCSA Admin Credentials (suggestion: administrator@vsphere.local)"
                    $rootCred = Get-Credential -Message "Enter VCSA Root Password" -UserName "root"
                    $esxiCred = Get-Credential -Message "Enter ESXi Root Password" -UserName "root"
                    Add-vCenterCredential -FQDN $fqdn -AdminCred $adminCred -RootCred $rootCred -EsxiCred $esxiCred -FilePath $FilePath
                    Pause
                }
            }
            "2" {
                $credentials = Get-vCenterCredentialStore -FilePath $FilePath
                if (-not $credentials.vCenters -or $credentials.vCenters.Count -eq 0) {
                    Write-Warning "No vCenter entries found to modify."
                    Pause
                    break
                }
                Write-Output "Stored vCenter FQDNs:"
                $credentials.vCenters | ForEach-Object { Write-Output $_.FQDN }
                $fqdn = Read-Host "Enter the FQDN for the entry you want to modify"
                $entry = $credentials.vCenters | Where-Object { $_.FQDN -eq $fqdn }
                if ($entry) {
                    $newAdminCred = Get-Credential -Message "Enter new VCSA Admin Credentials (suggestion: administrator@vsphere.local)"
                    $newRootCred = Get-Credential -Message "Enter new VCSA Root Password" -UserName "root"
                    $newEsxiCred = Get-Credential -Message "Enter new ESXi Root Password" -UserName "root"
                    Update-vCenterCredential -FQDN $fqdn -FilePath $FilePath -NewAdminCred $newAdminCred -NewRootCred $newRootCred -NewEsxiCred $newEsxiCred
                } else {
                    Write-Warning "No entry found for '$fqdn'."
                }
                Pause
            }
            "3" {
                $credentials = Get-vCenterCredentialStore -FilePath $FilePath
                if (-not $credentials.vCenters -or $credentials.vCenters.Count -eq 0) {
                    Write-Warning "No vCenter entries found to remove."
                    Pause
                    break
                }
                Write-Output "Stored vCenter FQDNs:"
                $credentials.vCenters | ForEach-Object { Write-Output $_.FQDN }
                $fqdn = Read-Host "Enter the FQDN for the entry you want to remove"
                Remove-vCenterCredential -FQDN $fqdn -FilePath $FilePath
                Pause
            }
            "4" {
                $credentials = Get-vCenterCredentialStore -FilePath $FilePath
                if ($credentials.vCenters -and $credentials.vCenters.Count -gt 0) {
                    Write-Output "Stored vCenter Credential Entries:"
                    $credentials.vCenters | ForEach-Object { Write-Output $_.FQDN }
                } else {
                    Write-Warning "No vCenter entries found."
                }
                Pause
            }
            "5" {
                Write-Output "Exiting Credential Manager..."
                return
            }
            default {
                Write-Warning "Invalid choice. Please select a valid option."
                Pause
            }
        }
    } while ($true)
}

# ======================
# Region: Main Entry Point
# ======================
function Invoke-CredentialManager {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$FilePath)
    Set-SecureFilePermissions -FilePath $FilePath
    Show-CredentialMenu -FilePath $FilePath
}

Export-ModuleMember -Function Invoke-CredentialManager, Add-vCenterCredential, Update-vCenterCredential, Remove-vCenterCredential, Get-vCenterCredential, Get-vCenterCredentialStore