# =========================================================================
# NAME: CredentialManagement.psm1
# DESCRIPTION: Stores vCenter and NetApp credentials in a true AES-256 encrypted vault.
#              Includes an interactive menu for admins to manage passwords.
# =========================================================================

$OverlayRoot = if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/..").Path }
$Script:KeyPath = Join-Path $OverlayRoot "conf/vault.key"

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
# Region: vCenter Credential Functions
# ====================================

function Get-vCenterCredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Import-CredentialFile -FilePath $FilePath

    # Convert PSCustomObject to Hashtable so we can add properties safely
    if ($credentials -is [PSCustomObject]) {
        $credentials = $credentials | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    }
    
    if (-not $credentials) { 
        $credentials = @{} 
    }
    
    if (-not $credentials.ContainsKey('vCenters')) {
        $credentials['vCenters'] = @()
    }
    
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

# ====================================
# Region: NetApp Credential Functions
# ====================================

function Get-NetAppCredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Import-CredentialFile -FilePath $FilePath

    # Convert PSCustomObject to Hashtable so we can add properties safely
    if ($credentials -is [PSCustomObject]) {
        $credentials = $credentials | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    }
    
    if (-not $credentials) { 
        $credentials = @{} 
    }
    
    if (-not $credentials.ContainsKey('netappClusters')) {
        $credentials['netappClusters'] = @()
    }
    
    return $credentials
}

function Set-NetAppCredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSObject]$Credentials, [Parameter(Mandatory)][string]$FilePath)
    Export-CredentialFile -Data $Credentials -FilePath $FilePath
}

function Add-NetAppCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FQDN,
        [Parameter(Mandatory)][PSCredential]$AdminCred,
        [Parameter(Mandatory)][string]$FilePath
    )
    $credentials = Get-NetAppCredentialStore -FilePath $FilePath
    $existing = $credentials.netappClusters | Where-Object { $_.FQDN -eq $FQDN }
    
    if ($existing) {
        Write-Output "A NetApp credential entry for '$FQDN' already exists."
        return $false
    }

    $credentials.netappClusters += @{
        FQDN      = $FQDN
        AdminCred = ConvertTo-StorableCredential -Cred $AdminCred
    }
    
    Set-NetAppCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "New NetApp credential entry for '$FQDN' safely encrypted and added to vault."
    return $true
}

function Get-NetAppCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FQDN, [Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Get-NetAppCredentialStore -FilePath $FilePath
    $entry = $credentials.netappClusters | Where-Object { $_.FQDN -eq $FQDN }
    
    if ($entry) {
        $adminCredential = New-Object PSCredential $entry.AdminCred.UserName, (ConvertTo-SecureString $entry.AdminCred.Password -AsPlainText -Force)
        
        return [PSCustomObject]@{
            FQDN      = $entry.FQDN
            AdminCred = $adminCredential
        }
    }
    Write-Warning "No NetApp credential entry found for '$FQDN'."
    return $null
}

function Update-NetAppCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FQDN,
        [Parameter(Mandatory)][string]$FilePath,
        [PSCredential]$NewAdminCred
    )
    $credentials = Get-NetAppCredentialStore -FilePath $FilePath
    $entry = $credentials.netappClusters | Where-Object { $_.FQDN -eq $FQDN }
    
    if (-not $entry) {
        Write-Warning "No NetApp entry found for '$FQDN'."
        return $false
    }

    if ($NewAdminCred) { $entry.AdminCred = ConvertTo-StorableCredential -Cred $NewAdminCred }

    Set-NetAppCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "NetApp credential entry for '$FQDN' updated securely."
    return $true
}

function Remove-NetAppCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FQDN, [Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Get-NetAppCredentialStore -FilePath $FilePath
    $origCount = $credentials.netappClusters.Count
    $credentials.netappClusters = @($credentials.netappClusters | Where-Object { $_.FQDN -ne $FQDN })
    
    if ($credentials.netappClusters.Count -eq $origCount) {
        Write-Warning "No NetApp credential entry for '$FQDN' was found to remove."
        return $false
    }
    
    Set-NetAppCredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "NetApp credential entry for '$FQDN' removed."
    return $true
}

# ====================================
# Region: F5 BIG-IP Credential Functions
# ====================================

function Get-F5CredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Import-CredentialFile -FilePath $FilePath
    if ($credentials -is [PSCustomObject]) {
        $credentials = $credentials | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    }
    if (-not $credentials) { $credentials = @{} }
    if (-not $credentials.ContainsKey('f5Devices')) {
        $credentials['f5Devices'] = @()
    }
    return $credentials
}

function Set-F5CredentialStore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSObject]$Credentials, [Parameter(Mandatory)][string]$FilePath)
    Export-CredentialFile -Data $Credentials -FilePath $FilePath
}

function Add-F5Credential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FQDN,
        [Parameter(Mandatory)][PSCredential]$AdminCred,
        [Parameter(Mandatory)][string]$FilePath
    )
    $credentials = Get-F5CredentialStore -FilePath $FilePath
    $existing = $credentials.f5Devices | Where-Object { $_.FQDN -eq $FQDN }
    if ($existing) {
        Write-Output "An F5 credential entry for '$FQDN' already exists."
        return $false
    }

    $credentials.f5Devices += @{
        FQDN      = $FQDN
        AdminCred = ConvertTo-StorableCredential -Cred $AdminCred
    }
    Set-F5CredentialStore -Credentials $credentials -FilePath $FilePath
    Write-Output "New F5 credential entry for '$FQDN' safely encrypted and added to vault."
    return $true
}

function Get-F5Credential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FQDN, [Parameter(Mandatory)][string]$FilePath)
    
    $credentials = Get-F5CredentialStore -FilePath $FilePath
    $entry = $credentials.f5Devices | Where-Object { $_.FQDN -eq $FQDN }
    if ($entry) {
        $adminCredential = New-Object PSCredential $entry.AdminCred.UserName, (ConvertTo-SecureString $entry.AdminCred.Password -AsPlainText -Force)
        return [PSCustomObject]@{
            FQDN      = $entry.FQDN
            AdminCred = $adminCredential
        }
    }
    Write-Warning "No F5 credential entry found for '$FQDN'."
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
        Write-Output "     Credential Manager"
        Write-Output "============================="
        Write-Output "1. Manage vCenter Credentials"
        Write-Output "2. Manage NetApp Credentials"
        Write-Output "3. Manage F5 BIG-IP Credentials"
        Write-Output "4. Exit"
        Write-Output "============================="
        $choice = Read-Host "Select an option (1-4)"

        switch ($choice) {
            "1" { Show-VCenterMenu -FilePath $FilePath }
            "2" { Show-NetAppMenu -FilePath $FilePath }
            "3" { Show-F5Menu -FilePath $FilePath }
            "4" {
                Write-Output "Exiting Credential Manager..."
                return
            }
            default {
                Write-Warning "Invalid choice."
                Pause
            }
        }
    } while ($true)
}

function Show-VCenterMenu {
    param([string]$FilePath)

    do {
        Clear-Host
        Write-Output "============================="
        Write-Output "   vCenter Credential Manager"
        Write-Output "============================="
        Write-Output "1. Add vCenter credentials"
        Write-Output "2. Modify vCenter credentials"
        Write-Output "3. Remove vCenter credentials"
        Write-Output "4. View vCenter entries"
        Write-Output "5. Back to main menu"
        Write-Output "============================="
        $choice = Read-Host "Select an option (1-5)"

        switch ($choice) {
            "1" {
                $fqdn = Read-Host "Enter the vCenter FQDN"
                $adminCred = Get-Credential -Message "Enter vCenter Admin Credentials (e.g. administrator@vsphere.local)"
                $rootCred  = Get-Credential -Message "Enter vCenter Root Password" -UserName "root"
                $esxiCred  = Get-Credential -Message "Enter ESXi Root Password" -UserName "root"
                Add-vCenterCredential -FQDN $fqdn -AdminCred $adminCred -RootCred $rootCred -EsxiCred $esxiCred -FilePath $FilePath
                Pause
            }
            "2" {
                $fqdn = Read-Host "Enter the vCenter FQDN to modify"
                $newAdminCred = Get-Credential -Message "Enter new vCenter Admin Credentials"
                $newRootCred  = Get-Credential -Message "Enter new vCenter Root Password" -UserName "root"
                $newEsxiCred  = Get-Credential -Message "Enter new ESXi Root Password" -UserName "root"
                Update-vCenterCredential -FQDN $fqdn -FilePath $FilePath -NewAdminCred $newAdminCred -NewRootCred $newRootCred -NewEsxiCred $newEsxiCred
                Pause
            }
            "3" {
                $fqdn = Read-Host "Enter the vCenter FQDN to remove"
                Remove-vCenterCredential -FQDN $fqdn -FilePath $FilePath
                Pause
            }
            "4" {
                $credentials = Get-vCenterCredentialStore -FilePath $FilePath
                if ($credentials.vCenters -and $credentials.vCenters.Count -gt 0) {
                    Write-Output "`nStored vCenter FQDNs:"
                    $credentials.vCenters | ForEach-Object { Write-Output $_.FQDN }
                } else {
                    Write-Warning "No vCenter entries found."
                }
                Pause
            }
            "5" { return }
            default {
                Write-Warning "Invalid choice."
                Pause
            }
        }
    } while ($true)
}

function Show-NetAppMenu {
    param([string]$FilePath)

    do {
        Clear-Host
        Write-Output "============================="
        Write-Output "   NetApp Credential Manager"
        Write-Output "============================="
        Write-Output "1. Add NetApp cluster credentials"
        Write-Output "2. Modify NetApp credentials"
        Write-Output "3. Remove NetApp credentials"
        Write-Output "4. View NetApp entries"
        Write-Output "5. Back to main menu"
        Write-Output "============================="
        $choice = Read-Host "Select an option (1-5)"

        switch ($choice) {
            "1" {
                $fqdn = Read-Host "Enter the NetApp cluster FQDN"
                $adminCred = Get-Credential -Message "Enter NetApp Cluster Admin Credentials"
                Add-NetAppCredential -FQDN $fqdn -AdminCred $adminCred -FilePath $FilePath
                Pause
            }
            "2" {
                $fqdn = Read-Host "Enter the NetApp cluster FQDN to modify"
                $newAdminCred = Get-Credential -Message "Enter new NetApp Admin Credentials"
                Update-NetAppCredential -FQDN $fqdn -FilePath $FilePath -NewAdminCred $newAdminCred
                Pause
            }
            "3" {
                $fqdn = Read-Host "Enter the NetApp cluster FQDN to remove"
                Remove-NetAppCredential -FQDN $fqdn -FilePath $FilePath
                Pause
            }
            "4" {
                $credentials = Get-NetAppCredentialStore -FilePath $FilePath
                if ($credentials.netappClusters -and $credentials.netappClusters.Count -gt 0) {
                    Write-Output "`nStored NetApp Clusters:"
                    $credentials.netappClusters | ForEach-Object { Write-Output $_.FQDN }
                } else {
                    Write-Warning "No NetApp entries found."
                }
                Pause
            }
            "5" { return }
            default {
                Write-Warning "Invalid choice."
                Pause
            }
        }
    } while ($true)
}

function Show-F5Menu {
    param([string]$FilePath)

    do {
        Clear-Host
        Write-Output "============================="
        Write-Output "   F5 BIG-IP Credential Manager"
        Write-Output "============================="
        Write-Output "1. Add F5 BIG-IP credentials"
        Write-Output "2. Modify F5 BIG-IP credentials"
        Write-Output "3. Remove F5 BIG-IP credentials"
        Write-Output "4. View F5 BIG-IP entries"
        Write-Output "5. Back to main menu"
        Write-Output "============================="
        $choice = Read-Host "Select an option (1-5)"

        switch ($choice) {
            "1" {
                $fqdn = Read-Host "Enter the F5 BIG-IP FQDN"
                $adminCred = Get-Credential -Message "Enter F5 BIG-IP Admin Credentials"
                Add-F5Credential -FQDN $fqdn -AdminCred $adminCred -FilePath $FilePath
                Pause
            }
            "2" {
                $fqdn = Read-Host "Enter the F5 BIG-IP FQDN to modify"
                $newAdminCred = Get-Credential -Message "Enter new F5 BIG-IP Admin Credentials"
                Update-F5Credential -FQDN $fqdn -FilePath $FilePath -NewAdminCred $newAdminCred
                Pause
            }
            "3" {
                $fqdn = Read-Host "Enter the F5 BIG-IP FQDN to remove"
                Remove-F5Credential -FQDN $fqdn -FilePath $FilePath
                Pause
            }
            "4" {
                $credentials = Get-F5CredentialStore -FilePath $FilePath
                if ($credentials.f5Devices -and $credentials.f5Devices.Count -gt 0) {
                    Write-Output "`nStored F5 BIG-IP Devices:"
                    $credentials.f5Devices | ForEach-Object { Write-Output $_.FQDN }
                } else {
                    Write-Warning "No F5 BIG-IP entries found."
                }
                Pause
            }
            "5" { return }
            default {
                Write-Warning "Invalid choice."
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

Export-ModuleMember -Function Invoke-CredentialManager, 
    Add-vCenterCredential, Update-vCenterCredential, Remove-vCenterCredential, Get-vCenterCredential, Get-vCenterCredentialStore,
    Add-NetAppCredential, Get-NetAppCredential, Update-NetAppCredential, Remove-NetAppCredential, Get-NetAppCredentialStore,
    Add-F5Credential, Get-F5Credential, Get-F5CredentialStore