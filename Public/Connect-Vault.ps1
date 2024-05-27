﻿function Connect-Vault {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseOutputTypeCorrectly", "")]
    [CmdletBinding()]
    [Alias('Login-Vault', 'Access-Vault')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [pscredential] $Credential
    )
    process {
        $personalVault = [ArgonCage]::vault
        $personalVault.UserName = if ([string]::IsNullOrEmpty($Credential.UserName)) { [ArgonCage]::vault.GetUser() } else { $Credential.UserName }
        $personalVault.Password = $Credential.Password
        # Return the Vault object so that it can be consumed and verified by other cmdlets
        $VAULT_USER = $personalVault.UserName; [ValidateNotNullOrEmpty()][string]$VAULT_USER = $VAULT_USER
        $VAULT_PASS = $personalVault.Password | ConvertFrom-SecureString; [ValidateNotNullOrEmpty()][string]$VAULT_PASS = $VAULT_PASS
        [System.Environment]::SetEnvironmentVariable("ARGONCAGE_U", $VAULT_USER, [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable("ARGONCAGE_P", $VAULT_PASS, [System.EnvironmentVariableTarget]::Process)
        return $personalVault
    }
}