function Connect-Vault {
    [CmdletBinding()]
    [Alias('Access-Vault')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [pscredential] $Credential
    )
    process {
        $vaultSession = [ArgonCage]::GetVault()
        $vaultSession.UserName = if ([string]::IsNullOrEmpty($Credential.UserName)) { [ArgonCage]::vault.UserName } else { $Credential.UserName }
        $vaultSession.Password = $Credential.Password
        # Return the Vault object so that it can be consumed and verified by other cmdlets
        $VAULT_USER = $vaultSession.UserName; [ValidateNotNullOrEmpty()][string]$VAULT_USER = $VAULT_USER
        $VAULT_PASS = $vaultSession.Password | ConvertFrom-SecureString; [ValidateNotNullOrEmpty()][string]$VAULT_PASS = $VAULT_PASS
        [System.Environment]::SetEnvironmentVariable("ARGONCAGE_U", $VAULT_USER, [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable("ARGONCAGE_P", $VAULT_PASS, [System.EnvironmentVariableTarget]::Process)
        return $vaultSession
    }
}