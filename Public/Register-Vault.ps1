function Register-Vault {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [pscredential] $Credential,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $RecoveryWord,
        [switch] $Force
    )
    process {
        $vaultSession = [ArgonCage]::GetVault()
        $vaultSession.UserName = if ([string]::IsNullOrEmpty($Credential.UserName)) { [ArgonCage]::vault.UserName } else { $Credential.UserName }
        $vaultSession.Password = $Credential.Password
        $vaultSession.Key = $RecoveryWord
        if (!(Test-Path ([ArgonCage]::vault.ConnectionFile))) { $vaultSession | Export-Clixml -Path ($vaultSession.ConnectionFile) }
        if ($Force.IsPresent) {
            if ([ArgonCage]::vault.GetConnection().IsValid) {
                $vaultSession | Export-Clixml -Path ([ArgonCage]::vault.ConnectionFile) -Force
            } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
        }
    }
}