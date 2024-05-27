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
        $personalVault = [ArgonCage]::vault
        $personalVault.UserName = if ([string]::IsNullOrEmpty($Credential.UserName)) { [ArgonCage]::vault.GetUser() } else { $Credential.UserName }
        $personalVault.Password = $Credential.Password
        $personalVault.Key = $RecoveryWord
        if (!(Test-Path ([ArgonCage]::vault.GetConnectionFile()))) { $personalVault | Export-Clixml -Path ([ArgonCage]::vault.GetConnectionFile()) }
        if ($Force.IsPresent) {
            if ([ArgonCage]::vault.GetConnection().IsValid) {
                $personalVault | Export-Clixml -Path ([ArgonCage]::vault.GetConnectionFile()) -Force
            } else { [ArgonCage]::vault.write_connectionWarning() }
        }
    }
}