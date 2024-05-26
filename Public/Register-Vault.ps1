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
        $personalVault = [Vault]::new()
        $personalVault.UserName = if ([string]::IsNullOrEmpty($Credential.UserName)) { [Vault]::GetUser() } else { $Credential.UserName }
        $personalVault.Password = $Credential.Password
        $personalVault.Key = $RecoveryWord
        if (!(Test-Path ([Vault]::GetConnectionFile()))) { $personalVault | Export-Clixml -Path ([Vault]::GetConnectionFile()) }
        if ($Force.IsPresent) {
            if ([Vault]::GetConnection().IsValid) {
                $personalVault | Export-Clixml -Path ([Vault]::GetConnectionFile()) -Force
            } else { [Vault]::Write_connectionWarning() }
        }
    }
}