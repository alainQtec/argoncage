function Import-Vault {
    [CmdletBinding()]
    [Alias('Load-Vault')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $RecoveryWord
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            if ([Vault]::ValidateRecoveryWord($RecoveryWord)) {
                $res = Import-Clixml -Path ([Vault]::GetConnectionFile())
                return [PSCustomObject]@{
                    UserName = $res.UserName
                    Password = ([pscredential]::new("P", $res.Password)).GetNetworkCredential().Password
                }
            } else {
                Write-Warning "Recovery word is incorrect. Please pass the valid recovery word and try again."
            }
        } else { [Vault]::Write_connectionWarning() }
    }
}