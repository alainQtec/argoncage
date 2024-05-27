function Import-Vault {
    [CmdletBinding()]
    [Alias('LoadVault')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $RecoveryWord
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ([ArgonCage]::vault.validateRecoveryWord($RecoveryWord)) {
                $res = Import-Clixml -Path ([ArgonCage]::vault.GetConnectionFile())
                return [PSCustomObject]@{
                    UserName = $res.UserName
                    Password = ([pscredential]::new("P", $res.Password)).GetNetworkCredential().Password
                }
            } else {
                Write-Warning "Recovery word is incorrect. Please pass the valid recovery word and try again."
            }
        } else { [ArgonCage]::vault.write_connectionWarning() }
    }
}