function Import-Vault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $RecoveryWord
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ([ArgonCage]::vault.validateRecoveryWord($RecoveryWord)) {
                $res = Import-Clixml -Path ([ArgonCage]::vault.ConnectionFile)
                return [PSCustomObject]@{
                    UserName = $res.UserName
                    Password = ([pscredential]::new("P", $res.Password)).GetNetworkCredential().Password
                }
            } else {
                Write-Warning "Recovery word is incorrect. Please pass the valid recovery word and try again."
            }
        } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
    }
}