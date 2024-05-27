function Disconnect-Vault {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [switch] $Force
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ($Force.IsPresent -or $PSCmdlet.ShouldProcess("Connection", "Disconnect Vault")) {
                [ArgonCage]::vault.ClearConnection()
            }
        } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
    }
}