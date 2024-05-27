function Remove-Vault {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [Alias('Delete-Vault')]
    param (
        [switch] $Force
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ($Force.IsPresent -or $PSCmdlet.ShouldProcess("Vault", "Remove ArgonCage vault")) {
                [ArgonCage]::vault.ClearDb()
            }
        } else { [ArgonCage]::vault.write_connectionWarning() }
    }
}