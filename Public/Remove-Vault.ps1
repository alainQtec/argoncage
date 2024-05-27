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
        } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
    }
}