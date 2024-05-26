function Remove-Vault {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [Alias('Delete-Vault')]
    param (
        [switch] $Force
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            if ($Force.IsPresent -or $PSCmdlet.ShouldProcess("Personal Vault", "Remove-PSPersonalVault")) {
                [Vault]::ClearDb()
            }
        } else { [Vault]::Write_connectionWarning() }
    }
}