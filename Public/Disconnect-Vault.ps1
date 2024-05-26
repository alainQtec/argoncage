function Disconnect-Vault {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [switch] $Force
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            if ($Force.IsPresent -or $PSCmdlet.ShouldProcess("Connection", "Disconnect Vault")) {
                [Vault]::ClearConnection()
            }
        } else { [Vault]::Write_connectionWarning() }
    }
}