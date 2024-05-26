function Update-Secret {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [Alias('Set-Secret', 'Edit-Secret')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ArgumentCompleter([NameCompleter])]
        [ValidateNotNullOrEmpty()]
        [string] $Name,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ArgumentCompleter([IdCompleter])]
        [int] $Id,
        [ValidateNotNullOrEmpty()]
        [string] $Key = (Get-Key -WarningAction SilentlyContinue),
        [switch] $Force
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            $res = ([Vault]::GetHackedPasswords($value)).Count
            $IsHacked = $res -gt 0
            if ($IsHacked) {
                Write-Warning "Secret '$value' was hacked $($res) time(s); Consider changing it ASAP!"
            }
            if ($Force -or $PSCmdlet.ShouldProcess($Value, "Update-Secret")) {
                $encryptedValue = [Vault]::Encrypt($Value, $Key)
                Invoke-SqliteQuery -DataSource ([Vault]::GetDbPath()) -Query "UPDATE _ SET Value = '$encryptedValue', UpdatedOn = (@D) WHERE Name = '$Name' AND Id = '$Id'" -SqlParameters @{
                    D = Get-Date
                }
                [Vault]::ClearHistory($MyInvocation.MyCommand.Name)
            }
        } else { [Vault]::Write_connectionWarning() }
    }
}