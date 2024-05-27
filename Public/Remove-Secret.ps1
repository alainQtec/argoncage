function Remove-Secret {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = "Id")]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Id")]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Both")]
        [ValidateNotNullOrEmpty()]
        [ArgumentCompleter([IdCompleter])]
        [int]$Id,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Both")]
        [ArgumentCompleter([NameCompleter])]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [switch]$Force
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ($Force -or $PSCmdlet.ShouldProcess($Name, "Remove-Secret")) {
                if ($PSCmdlet.ParameterSetName -eq "Id") {
                    Invoke-SqliteQuery -DataSource ([ArgonCage]::vault.File) -Query "DELETE FROM _ WHERE Id = '$Id'"
                }
                if ($PSCmdlet.ParameterSetName -eq "Name") {
                    $res = Get-Secret -Name $Name
                    if ($res.Count -eq 1) {
                        Invoke-SqliteQuery -DataSource ([ArgonCage]::vault.File) -Query "DELETE FROM _ WHERE Name = '$Name'"
                    } else {
                        Write-Warning "More than (1) values found for given Name '$Name'; Pass Id to remove the respective value from the vault."
                    }
                }
                if ($PSCmdlet.ParameterSetName -eq "Both") {
                    Invoke-SqliteQuery -DataSource ([ArgonCage]::vault.File) -Query "DELETE FROM _ WHERE Name = '$Name' AND Id = '$Id'"
                }
            }
        } else { [ArgonCage]::vault.write_connectionWarning() }
    }
}