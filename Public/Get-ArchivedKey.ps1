function Get-ArchivedKey {
    [CmdletBinding()]
    [Alias('Fetch-ArchivedKey')]
    [OutputType([object[]])]
    param (
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [datetime] $DateModified
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            $archivePath = Join-Path -Path (Split-Path -Path ([ArgonCage]::vault.GetKeyFile()) -Parent) -ChildPath "archive"
            if (Test-Path $archivePath) {
                $results = @()
                $archivedFiles = Get-ChildItem -Path $archivePath | Select-Object FullName, LastWriteTime
                if ($PSBoundParameters.ContainsKey('DateModified')) {
                    $archivedFiles = $archivedFiles | Where-Object { (Get-Date $_.LastWriteTime -Format ddMMyyyy) -eq (Get-Date $DateModified -Format ddMMyyyy) }
                }
                $archivedFiles | ForEach-Object {
                    $key = Import-Clixml $_.FullName
                    $keyObj = [pscredential]::new("key", $key)
                    $obj = [PSCustomObject]@{
                        DateModified = $_.LastWriteTime
                        Key          = $keyObj.GetNetworkCredential().Password
                    }
                    $results += $obj
                }
                return $results
            }
        } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
    }
}