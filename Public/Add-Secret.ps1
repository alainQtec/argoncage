function Add-Secret {
    [CmdletBinding()]
    [Alias('Save-Secret')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        # Provide the details of what you are storing
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Metadata,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $Key = (Get-Key -WarningAction SilentlyContinue)
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            $PwndCount = ([Vault]::GetHackedPasswords($value)).Count
            $Is_Hacked = $PwndCount -gt 0
            if ($Is_Hacked) {
                Write-Warning "Secret '$value' was hacked $($res) time(s); Consider changing it ASAP!"
            }
            $encryptedValue = [Vault]::Encrypt($Value, $Key)
            # create the database and save the KV pair
            $null = [Vault]::CreateDb()
            $SqlParameters = @{
                N = $Name
                V = $encryptedValue
                M = $Metadata
                D = Get-Date
                U = $null
            }
            Invoke-SqliteQuery -DataSource ([Vault]::GetDbPath()) -Query "INSERT INTO _ (Name, Value, Metadata, AddedOn, UpdatedOn) VALUES (@N, @V, @M, @D, @U)" -SqlParameters $SqlParameters
            # cleaning up
            [Vault]::ClearHistory($MyInvocation.MyCommand.Name)
        } else { [Vault]::Write_connectionWarning() }
    }
}