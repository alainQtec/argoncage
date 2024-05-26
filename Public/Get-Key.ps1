function Get-Key {
    [CmdletBinding()]
    [Alias('Fetch-Key')]
    [OutputType([string])]
    param (
        [switch] $Force
    )
    process {
        if ([Vault]::GetConnection().IsValid) {
            if ([IO.File]::Exists([Vault]::GetKeyFile())) {
                $res = Import-Clixml ([Vault]::GetKeyFile())
                $key = [pscredential]::new("key", $res)
                $key = $key.GetNetworkCredential().Password
            }
            if (![IO.File]::Exists([Vault]::GetKeyFile())) {
                $key = [vault]::GenerateKey(); [Vault]::SaveKey($key, $false)
            }
            if ($Force.IsPresent) {
                [Vault]::ArchiveKeyFile()
                $key = [vault]::GenerateKey(); [Vault]::SaveKey($key, $true)
            }
            return $key
        } else { [Vault]::Write_connectionWarning() }
    }
}