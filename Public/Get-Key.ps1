function Get-Key {
    [CmdletBinding()]
    [Alias('Fetch-Key')]
    [OutputType([string])]
    param (
        [switch] $Force
    )
    process {
        if ([ArgonCage]::vault.GetConnection().IsValid) {
            if ([IO.File]::Exists([ArgonCage]::vault.GetKeyFile())) {
                $res = Import-Clixml ([ArgonCage]::vault.GetKeyFile())
                $key = [pscredential]::new("key", $res)
                $key = $key.GetNetworkCredential().Password
            }
            if (![IO.File]::Exists([ArgonCage]::vault.GetKeyFile())) {
                $key = [ArgonCage]::vault.GenerateKey(); [ArgonCage]::vault.SaveKey($key, $false)
            }
            if ($Force.IsPresent) {
                [ArgonCage]::vault.ArchiveKeyFile()
                $key = [ArgonCage]::vault.GenerateKey(); [ArgonCage]::vault.SaveKey($key, $true)
            }
            return $key
        } else { Write-Warning -Message [Vault].MSG.CONNECTION_WARNING }
    }
}