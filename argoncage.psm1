using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Runtime.InteropServices

#Requires -Version 5.1
# https://learn.microsoft.com/en-us/answers/questions/444991/powershell-system-security-cryptography-aesgcm-not.html
# Load localizedData:
$dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine((Get-Variable -ValueOnly ExecutionContext).SessionState.path.CurrentLocation.Path, "en-US", "argoncage.strings.psd1"))
if ($dataFile.Exists) {
    $script:localizedData = [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke()
} else {
    Write-Warning 'FileNotFound: Unable to find the LocalizedData file argoncage.strings.psd1.'
}
#region    Classes
enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

#region    Main
#     A simple cli tool that uses state-of-the-art encryption to save secrets.
# .DESCRIPTION
#     Argon2 KDF is widely considered one of the most secure and modern method for deriving cryptographic keys from passwords.
#     It is designed to be memory-hard, making it extremely resistant to GPU/ASIC cracking attacks.
#     The goal is to achieve Military-Grade Encryption without leaving the cli.
# .NOTES
#     Information or caveats about the function e.g. 'This function is not supported in Linux'
# .LINK
#     https://github.com/alainQtec/argoncage
# .EXAMPLE
#     $pm = [ArgonCage]::New()
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class ArgonCage {
    [ValidateNotNullOrEmpty()][Object] $Config
    [ValidateNotNullOrEmpty()][version] $version
    static hidden [ValidateNotNull()][Object] $vault
    static hidden [ValidateNotNull()][PsObject] $Tmp
    Static hidden [ValidateNotNull()][IO.DirectoryInfo] $DataPath = (CryptoBase)::Get_dataPath('ArgonCage', 'Data')
    static [System.Collections.ObjectModel.Collection[PsObject]] $banners = @()
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope = [EncryptionScope]::User
    static hidden [bool]$UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")

    ArgonCage() {
        [ArgonCage]::NewSession($true)
        Push-Stack -class "ArgonCage"; $this.SetConfigs(); [ArgonCage]::Set_variables($this.Config)
        # $this.SyncConfigs()
        $this.PsObject.properties.add([psscriptproperty]::new('IsOffline', [scriptblock]::Create({ return ((Test-Connection github.com -Count 1).status -ne "Success") })))
        [ArgonCage].PsObject.Properties.Add([psscriptproperty]::new('Version', {
                    return $this.SetVersion()
                }, { throw [System.InvalidOperationException]::new("Cannot set Version") }
            )
        )
    }
    static [void] ShowMenu() {
        [ArgonCage]::WriteBanner()
        Write-Output "Vault:" ([ArgonCage]::vault)
        # code for menu goes here ...
    }
    static [void] WriteBanner() {
        if ($null -eq [ArgonCage]::banners -or ([ArgonCage]::banners.Count -eq 0)) {
            [void][ArgonCage]::banners.Add((New-CliArt 'H4sIAAAAAAAAA7VXaXOiQBD9ThU/wlVLjGGNxuBNopZJFmIw3B5RdzUEchiv/P+dwaiAAw6m8mWqeoQ3j9dvulvLzLwOZHEcm3HNyEXbMjPmY6iQJODGAmywkmW24iNFepg2lU8ufb0OheHlKhiMJLAOyybz34Eoi5Z5X00rCn+mDbrJWMIyhSKnqDfGyA5JwrURXdmPy9MkPQ+nxXbDSB8r57J3Kr7MPQRxQ5JQtVQhEvZsJ1vMjIBQUdnR0E1gMOhSHwqUM/vbcCUQhIq+KOzTh2KXpl4feuQM4IuZkeay7hFM/uifpzDcyeT25G6VnnHVhVqEdwPKnfhvX5//8XxrsJxY6gZC7NsxzE1F5CZQzmPc4IbA4+vLliSOfnvD9lBGFIlWa7AUmMjLDisZSfTGucQLqFXLmr2BDgXG64btrwWUnCHV/YIIX6uc7sR//GATwHIDunYeSd+3jwTw9WWLzsiPyenD1rcJ4Kv7M3KGVRfD4Bt1efU5YfGz1sTiDaaWf6GNTqdYfpqQxH13Um60Z9F4W7us9sX8eXPQ2VJ5tHFi/NXQX5qtnEFfw9bVoXjGXaQmYZJKfZTQx/YaaZwKvgw5XxyZ1EMGR/H1ZXvYF9++I4eoALZYPfXus02BYS77FIXjDyMllZPMLiQJz0boMGLLeXiMR6sLp9sKDSFAz5CnQzGGhgDzmVK819ugZ0QKltlYDZHWWsMFgcFB3AfMXXIQfPUl7RzeFZnRof3n3nGtiMynrs1EB1in3uwjRtcHjzu3YLtJt0rfylJL+OXLdtMQi4uZPGD/vcfXBFaGPOgnhZOO64BKZt2gy6eP4ABqCR+OgPlCXtBm3VGhQoPtbmqk7gHzvWut8mu2Ypm5xI39hSQB3dvZcwOc5fW/EQkKVgNh6kkW306c/5QkVYlyo8plDmqxgQPoGQ+YvvauE8z9t+HLWkG1YVplu0m45OGSS4mv89FdnNJnWom5YvV8tlcjCV3rnVLCzUj4FDhTrgrcvMsKvDFfSRpvsGC5ncC3KRsCLlm41LZhgyRs4HbuIkbp7+Z7Y4cuTsZvZyAdLUYa/wf3K1M5Uw8AAA=='))
        }
        [ArgonCage]::banners[(Get-Random (0..([ArgonCage]::banners.Count - 1)))].Tostring() | Write-Host -f Magenta
        Write-AnimatedHost '[!] https://github.com/alainQtec/argoncage' [ConsoleColor]::Red
    }
    [void] RegisterUser() {
        # TODO: FINSISH this .. I'm tir3d!
        # store the encrypted(user+ hashedPassword) s in a file. ie:
        # user1:HashedPassword1 -encrypt-> 3dsf#s3s#$3!@dd*34d@dssxb
        # user2:HashedPassword2 -encrypt-> dds#$3!@dssd*sf#s343dfdsf
    }
    [bool] Login([string]$UserName, [securestring]$Password) {
        # This method authenticates the user by verifying the supplied username and password.
        # Todo: replace this with a working authentication mechanism.
        [ValidateNotNullOrEmpty()][string]$username = $username
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        $valid_username = "example_user"
        $valid_password = "example_password"
        if ($username -eq $valid_username -and $password -eq $valid_password) {
            return $true
        } else {
            return $false
        }
    }
    static [void] LoadUsers([string]$UserFile) {
        [ValidateNotNullOrEmpty()][string]$UserFile = $UserFile
        # Reads the user file and loads the usernames and hashed passwords into a hashtable.
        if (Test-Path $UserFile) {
            $lines = Get-Content $UserFile
            foreach ($line in $lines) {
                $parts = $line.Split(":")
                $username = $parts[0]
                $password = $parts[1]
                [ArgonCage]::Tmp.vars.Users[$username] = $password
            }
        }
    }
    static [void] RegisterUser([string]$username, [securestring]$password) {
        [ValidateNotNullOrEmpty()][string]$username = $username
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        # Registers a new user with the specified username and password.
        # Hashes the password and stores it in the user file.
        $UserFile = ''
        $hashedPassword = $password | ConvertFrom-SecureString
        $line = "{0}:{1}" -f $username, $hashedPassword
        Add-Content $UserFile $line
        [ArgonCage]::Tmp.vars.Users[$username] = $hashedPassword
    }
    [void] EditConfig() {
        if ($null -eq $this.Config) { $this.SetConfigs() };
        $og_EncryptionScope = [ArgonCage]::EncryptionScope;
        try {
            $this::EncryptionScope = [EncryptionScope]::Machine
            Push-Stack -class "ArgonCage"; [void]$this.Config.Edit([ArgonCage]::Tmp)
        } finally {
            $this::EncryptionScope = $og_EncryptionScope;
        }
    }
    [void] SyncConfigs() {
        if ($null -eq $this.Config) { $this.SetConfigs() };
        if (!$this.Config.remote.IsAbsoluteUri) { $this.SetConfigs() }
        if (!$this.Config.remote.IsAbsoluteUri) { throw [System.InvalidOperationException]::new('Could not resolve remote uri') }
        $og_EncryptionScope = [ArgonCage]::EncryptionScope; try {
            $this::EncryptionScope = [EncryptionScope]::Machine
            # if ($this.Config.Remote.LastWriteTime -gt $this.Config.LastWriteTime) {
            # }
            # Imports remote configs into current ones, then uploads the updated version to github gist
            # Compare REMOTE's lastWritetime with [IO.File]::GetLastWriteTime($this.File)
            $this.Config.Import($this.Config.Remote, [ArgonCage]::Tmp)
            $this.Config.Save([ArgonCage]::Tmp);
        } finally {
            $this::EncryptionScope = $og_EncryptionScope;
        }
        if ($?) { Write-Host "[ArgonCage] Config Syncing" -NoNewline -f Blue; Write-Host " Completed." -f Green }
    }
    [void] ImportConfigs() {
        [void]$this.Config.Import($this.Config.File, [ArgonCage]::Tmp)
    }
    [void] ImportConfigs([uri]$raw_uri) {
        # $e = "GIST_CUD = {0}" -f ((AesGCM)::Decrypt("AfXkvWiCce7hAIvWyGeU4TNQyD6XLV8kFYyk87X4zqqhyzb7DNuWcj2lHb+2mRFdN/1aGUHEv601M56Iwo/SKhkWLus=", $(Read-Host -Prompt "pass" -AsSecureString), 1)); $e >> ./.env
        $this.Config.Import($raw_uri, [ArgonCage]::Tmp)
    }
    [bool] DeleteConfigs() {
        return [bool]$(
            try {
                $configFiles = (Get-GithubTokenFile | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ([ArgonCage]::DataPath | Get-ChildItem -File -Recurse).FullName
                $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose });
                $true
            } catch { $false }
        )
    }
    [void] SetConfigs() { $this.SetConfigs([string]::Empty, $false) }
    [void] SetConfigs([string]$ConfigFile) { $this.SetConfigs($ConfigFile, $true) }
    [void] SetConfigs([bool]$throwOnFailure) { $this.SetConfigs([string]::Empty, $throwOnFailure) }
    [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
        if ($null -eq $this.Config) { $this.Config = [ArgonCage]::Get_default_Config() | New-RecordMap }
        if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = (CryptoBase)::GetUnResolvedPath($ConfigFile) }
        if (![IO.File]::Exists($this.Config.File)) {
            if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
                throw [System.IO.FileNotFoundException]::new("Unable to find file '$($this.Config.File)'")
            }; [void](New-Item -ItemType File -Path $this.Config.File)
        }
        if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($this.Config.File).Trim())) {
            $og_EncryptionScope = [ArgonCage]::EncryptionScope; try {
                $this::EncryptionScope = [EncryptionScope]::Machine
                $this.Config.Save([ArgonCage]::Tmp);
            } finally {
                $this::EncryptionScope = $og_EncryptionScope;
            }
        }
    }
    static [PsObject] NewSession() {
        return [ArgonCage]::NewSession($false)
    }
    static [PsObject] NewSession([bool]$Force) {
        $notEmpty = $null -ne [ArgonCage]::Tmp
        if (($notEmpty -and $Force) -or !$notEmpty) {
            [ArgonCage]::Tmp = [PSCustomObject]@{
                vars  = New-RecordMap
                Paths = [System.Collections.Generic.List[string]]::new()
            }
        }
        return [ArgonCage]::Tmp
    }
    # Method to validate the password: This Just checks if its a good enough password
    static [bool] ValidatePassword([SecureString]$password) {
        $IsValid = $false; $minLength = 8; $handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        try {
            Add-Type -AssemblyName System.Runtime.InteropServices
            Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $((xconvert)::ToString($Password));
            Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
            # Set the required character types
            $requiredCharTypes = [System.Text.RegularExpressions.Regex]::Matches("$Passw0rd", "[A-Za-z]|[0-9]|[^A-Za-z0-9]") | Select-Object -ExpandProperty Value
            # Check if the password meets the minimum length requirement and includes at least one of each required character type
            $IsValid = ($Passw0rd.Length -ge $minLength -and $requiredCharTypes.Count -ge 3)
        } catch {
            throw $_
        } finally {
            Remove-Variable Passw0rd -Force -ErrorAction SilentlyContinue
            # Zero out the memory used by the variable.
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($handle);
            Remove-Variable handle -Force -ErrorAction SilentlyContinue
        }
        return $IsValid
    }
    # Method to save the password token (like a custom hash thing) to sql database
    static [void] SavePasswordToken([string]$username, [SecureString]$password, [string]$connectionString) {
        $passw0rdHash = [string]::Empty
        # Hash the password using the SHA-3 algorithm
        if ('System.Security.Cryptography.SHA3Managed' -is 'type') {
            $passw0rdHash = (New-Object System.Security.Cryptography.SHA3Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes((xconvert)::Tostring($password)))
        } else {
            # Hash the password using an online SHA-3 hash generator
            $passw0rdHash = ((Invoke-WebRequest -Method Post -Uri "https://passwordsgenerator.net/sha3-hash-generator/" -Body "text=$((xconvert)::Tostring($password))").Content | ConvertFrom-Json).sha3
        }
        # Connect to the database
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        # Create a SQL command to update the password hash in the database
        $command = New-Object System.Data.SqlClient.SqlCommand("UPDATE Users SET PasswordHash = @PasswordHash WHERE Username = @Username", $connection)
        $command.Parameters.AddWithValue("@Username", $username)
        $command.Parameters.AddWithValue("@PasswordHash", $passw0rdHash)

        # Execute the command
        $command.ExecuteNonQuery()

        # Close the connection
        $connection.Close()
    }
    # Method to retieve the passwordHash from sql database
    # Create an instance of the PasswordManager class
    # $manager = [ArgonCage]::new("username", "")
    # Load the password hash from the database
    # $manager.LoadPasswordHash("username", "Server=localhost;Database=MyDatabase;Trusted_Connection=True;")
    static [string] LoadPasswordToken([string]$username, [string]$connectionString) {
        # Connect to the database
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        # Create a SQL command to retrieve the password hash from the database
        $command = New-Object System.Data.SqlClient.SqlCommand("SELECT PasswordHash FROM Users WHERE Username = @Username", $connection)
        $command.Parameters.AddWithValue("@Username", $username)

        # Execute the command and retrieve the password hash
        $reader = $command.ExecuteReader()
        $reader.Read()
        $Passw0rdHash = $reader["PasswordHash"]

        # Close the connection
        $connection.Close()
        return $Passw0rdHash
    }
    static [securestring] ResolveSecret([securestring]$secret, [string]$cacheTag) {
        $cache = [ArgonCage]::Read_Cache().Where({ $_.Tag -eq $cacheTag })
        if ($null -eq $cache) {
            throw "Secret not found in cache. Please make sure creds caching is enabled."
        }
        $TokenSTR = $cache.Token
        return (HKDF2)::Resolve($secret, $TokenSTR)
    }
    static [bool] CheckCredCache([string]$TagName) {
        return [ArgonCage]::Tmp.vars.CachedCreds.Tag -contains $TagName
    }
    static [ConsoleKeyInfo] ReadInput() {
        $originalTreatControlCAsInput = [System.Console]::TreatControlCAsInput
        if (![console]::KeyAvailable) { [System.Console]::TreatControlCAsInput = $true }
        $key = [ConsoleKeyInfo]::new(' ', [System.ConsoleKey]::None, $false, $false, $false)
        Write-Host "Press a key :)" -f Green
        $key = [System.Console]::ReadKey($true); $key | Save-InputKeys
        # $IsCTRLQ = ($key.modifiers -band [consolemodifiers]::Control) -and ($key.key -eq 'q')
        Write-Host $("Pressed {0}{1}" -f $(if ($key.Modifiers -ne 'None') { $key.Modifiers.ToString() + '^' }), $key.Key) -f Green
        [System.Console]::TreatControlCAsInput = $originalTreatControlCAsInput
        return $key
    }
    static [void] Set_variables() {
        $curr_Config = $(if ($null -eq [ArgonCage]::Tmp.vars.SessionConfig) { [ArgonCage]::Get_default_Config() | New-RecordMap } else { [ArgonCage]::Tmp.vars.SessionConfig })
        [ArgonCage]::Set_variables($curr_Config)
    }
    static [void] Set_variables([Object]$Config) {
        # Sets default variables and stores them in $this::Tmp.vars
        # Makes it way easier to clean & manage variables without worying about scopes and not dealing with global variables.
        [ValidateNotNullOrEmpty()][Object]$Config = $Config
        [ArgonCage]::NewSession()
        [ArgonCage]::Tmp.vars.Set(@{
                Users         = @{}
                Host_Os       = (CryptoBase)::Get_Host_Os()
                ExitCode      = 0
                UseWhatIf     = [bool]$((Get-Variable WhatIfPreference -ValueOnly) -eq $true)
                SessionId     = [string]::Empty
                UseVerbose    = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
                OfflineMode   = !((Retry-Command { (CheckConnection -host "github.com" -msg "Check if offline").Output }).Output)
                CachedCreds   = $null
                SessionConfig = $Config
                OgWindowTitle = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
                Finish_reason = [string]::Empty
            }
        )
        if ($Config.SaveVaultCache) {
            [ArgonCage]::Tmp.vars.Set('CachedCreds', [ArgonCage]::Get_CachedCreds($Config))
        }
    }
    static hidden [hashtable] Get_default_Config() {
        return [ArgonCage]::Get_default_Config("Config.enc")
    }
    static hidden [hashtable] Get_default_Config([string]$Config_FileName) {
        Write-Host "[ArgonCage] Get default Config ..." -f Blue
        $default_Config = @{
            File            = (CryptoBase)::GetUnResolvedPath([IO.Path]::Combine([ArgonCage]::DataPath, $Config_FileName))
            FileName        = $Config_FileName # Config is stored locally and all it's contents are always encrypted.
            Remote          = [string]::Empty
            GistUri         = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
            ERROR_NAMES     = ('No_Internet', 'Failed_HttpRequest', 'Empty_API_key') # If exit reason is in one of these, the bot will appologise and close.
            NoApiKeyHelp    = 'Get your OpenAI API key here: https://platform.openai.com/account/api-keys'
            ThrowNoApiKey   = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
            UsageHelp       = "Usage:`nHere's an example of how to use this Password manager:`n   `$pm = [ArgonCage]::new()`n   `$pm.login()`n`nAnd make sure you have Internet."
            SaveVaultCache  = $true
            SaveEditorLogs  = $true
            VaultFileName   = "secret_Info" # Should also match the FileName of the remote gist.
            CachedCredsPath = [IO.Path]::Combine([ArgonCage]::DataPath, "SessionHashes.enc")
            LastWriteTime   = [datetime]::Now
        }
        try {
            Write-Host "     Set Remote uri for config ..." -f Blue; Push-Stack -class "ArgonCage"
            $l = [uri]::New($default_Config.GistUri) | New-GistFile; Set-GitHubUsername $l.UserName
            if ($?) {
                $default_Config.Remote = [uri]::new((Get-GistInfo -User $l.Owner -Id $l.Id).files."$Config_FileName".raw_url)
            }
            Write-Host "     Set Remote uri " -f Blue -NoNewline; Write-Host "Completed." -f Green
        } catch {
            Write-Host "     Set Remote uri Failed!" -f Red
            Write-Host "            $($_.Exception.PsObject.TypeNames[0]) $($_.Exception.Message)" -f Red
        }
        return $default_Config
    }
    static hidden [Object] Get_SessionConfig() {
        [ArgonCage]::NewSession()
        if ($null -eq [ArgonCage]::Tmp.vars.SessionId) {
            Write-Verbose "Creating new session ..."; [ArgonCage]::Set_variables()
        }
        $sc = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNullOrEmpty()][Object]$sc = $sc
        return $sc
    }
    static hidden [void] Get_CachedCreds($Config) {
        #Note: $Config should be a valid [RecordMap] object
        if ($null -eq [ArgonCage]::vault) { [ArgonCage]::vault = [ArgonCage]::Create_Vault($Config.VaultFileName) }
        if ([IO.File]::Exists($Config.CachedCredsPath)) {
            [ArgonCage]::vault.Cache.Read((xconvert)::ToSecurestring($Config.CachedCredsPath))
        } else {
            [ArgonCage]::Read_Cache()
        }
    }
    static [Object] Create_Vault([string]$Name) {
        if ([string]::IsNullOrWhiteSpace($Name)) { throw [System.ArgumentException]::new($Name) }
        [Object]$result = New-Object System.Object; ('Name', 'Remote', 'Cache').ForEach({ Add-Member -InputObject $result -Type NoteProperty -Name $_ -Value $null })
        # [ValidateNotNullOrEmpty()][string]$Name
        # [ValidateNotNullOrEmpty()][uri]$Remote
        # hidden [VaultCache]$Cache
        $result.Name = $Name
        if ([string]::IsNullOrWhiteSpace([ArgonCage]::DataPath)) {
            [ArgonCage]::DataPath = [IO.Path]::Combine((CryptoBase)::Get_dataPath('ArgonCage', 'Data'), 'secrets')
        }
        $result.PsObject.Properties.Add([psscriptproperty]::new('File', {
                    return [IO.FileInfo]::new([IO.Path]::Combine([ArgonCage]::DataPath, $result.Name))
                }, {
                    param($value)
                    if ($value -is [IO.FileInfo]) {
                        [ArgonCage]::DataPath = $value.Directory.FullName
                        $this.Name = $value.Name
                    } else {
                        throw "Invalid value assigned to File property"
                    }
                }
            )
        )
        $result.PsObject.Properties.Add([psscriptproperty]::new('Size', {
                    if ([IO.File]::Exists($result.File.FullName)) {
                        $this.File = Get-Item $this.File.FullName
                        return $this.File.Length
                    }
                    return 0
                }, { throw "Cannot set Size property" }
            )
        )
        $result.PsObject.Properties.Add([psscriptproperty]::new('Cache', {
                    if ($null -eq [ArgonCage].Cache) {
                        [ArgonCage] | Add-Member -Name Cache -Force -MemberType ScriptProperty -Value { return [ArgonCage]::Create_VaultCache() }.GetNewClosure() -SecondValue { throw [System.InvalidOperationException]::new("Cannot change Cache") }
                    }
                    return [ArgonCage].Cache
                }, { throw [System.InvalidOperationException]::new("Cannot set Cache") }
            )
        )
        if ($null -eq [ArgonCage]::Tmp.vars) { [ArgonCage]::Set_variables() }else {
            $result.Remote = [ArgonCage]::GetVaultRawUri($result.Name, [ArgonCage]::Tmp.vars.sessionConfig.Remote)
        }
        return $result
    }
    static [Object] Create_Vault([string]$FilePath, [uri]$RemoteUri) {
        [ValidateNotNullOrEmpty()][string]$FileName = $FilePath
        [ValidateNotNullOrEmpty()][uri]$RemoteUri = $RemoteUri
        $__FilePath = (CryptoBase)::GetUnResolvedPath($FilePath);
        $result = [ArgonCage]::Create_Vault([IO.Path]::GetFileName($__FilePath))
        $result.File = $(if ([IO.File]::Exists($__FilePath)) {
                Write-Host "    Found secrets file '$([IO.Path]::GetFileName($__FilePath))'" -f Green
                Get-Item $__FilePath
            } else {
                $result.File
            }
        )
        $result.Name = [IO.Path]::GetFileName($result.File.FullName); $result.Remote = $RemoteUri
        if (![IO.File]::Exists($result.File.FullName)) {
            $result.File = [ArgonCage]::FetchSecrets($result.Remote, $result.File.FullName)
        }
        return $result
    }
    static [Object] Create_VaultCache() {
        $cache = New-Object System.Object;
        $cache.PsObject.Properties.Add([psscriptmethod]::new('Read', {
                    [OutputType([array])]
                    param(
                        [Parameter(Mandatory = $true, Position = 0)]
                        [securestring]$CachedCredsPath
                    )
                    $FilePath = ''; $credspath = ''; $sc = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNullOrEmpty()][Object]$sc = $sc
                    Set-Variable -Name "FilePath" -Visibility Private -Option Private -Value ((xconvert)::Tostring($CachedCredsPath))
                    if ([string]::IsNullOrWhiteSpace($FilePath)) { throw "InvalidArgument: `$FilePath" }
                    Set-Variable -Name "credspath" -Visibility Private -Option Private -Value ([IO.Path]::GetDirectoryName($FilePath))
                    if ([string]::IsNullOrWhiteSpace($credspath)) { throw "InvalidArgument: `$credspath" }
                    if (!(Test-Path -Path $credspath -PathType Container -ErrorAction Ignore)) { (cryptobase)::Create_Dir($credspath) }
                    $_p = (xconvert)::ToSecurestring((CryptoBase)::GetUniqueMachineId())
                    $ca = @(); if (![IO.File]::Exists($FilePath)) {
                        if ($sc.SaveVaultCache) {
                            New-Item -Path $FilePath -ItemType File -Force -ErrorAction Ignore | Out-Null
                            Write-Debug "Saving default cache: rwsu"
                            $ca += [ArgonCage]::Update_Cache((whoami), $_p, 'rwsu', $true)
                        } else {
                            Write-Host "[ArgonCage] FileNotFoundException: No such file.`n$(' '*12)File name: $FilePath" -f Yellow
                        }
                        return $ca
                    }
                    $tc = [IO.FILE]::ReadAllText($FilePath); if ([string]::IsNullOrWhiteSpace($tc.Trim())) { return $ca }
                    $da = [byte[]](AesGCM)::Decrypt((Base85)::Decode($tc), $_p, (AesGCM)::GetDerivedBytes($_p), $null, 'Gzip', 1)
                    $([System.Text.Encoding]::UTF8.GetString($da) | ConvertFrom-Json).ForEach({ $ca += New-RecordMap $((xconvert)::ToHashTable($_)) })
                    return $ca
                }
            )
        )
        $cache.PsObject.Properties.Add([psscriptmethod]::new('Update', {
                    [OutputType([array])]
                    param(
                        [Parameter(Mandatory = $true, Position = 0)]
                        [pscredential]$Credential,

                        [Parameter(Mandatory = $true, Position = 1)]
                        [string]$TagName,

                        [Parameter(Mandatory = $true, Position = 2)]
                        [bool]$Force
                    )
                    $sessionConfig = [ArgonCage]::Tmp.vars.SessionConfig
                    [ValidateNotNullOrEmpty()][Object]$sessionConfig = $sessionConfig
                    $c_array = @()
                    $c_array += @{ $TagName = $Credential }
                    $results = @(); $c_array.keys | ForEach-Object {
                        $_TagName = $_; $_Credential = $c_array.$_
                        if ([string]::IsNullOrWhiteSpace($_TagName)) { throw "InvalidArgument : TagName" }
                        [ValidateNotNullOrEmpty()][pscredential]$_Credential = $_Credential
                        $results += $this.Read()
                        $IsNewTag = $_TagName -notin $results.Tag
                        if ($IsNewTag) {
                            if (!$Force) {
                                Throw [System.InvalidOperationException]::new("CACHE_NOT_FOUND! Please make sure the tag already exist, or use -Force to auto add.")
                            }
                        }
                        Write-Verbose "$(if ($IsNewTag) { "Adding new" } else { "Updating" }) tag: '$_TagName' ..."
                        if ($results.Count -eq 0 -or $IsNewTag) {
                            $results += New-RecordMap @{
                                User  = $_Credential.UserName
                                Tag   = $_TagName
                                Token = (HKDF2)::GetToken($_Credential.Password)
                            }
                        } else {
                            $results.Where({ $_.Tag -eq $_TagName }).Set('Token', (HKDF2)::GetToken($_Credential.Password))
                        }
                        if ($sessionConfig.SaveVaultCache) {
                            $_p = (xconvert)::ToSecurestring((CryptoBase)::GetUniqueMachineId())
                            Set-Content -Value $((Base85)::Encode((AesGCM)::Encrypt(
                                        [System.Text.Encoding]::UTF8.GetBytes([string]($results | ConvertTo-Json)),
                                        $_p, (AesGCM)::GetDerivedBytes($_p), $null, 'Gzip', 1
                                    )
                                )
                            ) -Path ($sessionConfig.CachedCredsPath) -Encoding utf8BOM
                        }
                    }
                    return $results
                }
            )
        )
        $cache.PsObject.Properties.Add([psscriptmethod]::new('Clear', {
                    [ArgonCage] | Add-Member -Name Cache -Force -MemberType ScriptProperty -Value { $null }.GetNewClosure()
                    [ArgonCage]::Tmp.vars.SessionConfig.CachedCredsPath | Remove-Item -Force -ErrorAction Ignore
                }
            )
        )
        $cache.PsObject.Properties.Add([psscriptmethod]::new('ToString', {
                    return [ArgonCage]::Get_SessionConfig().CachedCredsPath
                }
            )
        )
        return $cache
    }
    static [void] Read_Cache() {
        [ArgonCage]::vault.Cache.Read((xconvert)::ToSecurestring([ArgonCage]::Get_SessionConfig().CachedCredsPath))
    }
    static [array] Update_Cache([string]$userName, [securestring]$password, [string]$TagName) {
        return [ArgonCage]::Update_Cache($userName, $password, $TagName)
    }
    static [array] Update_Cache([string]$userName, [securestring]$password, [string]$TagName, [bool]$Force) {
        return [ArgonCage]::vault.Cache.Update($userName, $password, $TagName, $Force)
    }
    [void] SaveSessionKey([string]$Name, [SecureString]$Value) {
        [ValidateNotNullOrEmpty()][string]$Name = $Name
        if ($null -eq $this::Tmp.vars.SessionKeys) {
            $this::Tmp.vars.Set('SessionKeys', (New-RecordMap))
            $this::Tmp.vars.SessionKeys.Add(@{ $Name = $Value })
        } else {
            $this::Tmp.vars.SessionKeys.Set(@{ $Name = $Value })
        }
    }
    [SecureString] GetSessionKey([string]$Name) {
        return $this.GetSessionKey($Name, [PSCustomObject]@{
                caller = Show-Stack
                prompt = "Paste/write a Password"
            }
        )
    }
    [SecureString] GetSessionKey([string]$Name, [psobject]$Options) {
        [ValidateNotNullOrEmpty()][string]$Name = $Name
        [ValidateNotNullOrEmpty()][psobject]$Options = $Options
        if ($null -eq $this::Tmp.vars.SessionKeys) {
            $scope = $this::Get_Enc_Scope($Options.caller)
            [ValidateNotNullOrEmpty()][EncryptionScope]$scope = $scope
            $this.SaveSessionKey($Name, $(if ($scope -eq "User") {
                        Write-Verbose "Save Sessionkey $Name ..."
                        (CryptoBase)::GetPassword(("{0} {1}" -f $Options.caller, $Options.Prompt))
                    } else {
                        (xconvert)::ToSecurestring((CryptoBase)::GetUniqueMachineId())
                    }
                )
            )
        }
        return $this::Tmp.vars.SessionKeys.$Name
    }
    static hidden [EncryptionScope] Get_Enc_Scope([string]$caller) {
        $_scope = [scriptblock]::Create("return $($caller)::EncryptionScope").Invoke();
        if ([string]::IsNullOrWhiteSpace("$_scope")) {
            return [ArgonCage]::Tmp::EncryptionScope
        }
        return $_scope
    }
    [void] ClearSession() {
        $this::Tmp.vars = New-RecordMap
        $this::Tmp.Paths | ForEach-Object { Remove-Item "$_" -ErrorAction SilentlyContinue };
        $this::Tmp.Paths = [System.Collections.Generic.List[string]]::new()
    }
    [PsObject] GetSecrets() {
        if (![IO.File]::Exists($this::vault.File.FullName)) {
            if ([string]::IsNullOrWhiteSpace($this.Remote.AbsoluteUri)) { $this::vault.SetVaultUri() }
            $this.File = [ArgonCage]::FetchSecrets($this::vault.Remote, $this::vault.File.FullName)
        }
        return $this.GetSecrets($this::vault.File)
    }
    [PsObject] GetSecrets([String]$Path) {
        # $IsCached = [ArgonCage]::checkCredCache($Path)
        $password = (AesGCM)::GetPassword("[ArgonCage] password to read secrets")
        return $this.GetSecrets($Path, $password, [string]::Empty)
    }
    [PsObject] GetSecrets([String]$Path, [securestring]$password, [string]$Compression) {
        [ValidateNotNullOrEmpty()][string]$Path = (CryptoBase)::GetResolvedPath($Path)
        if (![IO.File]::Exists($Path)) { throw [System.IO.FileNotFoundException]::new("File '$path' does not exist") }
        if (![string]::IsNullOrWhiteSpace($Compression)) { (CryptoBase)::ValidateCompression($Compression) }
        $da = [byte[]](AesGCM)::Decrypt((Base85)::Decode([IO.FILE]::ReadAllText($Path)), $Password, (AesGCM)::GetDerivedBytes($Password), $null, $Compression, 1)
        return $(ConvertFrom-Csv ([System.Text.Encoding]::UTF8.GetString($da).Split('" "'))) | Select-Object -Property @{ l = 'link'; e = { if ($_.link.Contains('"')) { $_.link.replace('"', '') } else { $_.link } } }, 'user', 'pass'
    }
    [void] EditSecrets() {
        if (![IO.File]::Exists($this::vault.File.FullName)) {
            if ([string]::IsNullOrWhiteSpace($this::vault.Remote.AbsoluteUri)) { $this::vault.SetVaultUri() }
            $this.File = [ArgonCage]::FetchSecrets($this::vault.Remote, $this::vault.File.FullName)
        }
        $this.EditSecrets($this::vault.File.FullName)
    }
    [void] EditSecrets([String]$Path) {
        $private:secrets = $null; $fswatcher = $null; $process = $null; $outFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        try {
            Push-Stack ([ArgonCage]); (NetworkManager)::BlockAllOutbound()
            if ([ArgonCage]::UseVerbose) { "[+] Edit secrets started .." | Write-Host -f Magenta }
            $this.GetSecrets($Path) | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = New-FileSystemWatcher -File $outFile.FullName -OnComplete ([scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
            if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
            $private:secrets = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
        } finally {
            (NetworkManager)::UnblockAllOutbound()
            if ($fswatcher) { $fswatcher.Dispose() }
            if ($process) {
                "[+] Neovim process {0} successfully" -f $(if (!$process.HasExited) {
                        $process.Kill($true)
                        "closed"
                    } else {
                        "exited"
                    }
                ) | Write-Host -f Green
                $process.Close()
                $process.Dispose()
            }
            Remove-Item $outFile.FullName -Force
            if ([ArgonCage]::UseVerbose) { "[+] FileMonitor Log saved in variable: `$$(Get-FMLogvariableName)" | Write-Host -f Green }
            if ($null -ne $secrets) { $this.UpdateSecrets($secrets, $Path) }
            if ([ArgonCage]::UseVerbosee) { "[+] Edit secrets completed." | Write-Host -f Magenta }
        }
    }
    [IO.FileInfo] FetchSecrets() {
        if ([string]::IsNullOrWhiteSpace($this::vault.Remote.AbsoluteUri)) { $this::vault.SetVaultUri() }
        return $this::FetchSecrets($this::vault.Remote, $this::vault.File.FullName)
    }
    static [IO.FileInfo] FetchSecrets([uri]$remote, [string]$OutFile) {
        if ([string]::IsNullOrWhiteSpace($remote.AbsoluteUri)) { throw [System.ArgumentException]::new("Invalid Argument: remote") }
        if ([ArgonCage]::UseVerbose) { "[+] Fetching secrets from gist ..." | Write-Host -f Magenta }
        Push-Stack ([ArgonCage]); (NetworkManager)::DownloadOptions.ShowProgress = $true
        $og_PbLength = (NetworkManager)::DownloadOptions.ProgressBarLength
        $og_pbMsg = (NetworkManager)::DownloadOptions.ProgressMessage
        $Progress_Msg = "[+] Downloading secrets to {0}" -f $OutFile
        (NetworkManager)::DownloadOptions.ProgressBarLength = $Progress_Msg.Length - 7
        (NetworkManager)::DownloadOptions.ProgressMessage = $Progress_Msg
        $resfile = (NetworkManager)::DownloadFile($remote, $OutFile)
        (NetworkManager)::DownloadOptions.ProgressBarLength = $og_PbLength
        (NetworkManager)::DownloadOptions.ProgressMessage = $og_pbMsg
        [Console]::Write([Environment]::NewLine)
        return $resfile
    }
    hidden [void] SetVaultUri() {
        if ([string]::IsNullOrWhiteSpace($this::vault.Remote.AbsoluteUri)) {
            $this::vault.Remote = $this.GetVaultRawUri()
        } else {
            $this::vault.Remote = $this.GetVaultRawUri($this::vault.Name, $this::vault.Remote)
        }
    }
    static [uri] GetVaultRawUri() {
        [ArgonCage]::NewSession(); if ([ArgonCage]::Tmp.vars.count -eq 0) { [ArgonCage]::Set_variables() }
        $curr_Config = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNull()][Object]$curr_Config = $curr_Config
        return [ArgonCage]::GetVaultRawUri([ArgonCage]::vault.Name, $curr_Config.Remote)
    }
    static [uri] GetVaultRawUri([string]$vaultName, [uri]$remote) {
        [ValidateNotNullOrEmpty()][uri]$remote = $remote
        [ValidateNotNullOrEmpty()][string]$vaultName = $vaultName
        $rem_gist = $null; $raw_uri = [string]::Empty -as [uri]
        if ([string]::IsNullOrWhiteSpace($remote)) {
            throw [System.ArgumentNullException]::new("remote", "Failed to get remote uri. Argument IsNullorEmpty.")
        }
        try {
            $rem_gist = $remote | Get-GistInfo
        } catch {
            Write-Host "[-] Error: $_" -f Red
        } finally {
            if ($null -ne $rem_gist) {
                $raw_uri = [uri]::new($rem_gist.files.$vaultName.raw_url)
            }
        }
        return $raw_uri
    }
    [void] UpdateSecrets([psObject]$InputObject, [string]$outFile) {
        $password = (AesGCM)::GetPassword("[ArgonCage] password to save secrets")
        $this.UpdateSecrets($InputObject, (CryptoBase)::GetUnResolvedPath($outFile), $password, '')
    }
    [void] UpdateSecrets([psObject]$InputObject, [string]$outFile, [securestring]$Password, [string]$Compression) {
        Push-Stack ([ArgonCage]); if ([ArgonCage]::UseVerbose) { "[+] Updating secrets .." | Write-Host -f Green }
        if (![string]::IsNullOrWhiteSpace($Compression)) { (CryptoBase)::ValidateCompression($Compression) }
        (Base85)::Encode((AesGCM)::Encrypt([System.Text.Encoding]::UTF8.GetBytes([string]($InputObject | ConvertTo-Csv)), $Password, (AesGCM)::GetDerivedBytes($Password), $null, $Compression, 1)) | Out-File $outFile -Encoding utf8BOM
    }
    [version] SetVersion() {
        $this.version = [version]::New($script:localizedData.ModuleVersion)
        return $this.version
    }
}

#endregion Main

#endregion Classes
$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $Module : $_"
        }
    }
}
# Dot source the files
foreach ($Import in ($Public, $Private)) {
    Try {
        if ([string]::IsNullOrWhiteSpace($Import.fullname)) { continue }
        . "$($Import.fullname)"
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
if ([IO.path]::GetExtension($MyInvocation.MyCommand.Path) -eq '.psm1') {
    $Param = @{
        Function = $Public.BaseName
        Variable = '*'
        Cmdlet   = '*'
        Alias    = '*'
    }
    Export-ModuleMember @Param -Verbose
}