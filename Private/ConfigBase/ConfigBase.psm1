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
    [void] Import([uri]$raw_uri) {
        try {
            Push-Stack -class "ArgonCage"; $pass = $null;
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([ArgonCage]::Tmp.GetSessionKey('configrw', [PSCustomObject]@{
                        caller = Show-Stack
                        prompt = "Paste/write a Password to decrypt configs"
                    }
                )
            )
            $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
            $this.Set([hashtable[]]$_ob.Properties.Name.ForEach({ @{ $_ = $_ob.$_ } }))
        } catch {
            throw $_
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
    }
    [void] Import([String]$FilePath) {
        Write-Host "$(Show-Stack) Import records: $FilePath ..." -f Green
        $this.Set([RecordMap]::Read($FilePath))
        Write-Host "$(Show-Stack) Import records Complete" -f Green
    }
    [void] Upload() {
        if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [System.ArgumentException]::new('remote') }
        # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
        # (GitHub)::UpdateGist($gisturi, $content)
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
            if (!$this.psObject.Properties.Name.Contains($key)) {
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
    static [hashtable[]] Read([string]$FilePath) {
        Push-Stack -class "ArgonCage"; $pass = $null; $cfg = $null; $FilePath = (AesGCM)::GetResolvedPath($FilePath);
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
        Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([ArgonCage]::Tmp.GetSessionKey('configrw', [PSCustomObject]@{
                    caller = Show-Stack
                    prompt = "Paste/write a Password to decrypt configs"
                }
            )
        )
        $txt = [IO.File]::ReadAllText($FilePath)
        $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($txt), $pass)))
        $cfg = [hashtable[]]$_ob.PsObject.Properties.Name.Where({ $_ -notin ('Count', 'Properties', 'IsSynchronized') }).ForEach({ @{ $_ = $_ob.$_ } })
        return $cfg
    }
    [hashtable[]] Edit() {
        $result = $this.Edit($this.File)
        $this.Set($result); $this.Save()
        return $result
    }
    [hashtable[]] Edit([string]$FilePath) {
        $result = @(); $private:config_ob = $null; $fswatcher = $null; $process = $null;
        $FilePath = (AesGCM)::GetResolvedPath($FilePath);
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
        $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
        try {
            (NetworkManager)::BlockAllOutbound()
            if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -f Magenta }
            $parsed_content = [RecordMap]::Read("$FilePath");
            [ValidateNotNullOrEmpty()][hashtable[]]$parsed_content = $parsed_content
            $parsed_content | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = (FileMonitor)::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
            if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
            $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
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
            Set-Variable -Name ((FileMonitor)::LogvariableName) -Scope Global -Value ((FileMonitor)::GetLogSummary()) | Out-Null
            if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$((FileMonitor)::LogvariableName)" | Write-Host -f Magenta }
            if ($null -ne $config_ob) { $result = $config_ob.ForEach({ (xconvert)::ToHashTable($_) }) }
            if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -f Magenta }
        }
        return $result
    }
    [void] Save() {
        try {
            $cllr = Show-Stack; [ValidateNotNullOrEmpty()][string]$cllr = $cllr
            $pass = $null; Write-Host "$cllr Saving records to file: $($this.File) ..." -f Blue
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([ArgonCage]::Tmp.GetSessionKey('configrw', [PSCustomObject]@{
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

function New-RecordMap {
    [CmdletBinding()]
    [OutputType([RecordMap])]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [hashtable[]]$hashtable
    )
    end {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('hashtable')) {
            if ($null -ne $hashtable) {
                return [RecordMap]::New($hashtable)
            }
        }
        return [RecordMap]::New()
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")