class FileMonitor {
    static [bool] $FileClosed
    static [bool] $FileLocked
    static [System.ConsoleKeyInfo[]] $Keys
    static [ValidateNotNull()][IO.FileInfo] $FileTowatch
    static [ValidateNotNull()][string] $LogvariableName
    FileMonitor() {
        $noFileToWatch = [string]::IsNullOrWhiteSpace($this::FileTowatch)
        [FileMonitor]::FileClosed = $noFileToWatch
        if (!$noFileToWatch) { $this::FileLocked = $this::IsFileLocked($this::FileTowatch.FullName) } else { $this::FileLocked = $false }
        if ($null -eq $this::Keys) { $this::Keys = @() }
        if ([string]::IsNullOrWhiteSpace($this::LogvariableName)) {
            $n = ('fileMonitor_log_' + [guid]::NewGuid().Guid).Replace('-', '_');
            Set-Variable -Name $n -Scope Global -Value ([string[]]@());
            $this::LogvariableName = $n
        }
    }
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File) {
        return [FileMonitor]::monitorFile($File, { Write-Host "[+] File monitor Completed" -f Green })
    }
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File, [scriptblock]$Action) {
        [ValidateNotNull()][IO.FileInfo]$File = [IO.FileInfo](CryptoBase)::GetUnResolvedPath($File)
        if (![IO.File]::Exists($File.FullName)) {
            throw "The file does not exist"
        }
        [FileMonitor]::FileTowatch = $File
        $watcher = [System.IO.FileSystemWatcher]::new();
        $Watcher = New-Object IO.FileSystemWatcher ([IO.Path]::GetDirectoryName($File.FullName)), $File.Name -Property @{
            IncludeSubdirectories = $false
            EnableRaisingEvents   = $true
        }
        $watcher.Filter = $File.Name
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite;
        $onChange = Register-ObjectEvent $Watcher Changed -Action {
            [FileMonitor]::FileLocked = $true
        }
        $OnClosed = Register-ObjectEvent $Watcher Disposed -Action {
            [FileMonitor]::FileClosed = $true
        }
        # [Console]::Write("Monitoring changes to $File"); [Console]::WriteLine("Press 'crl^q' to stop")
        do {
            try {
                [FileMonitor]::FileLocked = [FileMonitor]::IsFileLocked($File.FullName)
            } catch [System.IO.IOException] {
                [FileMonitor]::FileLocked = $(if ($_.Exception.Message.Contains('is being used by another process')) {
                        $true
                    } else {
                        throw 'An error occured while checking the file'
                    }
                )
            } finally {
                [System.Threading.Thread]::Sleep(100)
            }
        } until ([FileMonitor]::FileClosed -and ![FileMonitor]::FileLocked -and ![FileMonitor]::IsFileOpenInVim($File.FullName))
        Invoke-Command -ScriptBlock $Action
        Unregister-Event -SubscriptionId $onChange.Id; $onChange.Dispose();
        Unregister-Event -SubscriptionId $OnClosed.Id; $OnClosed.Dispose(); $Watcher.Dispose();
        return $watcher
    }
    static [PsObject] MonitorFileAsync([string]$filePath) {
        # .EXAMPLE
        # $flt = [FileMonitor]::MonitorFileAsync($filePath)
        # $flt.Thread.CloseInputStream();
        # $flt.Thread.StopJobAsync();
        # Stop-Job -Name $flt.Name -Verbose -PassThru | Remove-Job -Force -Verbose
        # $flt.Thread.Dispose()MOnitorFile
        # while ((Get-Job -Name $flt.Name).State -ne "Completed") {
        #     # DO other STUFF here ...
        # }
        $threadscript = [scriptblock]::Create("[FileMonitor]::MonitorFile('$filePath')")
        $fLT_Name = "kLThread-$([guid]::NewGuid().Guid)"
        return [PSCustomObject]@{
            Name   = $fLT_Name
            Thread = Start-ThreadJob -ScriptBlock $threadscript -Name $fLT_Name
        }
    }
    static [string] GetLogSummary() {
        return [FileMonitor]::GetLogSummary([FileMonitor]::LogvariableName)
    }
    static [string] GetLogSummary([string]$LogvariableName) {
        if ([string]::IsNullOrWhiteSpace($LogvariableName)) { throw "InvalidArgument : LogvariableName" }
        $l = Get-Variable -Name $LogvariableName -Scope Global -ValueOnly;
        $summ = ''; $rgx = "\[.*\] The file '.*' is open in nvim \(PID: \d+\)"
        if ($null -eq $l) { return '' }; $ct = $l.Where({ $_ -notmatch $rgx })
        $LogSessions = @();
        $LogSessions += $(if ($ct.count -gt 1) {
                (($l.ForEach({ if ($_ -notmatch $rgx) { $_ + '|' } else { $_ } })) -join "`n").Split('|')
            } else {
                [string]::Join("`n", $l)
            }
        )
        foreach ($item in $LogSessions) {
            $s = ''; $lines = $item.Split("`n")
            0 .. $lines.Count | ForEach-Object { if ($_ -eq 0) { $s += "$($lines[0])`n" } elseif ($lines[$_] -match $rgx -or $lines[$_ + 1] -match $rgx) { $s += '.' } else { $s += "`n$($lines[$_ - 1])" } }
            $summ += [string]::Join("`n", $s.Split("`n").ForEach({ if ($_ -like "......*") { '⋮' } else { $_ } })).Trim()
            $summ += "`n"
        }
        return $summ.Trim()
    }
    static [bool] IsFileOpenInVim([IO.FileInfo]$file) {
        $res = $null; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global;
        $fileName = Split-Path -Path $File.FullName -Leaf;
        $res = $false; $_log_msg = @(); $processes = Get-Process -Name "nvim*", "vim*" -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            if ($process.CommandLine -like "*$fileName*") {
                $_log_msg = "[{0}] The file '{1}' is open in {2} (PID: {3})" -f [DateTime]::Now.ToString(), $fileName, $process.ProcessName, $process.Id
                $res = $true; continue
            }
        }
        $_log_msg = $_log_msg -join [Environment]::NewLine
        if ([string]::IsNullOrEmpty($_log_msg)) {
            $res = $false; $_log_msg = "[{0}] The file '{1}' is not open in vim" -f [DateTime]::Now.ToString(), $fileName
        }
        $logvar.Value += $_log_msg
        Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
        return $res
    }
    static [bool] IsFileLocked([string]$filePath) {
        $res = $true; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global; $filePath = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
        try {
            # (lsof -t "$filePath" | wc -w) -gt 0
            [System.IO.FileStream]$stream = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            if ($stream) { $stream.Close(); $stream.Dispose() }
            $res = $false
        } finally {
            if ($res) { $logvar.Value += "[$([DateTime]::Now.ToString())] File is already locked by another process." }
            Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
        }
        return $res
    }
}

function FileMonitor {
    [CmdletBinding()]
    param ()
    end {
        return [FileMonitor]::New()
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")