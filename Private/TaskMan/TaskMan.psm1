# A small process managment class
class TaskMan {
    static [System.Management.Automation.PsObject[]] RunInParallel([System.Management.Automation.Job[]]$jobs) {
        $threadjobs = $jobs | ForEach-Object { Start-ThreadJob -ScriptBlock ([ScriptBlock]::Create($_.Command)) }
        $results = $threadjobs | Receive-Job -Wait
        return $results
    }
    static [TaskResult] WaitTask([string]$progressMsg, [scriptblock]$scriptBlock) {
        return [TaskMan]::WaitTask($progressMsg, $(Start-Job -ScriptBlock $scriptBlock))
    }
    static [TaskResult] WaitTask([string]$progressMsg, [System.Management.Automation.Job]$Job) {
        [Console]::CursorVisible = $false;
        [ProgressUtil]::frames = [ProgressUtil]::_twirl[0]
        [int]$length = [ProgressUtil]::frames.Length;
        $originalY = [Console]::CursorTop
        while ($Job.JobStateInfo.State -notin ('Completed', 'failed')) {
            for ($i = 0; $i -lt $length; $i++) {
                [ProgressUtil]::frames.Foreach({ [Console]::Write("$progressMsg $($_[$i])") })
                [System.Threading.Thread]::Sleep(50)
                [Console]::Write(("`b" * ($length + $progressMsg.Length)))
                [Console]::CursorTop = $originalY
            }
        }
        Write-Host "`b$progressMsg ... " -f Blue -NoNewline
        [System.Management.Automation.Runspaces.RemotingErrorRecord[]]$Errors = $Job.ChildJobs.Where({
                $null -ne $_.Error
            }
        ).Error;
        if ($Job.JobStateInfo.State -eq "Failed" -or $Errors.Count -gt 0) {
            $errormessages = ""; $errStackTrace = ""
            if ($null -ne $Errors) {
                $errormessages = $Errors.Exception.Message -join "`n"
                $errStackTrace = $Errors.ScriptStackTrace
                if ($null -ne $Errors.Exception.InnerException) {
                    $errStackTrace += "`n`t"
                    $errStackTrace += $Errors.Exception.InnerException.StackTrace
                }
            }
            [taskman]::WriteLog("Completed with errors.`n`t$errormessages`n`t$errStackTrace", $false)
        } else {
            [TaskMan]::WriteLog("Done.", $true)
        }
        [Console]::CursorVisible = $true;
        return [TaskResult]::new($Job)
    }
    static [TaskResult] RetryCommand([ScriptBlock]$ScriptBlock) {
        return [TaskMan]::RetryCommand($ScriptBlock, "")
    }
    static [TaskResult] RetryCommand([ScriptBlock]$ScriptBlock, [string]$Message) {
        return [TaskMan]::RetryCommand($ScriptBlock, $Message, 3)
    }
    static [TaskResult] RetryCommand([ScriptBlock]$ScriptBlock, [string]$Message, [Int]$MaxAttempts) {
        return [TaskMan]::RetryCommand($ScriptBlock, $null, [System.Threading.CancellationToken]::None, $MaxAttempts, "$Message", 1000)
    }
    static [TaskResult] RetryCommand([ScriptBlock]$ScriptBlock, [Object[]]$ArgumentList, [string]$Message) {
        return [TaskMan]::RetryCommand($ScriptBlock, $ArgumentList, [System.Threading.CancellationToken]::None, 3, "$Message", 1000)
    }
    static [TaskResult] RetryCommand([ScriptBlock]$ScriptBlock, [Object[]]$ArgumentList, [System.Threading.CancellationToken]$CancellationToken, [Int]$MaxAttempts, [String]$Message, [Int]$Timeout) {
        [ValidateNotNullOrEmpty()][scriptblock]$ScriptBlock = $ScriptBlock
        if ([string]::IsNullOrWhiteSpace((Show-Stack))) { Push-Stack "TaskMan" }
        $IsSuccess = $false; $fxn = Show-Stack; $AttemptStartTime = $null;
        $Output = [string]::Empty; $ErrorRecord = $null; $Attempts = 1
        if ([string]::IsNullOrWhiteSpace($Message)) { $Message = "Invoke Command" }
        $Result = [TaskResult]::new($Output, [bool]$IsSuccess, $ErrorRecord)
        $CommandStartTime = Get-Date
        while (($Attempts -le $MaxAttempts) -and !$Result.IsSuccess) {
            $Retries = $MaxAttempts - $Attempts
            if ($cancellationToken.IsCancellationRequested) {
                [TaskMan]::WriteLog("$fxn CancellationRequested when $Retries retries were left.", $false)
                throw
            }
            try {
                Write-Host "$fxn $Message" -NoNewline -f DarkGray; Write-Host " Attempt # $Attempts/$MaxAttempts : " -NoNewline
                $AttemptStartTime = Get-Date
                if ($null -ne $ArgumentList) {
                    $Output = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
                } else {
                    $Output = Invoke-Command -ScriptBlock $ScriptBlock
                }
                $IsSuccess = [bool]$?
                if ($Output -is [bool]) { $IsSuccess = $Output }
            } catch {
                $IsSuccess = $false; $ErrorRecord = $_
                Write-Host "$fxn Errored after $([math]::Round(($(Get-Date) - $AttemptStartTime).TotalSeconds, 2)) seconds" -f Red -NoNewline
            } finally {
                $Result.Output = $Output
                $Result.IsSuccess = $IsSuccess
                $Result.ErrorRecord = $ErrorRecord
                if ($Retries -eq 0 -or $Result.IsSuccess) {
                    Write-Host " E.T = $([math]::Round(($(Get-Date) - $CommandStartTime).TotalSeconds, 2)) seconds"
                } elseif (!$cancellationToken.IsCancellationRequested -and $Retries -ne 0) {
                    Start-Sleep -Milliseconds $Timeout
                }
                $Attempts++
            }
        }
        return $Result
    }
    static [void] WriteLog([bool]$IsSuccess) {
        [TaskMan]::WriteLog($null, $IsSuccess)
    }
    static [void] WriteLog([string]$Message, [bool]$IsSuccess) {
        $re = @{ true = @{ m = "Success "; c = "Cyan" }; false = @{ m = "Failed "; c = "Red" } }
        if (![string]::IsNullOrWhiteSpace($Message)) { $re["$IsSuccess"].m = $Message }
        $re = $re["$IsSuccess"]
        Write-Host $re.m -f $re.c -NoNewline:$IsSuccess
    }
}

# .SYNOPSIS
# A simple progress utility class
# .EXAMPLE
# $OgForeground = (Get-Variable host).Value.UI.RawUI.ForegroundColor
# (Get-Variable host).Value.UI.RawUI.ForegroundColor = [ConsoleColor]::Green
# for ($i = 0; $i -le 100; $i++) {
#     [ProgressUtil]::WriteProgressBar($i)
#     [System.Threading.Thread]::Sleep(50)
# }
# (Get-Variable host).Value.UI.RawUI.ForegroundColor = $OgForeground
# [TaskMan]::WaitTask("Waiting", { Start-Sleep -Seconds 3 })
#
class ProgressUtil {
    static hidden [string] $_block = '■';
    static hidden [string] $_back = "`b";
    static hidden [string[]] $_twirl = @(
        "-\\|/", "|/-\\", "+■0"
    );
    static [int] $_twirlIndex = 0
    static hidden [string]$frames
    static [void] WriteProgressBar([int]$percent) {
        [ProgressUtil]::WriteProgressBar($percent, $true)
    }
    static [void] WriteProgressBar([int]$percent, [bool]$update) {
        [ProgressUtil]::WriteProgressBar($percent, $update, [int]([Console]::WindowWidth * 0.7))
    }
    static [void] WriteProgressBar([int]$percent, [bool]$update, [int]$PBLength) {
        [ValidateNotNull()][int]$PBLength = $PBLength
        [ValidateNotNull()][int]$percent = $percent
        [ValidateNotNull()][bool]$update = $update
        [ProgressUtil]::_back = "`b" * [Console]::WindowWidth
        if ($update) { [Console]::Write([ProgressUtil]::_back) }
        [Console]::Write("["); $p = [int](($percent / 100.0) * $PBLength + 0.5)
        for ($i = 0; $i -lt $PBLength; $i++) {
            if ($i -ge $p) {
                [Console]::Write(' ');
            } else {
                [Console]::Write([ProgressUtil]::_block);
            }
        }
        [Console]::Write("] {0,3:##0}%", $percent);
    }
}

class TaskResult {
    [bool]$IsSuccess
    hidden [string]$JobName
    hidden [string]$Command
    [System.Management.Automation.ErrorRecord]$ErrorRecord
    [System.Management.Automation.PSDataCollection[psobject]]$Output
    TaskResult([object]$Output, [bool]$IsSuccess, [object]$ErrorRecord) {
        $this.Output = $Output;
        $this.IsSuccess = $IsSuccess;
        $this.ErrorRecord = $ErrorRecord
        $job_state = $(if ($this.IsSuccess) { "Completed" } else { "Failed" })
        $get_state = [scriptblock]::Create("return '$job_state'")
        $this.PsObject.Properties.Add([psscriptproperty]::new('State', $get_state, { throw [System.InvalidOperationException]::new("Cannot set State") }))
    }
    TaskResult([System.Management.Automation.Job]$job) {
        $this.Command = $job.Command
        $get_state = [scriptblock]::Create("return '$($job.JobStateInfo.State.ToString())'")
        $this.PsObject.Properties.Add([psscriptproperty]::new('State', $get_state, { throw [System.InvalidOperationException]::new("Cannot set State") }))
        $this.Output = $job.ChildJobs | Receive-Job -Wait
        # [scriptBlock]::Create("$($job.ChildJobs.Command)").Invoke()
        $this.IsSuccess = $job.JobStateInfo.State -eq "Completed"
        if (!$this.IsSuccess) {
            $this.ErrorRecord = (Get-Variable -Name Error -ValueOnly)[0]
        }
    }
}

class CommandOptions {
    [Int]$MaxAttempts
    [Int]$Timeout
    [System.Threading.CancellationToken]$CancellationToken
    CommandOptions() {
        $this.MaxAttempts = 3
        $this.Timeout = 1000
        $this.CancellationToken = [System.Threading.CancellationToken]::None
    }
}

function Write-ProgressBar {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('p')]
        [int]$percent,

        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('l')]
        [int]$PBLength,

        [Parameter(Mandatory = $false)]
        [switch]$update
    )

    end {
        [ProgressUtil]::WriteProgressBar($percent, $update.IsPresent, $PBLength);
    }
}

function Invoke-RetriableCommand {
    [Alias('Retry-Command')]
    [OutputType([TaskResult])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('s')]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false, Position = 1)]
        [Alias('args')]
        [Object[]]$ArgumentList,

        [Parameter(Mandatory = $false, Position = 2)]
        [Alias('m')]
        [string]$Message,

        [Parameter(Mandatory = $false, Position = 3)]
        [Alias('o')]
        [CommandOptions]$Options
    )

    begin {
        $cmdOptions = $null
        $result = $null
    }

    process {
        if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Options')) {
            $cmdOptions = [CommandOptions]::new()
        } else {
            $cmdOptions = $Options
        }
        $result = [TaskMan]::RetryCommand($ScriptBlock, $ArgumentList, $cmdOptions.CancellationToken, $cmdOptions.MaxAttempts, "$Message", $cmdOptions.Timeout)
    }

    end {
        return $result
    }
}

function Wait-Task {
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    [OutputType([TaskResult])][Alias('await')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllparameterSets')]
        [Alias('m')]
        [string]$progressMsg,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'scriptBlock')]
        [Alias('s')]
        [scriptblock]$scriptBlock,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'job')]
        [System.Management.Automation.Job]$Job,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1, ParameterSetName = 'task')]
        [System.Threading.Tasks.Task[]]$Task
    )
    begin {
        $result = $null
        # $Tasks = @()
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'scriptBlock') {
            $result = [TaskMan]::WaitTask($progressMsg, $scriptBlock)
        } else {
            throw [System.NotSupportedException]::new("Sorry, ParameterSetName '$($PSCmdlet.ParameterSetName)' is not yet supported")
        }
        # $Tasks += $Task
        # While (-not [System.Threading.Tasks.Task]::WaitAll($Tasks, 200)) {}
        # $Tasks.ForEach( { $_.GetAwaiter().GetResult() })
    }
    end {
        return $result
    }
}

function New-Task {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    [Alias('Create-Task')]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false, Position = 1)]
        [Object[]]$ArgumentList
    )
    begin {
        $_result = $null
        $powershell = [System.Management.Automation.PowerShell]::Create()
    }
    process {
        $_Action = $(if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('ArgumentList')) {
                { Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList } -as [System.Action]
            } else {
                { Invoke-Command -ScriptBlock $ScriptBlock } -as [System.Action]
            }
        )
        $powershell.AddScript({
                param (
                    [Parameter(Mandatory)]
                    [ValidateNotNull()]
                    [System.Action]$Action
                )
                return [System.Threading.Tasks.Task]::Factory.StartNew($Action)
            }
        ).AddArgument($_Action)
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $runspace.Open(); $powershell.Runspace = $runspace
        [ValidateNotNull()][System.Action]$_Action = $_Action;
        Write-Host "Run In Background .." -ForegroundColor DarkBlue

        $threads = New-Object System.Collections.ArrayList;
        $result = [PSCustomObject]@{
            PowerShell = $PowerShell
            returnVal  = $PowerShell.BeginInvoke()
        }
        $threads.Add($result) | Out-Null;
        $completed = $false;
        while ($completed -eq $false) {
            $completed = $true;
            foreach ($thread in $threads) {
                $endInvoke = $thread.PowerShell.EndInvoke($thread.returnVal);
                $endInvoke;
                $threadHandle = $thread.returnVal.AsyncWaitHandle.Handle;
                $threadIsCompleted = $thread.returnVal.IsCompleted;
                Write-Host "$threadHandle is $threadIsCompleted";
                if ($threadIsCompleted -eq $false) {
                    $completed = $false;
                }
            }
            Write-Host "";
            Start-Sleep -Milliseconds 500;
        }
        foreach ($thread in $threads) {
            $thread.PowerShell.Dispose();
        }
        $_result = $result
    }
    end {
        return $_result
    }
}
# $t = New-Task { "running ...."; Start-Sleep -Seconds 3;  return "hello world" }

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")