
# .SYNOPSIS
# BackJobs.psm1 Contains classes & functions to help with Background jobs


class cli {
    static hidden [ValidateNotNull()][string]$Preffix # .EXAMPLE Try this: # [cli]::Preffix = '@:'; [void][cli]::Write('animations and stuff', [ConsoleColor]::Magenta)
    static hidden [ValidateNotNull()][scriptblock]$textValidator # ex: if $text does not match a regex throw 'erro~ ..'
    static [string] write([string]$text) {
        return [cli]::Write($text, 20, 1200)
    }
    static [string] Write([string]$text, [bool]$AddPreffix) {
        return [cli]::Write($text, 20, 1200, $AddPreffix)
    }
    static [string] Write([string]$text, [int]$Speed, [int]$Duration) {
        return [cli]::Write($text, 20, 1200, $true)
    }
    static [string] write([string]$text, [ConsoleColor]$color) {
        return [cli]::Write($text, $color, $true)
    }
    static [string] write([string]$text, [ConsoleColor]$color, [bool]$Animate) {
        return [cli]::Write($text, [cli]::Preffix, 20, 1200, $color, $Animate, $true)
    }
    static [string] write([string]$text, [int]$Speed, [int]$Duration, [bool]$AddPreffix) {
        return [cli]::Write($text, [cli]::Preffix, $Speed, $Duration, [ConsoleColor]::White, $true, $AddPreffix)
    }
    static [string] write([string]$text, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix) {
        return [cli]::Write($text, [cli]::Preffix, 20, 1200, $color, $Animate, $AddPreffix)
    }
    static [string] write([string]$text, [string]$Preffix, [System.ConsoleColor]$color) {
        return [cli]::Write($text, $Preffix, $color, $true)
    }
    static [string] write([string]$text, [string]$Preffix, [System.ConsoleColor]$color, [bool]$Animate) {
        return [cli]::Write($text, $Preffix, 20, 1200, $color, $Animate, $true)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [bool]$AddPreffix) {
        return [cli]::Write($text, $Preffix, $Speed, $Duration, [ConsoleColor]::White, $true, $AddPreffix)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix) {
        return [cli]::Write($text, $Preffix, $Speed, $Duration, $color, $Animate, $AddPreffix, [cli]::textValidator)
    }
    static [string] write([string]$text, [string]$Preffix, [int]$Speed, [int]$Duration, [ConsoleColor]$color, [bool]$Animate, [bool]$AddPreffix, [scriptblock]$textValidator) {
        if ($null -ne $textValidator) {
            $textValidator.Invoke($text)
        }
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $text
        }
        [int]$length = $text.Length; $delay = 0
        # Check if delay time is required:
        $delayIsRequired = if ($length -lt 50) { $false } else { $delay = $Duration - $length * $Speed; $delay -gt 0 }
        if ($AddPreffix -and ![string]::IsNullOrEmpty($Preffix)) {
            [void][cli]::Write($Preffix, [string]::Empty, 1, 100, [ConsoleColor]::Green, $false, $false);
        }
        $FgColr = [Console]::ForegroundColor
        [Console]::ForegroundColor = $color
        if ($Animate) {
            for ($i = 0; $i -lt $length; $i++) {
                [void][Console]::Write($text[$i]);
                Start-Sleep -Milliseconds $Speed;
            }
        } else {
            [void][Console]::Write($text);
        }
        if ($delayIsRequired) {
            Start-Sleep -Milliseconds $delay
        }
        [Console]::ForegroundColor = $FgColr
        return $text
    }
}

# .SYNOPSIS
#     A class to convert dot ascii arts to b64string & vice versa
# .DESCRIPTION
#     Cli art created from sites like https://lachlanarthur.github.io/Braille-ASCII-Art/ can only be embeded as b64 string
#     So this class helps speed up the conversion process
# .EXAMPLE
#     $b64str = [cliart]::ToBase64String((Get-Item ./ascii))
#     [CliArt]::FromBase64String($b64str) | Write-Host -f Green
class CliArt {
    hidden [string]$Base64String
    CliArt([byte[]]$ArtBytes) {
        $this.Base64String = [CliArt]::ToBase64String($ArtBytes)
    }
    CliArt([IO.FileInfo]$Artfile) {
        $this.Base64String = [CliArt]::ToBase64String($Artfile)
    }
    CliArt([string]$Base64String) {
        $this.Base64String = $Base64String
    }
    static [string] ToBase64String([byte[]]$ArtBytes) {
        return [convert]::ToBase64String((xconvert)::ToCompressed([System.Text.Encoding]::UTF8.GetBytes((Base85)::Encode($ArtBytes))))
    }
    static [string] ToBase64String([IO.FileInfo]$Artfile) {
        return [CliArt]::ToBase64String([IO.File]::ReadAllBytes($Artfile.FullName))
    }
    static [string] FromBase64String([string]$B64String) {
        return [System.Text.Encoding]::UTF8.GetString((Base85)::Decode([System.Text.Encoding]::UTF8.GetString((xconvert)::ToDeCompressed([convert]::FromBase64String($B64String)))))
    }
    [string] ToString() {
        return [CliArt]::FromBase64String($this.Base64String)
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
# Wait-Task "Waiting" { Start-Sleep -Seconds 3 }
#
class ProgressUtil {
    static hidden [string] $_block = '■';
    static hidden [string] $_back = "`b";
    static hidden [string[]] $_twirl = @(
        "-\\|/", "|/-\\", "+■0"
    );
    static [string] $AttemptMSg
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

class StackTracer {
    static [System.Collections.Concurrent.ConcurrentStack[string]]$stack = [System.Collections.Concurrent.ConcurrentStack[string]]::new()
    static [System.Collections.Generic.List[hashtable]]$CallLog = @()
    static [void] Push([string]$class) {
        $str = "[{0}]" -f $class
        if ([StackTracer]::Peek() -ne "$class") {
            [StackTracer]::stack.Push($str)
            $LAST_ERROR = $(Get-Variable -Name Error -ValueOnly)[0]
            [StackTracer]::CallLog.Add(@{ ($str + ' @ ' + [datetime]::Now.ToShortTimeString()) = $(if ($null -ne $LAST_ERROR) { $LAST_ERROR.ScriptStackTrace } else { [System.Environment]::StackTrace }).Split("`n").Replace("at ", "# ").Trim() })
        }
    }
    static [type] Pop() {
        $result = $null
        if ([StackTracer]::stack.TryPop([ref]$result)) {
            return $result
        } else {
            throw [System.InvalidOperationException]::new("Stack is empty!")
        }
    }
    static [string] Peek() {
        $result = $null
        if ([StackTracer]::stack.TryPeek([ref]$result)) {
            return $result
        } else {
            return [string]::Empty
        }
    }
    static [int] GetSize() {
        return [StackTracer]::stack.Count
    }
    static [bool] IsEmpty() {
        return [StackTracer]::stack.IsEmpty
    }
}
function Pop-Stack {
    [CmdletBinding()]
    param ()
    process {
        return [StackTracer]::Pop()
    }
}

function Push-Stack {
    [CmdletBinding()]
    param (
        [string]$class
    )
    process {
        [StackTracer]::Push($class)
    }
}

function Show-Stack {
    [CmdletBinding()]
    param ()
    process {
        [StackTracer]::Peek()
    }
}

function New-CliArt {
    [CmdletBinding()]
    [OutputType([CliArt])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Base64String
    )
    process {
        return [CliArt]::new($Base64String)
    }
}

function Write-AnimatedHost {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('t')][AllowEmptyString()]
        [string]$text,

        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('f')]
        [System.ConsoleColor]$foregroundColor
    )
    process {
        [void][cli]::Write($text, $foregroundColor)
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
    # .SYNOPSIS
    #     Retries a Command
    # .DESCRIPTION
    #     A longer description of the function, its purpose, common use cases, etc.
    # .LINK
    #     https://github.com/alainQtec/argoncage/blob/main/Private/TaskMan/TaskMan.psm1
    # .EXAMPLE
    #     Invoke-RetriableCommand { (CheckConnection -host "github.com" -msg "Testing Connection" -IsOnline).Output }
    #     Tries to connect to github 3 times
    [CmdletBinding()]
    [OutputType([psobject])]
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
        [Alias('cs')][ValidateNotNullOrEmpty()]
        [scriptblock]$CleanupScript,

        [Parameter(Mandatory = $false, Position = 4)]
        [Alias('o')]
        [PSCustomObject]$Options
    )

    begin {
        function WriteLog {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
                [string]$m = '',
                [Parameter(Mandatory = $false, Position = 1)]
                [switch]$s
            )
            # DynamicParam {
            #     if ($args.GetType().Name -eq 'syste.object[]') {
            #         $ageAttribute = [System.Management.Automation.ParameterAttribute]::new()
            #         $ageAttribute.Position = 3
            #         $ageAttribute.Mandatory = $true
            #         $ageAttribute.HelpMessage = "This product is only available for customers 21 years of age and older. Please enter your age:"
            #         $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::New()
            #         $attributeCollection.Add($ageAttribute)
            #         $ageParam = [System.Management.Automation.RuntimeDefinedParameter]::new('age', [Int16], $attributeCollection)
            #         $paramDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::New()
            #         $paramDictionary.Add('age', $ageParam)
            #         return $paramDictionary
            #     }
            # }
            process {
                $args.GetType().Name | Write-Host -f Green
                $re = @{ true = @{ m = "Complete "; c = "Cyan" }; false = @{ m = "Errored "; c = "Red" } }
                if (![string]::IsNullOrWhiteSpace($m)) { $re["$s"].m = $m }
                $re = $re["$s"]
                Write-Host $re.m -f $re.c -NoNewline:$s
            }
        }
    }

    process {
        $cmdOptions = $(if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Options')) {
                [PSCustomObject]@{
                    MaxAttempts       = 3
                    Timeout           = 1000
                    CancellationToken = [System.Threading.CancellationToken]::None
                    CleanupScript     = $null
                }
            } else { $Options }
        )
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('CleanupScript')) { $cmdOptions.CleanupScript = $CleanupScript }
        [System.Threading.CancellationToken]$CancellationToken = $cmdOptions.CancellationToken
        [Int]$MaxAttempts = $cmdOptions.MaxAttempts
        [String]$Message = "$Message"; if ([string]::IsNullOrWhiteSpace($Message)) { $Message = "Invoke Command" }
        [Int]$Timeout = $cmdOptions.Timeout
        [ScriptBlock]$CleanupScript = $cmdOptions.CleanupScript
        [string]$Output = [string]::Empty; $bgTask = BackgroundTask -Output $Output ; $bgTask.IsSuccess = $IsSuccess
        [ValidateNotNullOrEmpty()][scriptblock]$ScriptBlock = $ScriptBlock
        if ([string]::IsNullOrWhiteSpace((Show-Stack))) { Push-Stack 'TaskMan' }
        $IsSuccess = $false; $fxn = Show-Stack; $AttemptStartTime = $null;
        $ErrorRecord = $null;
        [int]$Attempts = 1
        $CommandStartTime = Get-Date
        while (($Attempts -le $MaxAttempts) -and !$bgTask.IsSuccess) {
            $Retries = $MaxAttempts - $Attempts
            if ($cancellationToken.IsCancellationRequested) {
                WriteLog "$fxn CancellationRequested when $Retries retries were left."
                throw
            }
            try {
                " Attempt # $Attempts/$MaxAttempts" | Set-AttemptMSg
                Write-Debug "$fxn $Message$([ProgressUtil]::AttemptMSg) "
                $AttemptStartTime = Get-Date
                if ($null -ne $ArgumentList) {
                    $Output = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
                    $IsSuccess = [bool]$?
                } else {
                    $Output = Invoke-Command -ScriptBlock $ScriptBlock
                    $IsSuccess = [bool]$?
                }
            } catch {
                $IsSuccess = $false; $ErrorRecord = $_
                " Errored after $([math]::Round(($(Get-Date) - $AttemptStartTime).TotalSeconds, 2)) seconds" | Set-AttemptMSg
                Write-Debug "$fxn $([ProgressUtil]::AttemptMSg)"
            } finally {
                $bgTask.Output = $Output
                $bgTask.IsSuccess = $IsSuccess
                $bgTask.ErrorRecord = $ErrorRecord
                if ($null -ne $CleanupScript) { $bgTask = $CleanupScript.Invoke($bgTask) }
                $job_state = $(if ($bgTask.IsSuccess) { "Completed" } else { "Failed" })
                $bgTask.SetJobState([scriptblock]::Create("return '$job_state'"))
                if ($Retries -eq 0 -or $bgTask.IsSuccess) {
                    Write-Debug " E.T = $([math]::Round(($(Get-Date) - $CommandStartTime).TotalSeconds, 2)) seconds"
                } elseif (!$cancellationToken.IsCancellationRequested -and $Retries -ne 0) {
                    Start-Sleep -Milliseconds $Timeout
                }
                $Attempts++
            }
        }
        return $bgTask
    }
}

function Get-AttemptMSg {
    return [ProgressUtil]::AttemptMSg
}

function Set-AttemptMSg {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true , Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    [ProgressUtil]::AttemptMSg = $Message
}

function Wait-Task {
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    [OutputType([psobject])][Alias('await')]
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
        $TaskResult = $null
        # $Tasks = @()
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'scriptBlock') {
            [int]$JobId = $(Start-Job -ScriptBlock $scriptBlock).Id
        } else {
            throw [System.NotSupportedException]::new("Sorry, ParameterSetName is not yet supported")
        }
        # $Tasks += $Task
        # While (![System.Threading.Tasks.Task]::WaitAll($Tasks, 200)) {}
        # $Tasks.ForEach( { $_.GetAwaiter().GetResult() })

        [System.Management.Automation.Job]$Job = Get-Job -Id $JobId
        [Console]::CursorVisible = $false;
        [ProgressUtil]::frames = [ProgressUtil]::_twirl[0]
        [int]$length = [ProgressUtil]::frames.Length;
        $originalY = [Console]::CursorTop
        while ($Job.JobStateInfo.State -notin ('Completed', 'failed')) {
            for ($i = 0; $i -lt $length; $i++) {
                [ProgressUtil]::frames | ForEach-Object { [Console]::Write("$progressMsg $($_[$i])") }
                [System.Threading.Thread]::Sleep(50)
                [Console]::Write(("`b" * ($length + $progressMsg.Length)))
                [Console]::CursorTop = $originalY
            }
        }
        # i.e: Gives an illusion of loading animation.
        [void][cli]::Write("`b$progressMsg", [ConsoleColor]::Blue)
        [System.Management.Automation.Runspaces.RemotingErrorRecord[]]$Errors = $Job.ChildJobs.Where({
                $null -ne $_.Error
            }
        ).Error;
        $LogMsg = ''; $_Success = ($null -eq $Errors); $attMSg = Get-AttemptMSg;
        if (![string]::IsNullOrWhiteSpace($attMSg)) { $LogMsg += $attMSg } else { $LogMsg += "... " }
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
            $TaskResult = $Job | BackgroundTask -e $Errors # BackgroundTask -Job $Job -ErrorRecord $Errors
            $_Success = $false; $LogMsg += " Completed with errors.`n`t$errormessages`n`t$errStackTrace"
        } else {
            $TaskResult = $Job | BackgroundTask
        }
        WriteLog $LogMsg -s:$_Success
        [Console]::CursorVisible = $true; Set-AttemptMSg ' '
    }
    end {
        return $TaskResult
    }
}

function BackgroundTask {
    # .EXAMPLE
    #     Start-Job -ScriptBlock { start-sleep -seconds 2; return 100 } | BackgroundTask
    #     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    # .OUTPUTS
    #     BackgroundTask.TaskResult
    [CmdletBinding(DefaultParameterSetName = 'Job')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'output')]
        [AllowNull()][Alias('o')]
        [object]$Output,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Job', ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][Alias('J')]
        [System.Management.Automation.Job]$Job,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'output')]
        [Alias('s')]
        [bool]$IsSuccess = 0,

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllparameterSets')]
        [ValidateNotNullOrEmpty()][Alias('e')]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    begin {
        class TaskCommands : System.Collections.Generic.List[String] {
            TaskCommands() {}
            [string] ToString() {
                if ($this.Count -eq 0) { return [string]::Empty }else { return '...' }
            }
        }
        class TaskResult {
            [bool]$IsSuccess
            [string]$JobName
            [array]$ErrorRecord
            hidden [TaskCommands]$Commands
            [System.Management.Automation.PSDataCollection[psobject]]$Output
            TaskResult() {
                $this.IsSuccess = $false
                $this.JobName = [string]::Empty
                $this.ErrorRecord = @()
                $this.Commands = [TaskCommands]::new()
                $this.Output = [System.Management.Automation.PSDataCollection[psobject]]::new()
            }
            [void] SetJobState() { $this.SetJobState($null) }
            [void] SetJobState([scriptblock]$get_state) {
                # .EXAMPLE
                #   $result.SetJobState()
                # .EXAMPLE
                #   $result.SetJobState({ return 'StateSTR' })
                if ($null -eq $get_state) {
                    $job_state = $(if ($this.IsSuccess) { "Completed" } else { "Failed" })
                    $get_state = [scriptblock]::Create("return '$job_state'")
                }
                $this.PsObject.Properties.Add([psscriptproperty]::new('State', $get_state, { throw [System.InvalidOperationException]::new("Cannot set State") }))
            }
        }
        $tresult = [TaskResult]::new()
    }

    process {
        $HasErrorRecord = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('ErrorRecord')
        if ($PSCmdlet.ParameterSetName -eq 'output') {
            if ($null -eq $Output) { $Output = New-Object psobject }
            [void]$tresult.Output.Add($Output); $tresult.SetJobState()
        } else {
            $tresult.Commands.Add($Job.Command) | Out-Null
            $tresult.SetJobState([scriptblock]::Create("return '$($job.JobStateInfo.State.ToString())'"))
            $JobRes = $job.ChildJobs | Receive-Job -Wait
            if ($JobRes -is [bool]) { $tresult.IsSuccess = $JobRes }
            $tresult.Output.Add($JobRes) | Out-Null
        }
        $tresult.IsSuccess = !$HasErrorRecord -and $($tresult.State -eq "Completed")
        if ($HasErrorRecord) { $tresult.ErrorRecord = $ErrorRecord }
    }

    end {
        return $tresult
    }
}

function New-Task {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    [Alias('Create-Task')]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [scriptblock][ValidateNotNullOrEmpty()]
        $ScriptBlock,

        [Parameter(Mandatory = $false, Position = 1)]
        [Object[]]
        $ArgumentList,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullOrEmpty()][System.Management.Automation.Runspaces.Runspace]
        $Runspace = (Get-Variable ExecutionContext -ValueOnly).Host.Runspace
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
        $powershell = $powershell.AddScript({
                param (
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNull()]
                    [System.Action]$Action
                )
                return [System.Threading.Tasks.Task]::Factory.StartNew($Action)
            }
        ).AddArgument($_Action)
        if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Runspace')) {
            $Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        } else {
            Write-Debug "[New-Task] Using LocalRunspace ..."
            $Runspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        }
        if ($Runspace.RunspaceStateInfo.State -ne 'Opened') { $Runspace.Open() }
        $powershell.Runspace = $Runspace
        [ValidateNotNull()][System.Action]$_Action = $_Action;
        Write-Host "[New-Task] Runing in background ..." -ForegroundColor DarkBlue
        $threads = New-Object System.Collections.ArrayList;
        $result = [PSCustomObject]@{
            Task   = $null
            Shell  = $PowerShell
            Result = $PowerShell.BeginInvoke()
        }
        $threads.Add($result) | Out-Null;
        $completed = $false; $_r = @{ true = 'Completed'; false = 'Still open' }
        while ($completed -eq $false) {
            $completed = $true;
            foreach ($thread in $threads) {
                $result.Task = $thread.Shell.EndInvoke($thread.Result);
                $threadHandle = $thread.Result.AsyncWaitHandle.Handle;
                $threadIsCompleted = $thread.Result.IsCompleted;
                ("[New-Task] ThreadHandle {0} is {1}" -f $threadHandle, $_r["$threadIsCompleted"]) | Write-Host -f Blue
                if ($threadIsCompleted -eq $false) {
                    $completed = $false;
                }
            }
            Write-Host "";
            Start-Sleep -Milliseconds 500;
        }
        foreach ($thread in $threads) {
            $thread.Shell.Dispose();
        }
        $_result = $result
    }
    end {
        return $_result
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")