using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Management.Automation

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

#region    cboxclasses
enum HostOs {
    Windows
    Linux
    MacOS
    UNKNOWN
}
class MinRequirements {
    [int]$FreeMemGB = 1
    [int]$MinDiskGB = 10
    [bool]$RunAsAdmin = $false
    [FileInfo[]]$RequiredFiles
    [DirectoryInfo[]]$RequiredDirectories
    hidden [string[]]$IgnoredProps = @()
    MinRequirements() {}
}
class InstallReport {
    hidden [string]$Title
    InstallReport ([string]$Title, [hashtable]$table) {
        $this.Title = $Title; $this.SetObjects($table)
    }
    hidden [void] SetObjects([hashtable]$table) {
        $dict = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $table.Keys.ForEach({ [void]$dict.Add($_, $table[$_]) }); $this.SetObjects($dict)
    }
    [void] SetObjects([System.Collections.Generic.Dictionary[string, string]]$dict) {
        $dict.Keys.ForEach({ $this.psobject.Properties.Add([PSScriptProperty]::new($_, [scriptblock]::Create("return '$($dict[$_])'"), { throw "$_ is a readonly property" })) })
    }
    [string] ToString() {
        return (" " + $this.Title + "`n" + ($this | Format-List | Out-String))
    }
}

class SetupStep {
    [string]$MethodName
    [string]$Desscription
    [System.Array]$ArgumentList

    SetupStep([string]$Name) {
        $this.MethodName = $Name
    }
    SetupStep([string]$Name, [System.Array]$ArgumentList) {
        $this.MethodName = $Name; $this.ArgumentList = $ArgumentList
    }
    [SetupStep] SetDescription([string]$Desscription) {
        $this.Desscription = $Desscription
        return $this
    }
}

class Setup {
    [string] $Name
    [bool] $RunAsAdmin = $true
    static [HostOs] $HostOs = [Setup]::GetHostOs()
    static [ActionPreference] $OnError = (Get-Variable -Name ErrorActionPreference -ValueOnly)
    [System.Collections.Generic.Queue[SetupStep]]$Steps = @()
    Setup() {}
    [TaskResult] Run([Setup]$setup) {
        return $this.Run($setup, $true)
    }
    [TaskResult] Run([SetupStep]$step) {
        return $this.Run($step, $false)
    }
    [TaskResult] Run([Setup]$setup, [bool]$Async) {
        $result = [TaskResult]::new()
        # if (!$setup.CheckRequirements()) { throw "Minimum requirements were not met" }
        $c = 1; $setup.Steps.ForEach({
                Write-Verbose "[$c/$($setup.Steps.Count)] $($_.MethodName) ..."
                [void]$result.Output.Add($setup.Run($_, $Async))
                $c++
            }
        )
        return $result
    }
    [TaskResult] Run([SetupStep]$step, [bool]$Async) {
        if ($Async) {
            return [TaskResult]::new($(Start-Job -Name $step.MethodName -ScriptBlock {
                        param($setup, $stp)
                        if (0 -eq $stp.ArgumentList.Count) { return $setup."$($stp.MethodName)"() }
                        return $setup."$($stp.MethodName)"($stp.ArgumentList)
                    } -ArgumentList $this, $step
                )
            )
        } else {
            if (0 -eq $step.ArgumentList.Count) { return [TaskResult]::new($this."$($step.MethodName)"()) }
            return [TaskResult]::new($this."$($step.MethodName)"($step.ArgumentList))
        }
    }
    static [Ordered] CheckRequirements([MinRequirements]$InstallReqs) {
        if (!$InstallReqs.RunAsAdmin) { $InstallReqs.IgnoredProps += "HasAdminPrivileges" }
        $h = @{
            HasEnoughRAM          = $InstallReqs.FreeMemGB -le [Setup]::GetfreRAMsize()
            HasEnoughDiskSpace    = $InstallReqs.MinDiskGB -le [math]::Round((Get-PSDrive -Name ([IO.Directory]::GetDirectoryRoot((Get-Location)))).Free / 1GB)
            HasAdminPrivileges    = $InstallReqs.RunAsAdmin -and [Setup]::IsAdmin()
            HasAllRequiredFiles   = $InstallReqs.RequiredFiles.Where({ ![IO.File]::Exists($_.FullName) }).count -eq 0
            HasAllRequiredFolders = $InstallReqs.RequiredDirectories.Where({ ![IO.Directory]::Exists($_.FullName) }).count -eq 0
        }
        Write-Verbose -Message $("Checking install requirements ...`n{0}" -f (New-Object PsObject -Property $h | Out-String).TrimEnd())
        $r = [Ordered]::new(); $h.Keys.Where({ $_ -notin $InstallReqs.IgnoredProps }).ForEach({ $r.Add($_, $h[$_]) })
        return $r
    }
    static [HostOs] GetHostOs() {
        return $(
            if ($(Get-Variable IsWindows -Value)) {
                "Windows"
            } elseif ($(Get-Variable IsLinux -Value)) {
                "Linux"
            } elseif ($(Get-Variable IsMacOS -Value)) {
                "MacOS"
            } else {
                "UNKNOWN"
            }
        )
    }
    static [bool] IsAdmin() {
        [string]$_Host_OS = [Setup]::getHostOs()
        [bool]$Isadmin = $(switch ($true) {
                $($_Host_OS -eq "Windows") {
                    $(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
                    break;
                }
                $($_Host_OS -in ("MacOS", "Linux")) {
                    $(whoami) -eq "root";
                    break;
                }
                Default {
                    Write-Warning "Unknown OS: $_Host_OS";
                    $false
                }
            }
        )
        if (!$Isadmin) { Write-Warning "[USER is not ADMIN]. This script requires administrative privileges." }
        return $Isadmin
    }
    static [int] GetfreRAMsize() {
        [string]$OsName = [Setup]::GetHostOs();
        return $(switch ($OsName) {
                "Windows" {
                    [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
                    break
                }
                "Linux" {
                    [math]::Round([int64](((& free -b) -split "`n")[1] -split "\s+")[1] / 1GB, 2)
                    break;
                }
                "MacOs" {
                    [math]::Round(((& sysctl hw.memsize) -split ' ')[1] / 1GB, 2)
                    break;
                }
                Default { throw "Unable to read memory size for OS: $OsName" }
            }
        )
    }
    hidden [void] SetSteps([hashtable]$method_args_hash) {
        $method_args_hash.Keys.ForEach({ $this.steps.Enqueue([SetupStep]::New($_, $method_args_hash[$_])) })
    }
    [InstallReport] GetInstallReport() {
        return [InstallReport]::new("$($this.Name) setup completed successfully.")
    }
}

class CboxSetup : Setup {
    [bool]$UseCloudVps = $false
    CboxSetup() {
        $this.Name = "C/C++ development environment"
        $this.SetSteps(@{
                CheckRequirements        = @()
                InstallChoco             = @()
                InstallMSYS2             = @()
                InstallGcc               = @()
                InstallClang             = @()
                InstallCMake             = @()
                PrepareVisualStudioCode  = @()
                InstallGoogleTestPackage = @()
                InstallDoxygen           = @()
                InstallGit               = @()
            }
        )
    }
    [TaskResult] Run() {
        if ($this.UseCloudVps -and $this.RunAsAdmin) {
            throw [System.InvalidOperationException]::new("Cannot run as admin on a cloud VPS")
        }
        Write-Verbose "Running setup: $($this.Name) ..."
        return $this.Run($this, $false)
    }
    [void] InstallChoco($nptargs) {
        # Install Chocolatey package manager
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    [void] InstallMSYS2($nptargs) {
        # Install MSYS2
        choco install msys2 --params = "/NoUpdate" -y

        # Add MSYS2 binaries to system PATH
        $msys2BinPath = Join-Path $env:ChocolateyInstall "lib\msys2\mingw64\bin"
        $env:Path += ";$msys2BinPath"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
    }
    [void] InstallGcc($nptargs) {
        # Install GCC and related tools
        & "$env:ChocolateyInstall\lib\msys2\tools\msys2.exe" -c "/usr/bin/bash -lc 'pacman -Syu --noconfirm'" | Out-Null
        & "$env:ChocolateyInstall\lib\msys2\tools\msys2.exe" -c "/usr/bin/bash -lc 'pacman -S --needed --noconfirm mingw-w64-x86_64-gcc mingw-w64-x86_64-make mingw-w64-x86_64-gdb'" | Out-Null
    }
    [void] InstallClang($nptargs) {
        # Install Clang
        & "$env:ChocolateyInstall\lib\msys2\tools\msys2.exe" -c "/usr/bin/bash -lc 'pacman -S --needed --noconfirm mingw-w64-x86_64-clang mingw-w64-x86_64-clang-tools-extra'" | Out-Null
    }
    [void] InstallCMake($nptargs) {
        # Install CMake
        choco install cmake --install-arguments = 'ADD_CMAKE_TO_PATH=System' -y
    }
    [void] PrepareVisualStudioCode($nptargs) {
        choco install vscode -y
        # Install C/C++ extension for VSCode
        code --install-extension ms-vscode.cpptools

        # Install CMake Tools extension for VSCode
        code --install-extension ms-vscode.cmake-tools
    }
    [void] InstallGoogleTestPackage($nptargs) {
        # Install Google Test package
        choco install vcpkg -y
        & "$env:ChocolateyInstall\lib\vcpkg\tools\vcpkg.exe" integrate install
        & "$env:ChocolateyInstall\lib\vcpkg\tools\vcpkg.exe" install gtest:x64-windows
    }
    [void] InstallDoxygen($nptargs) {
        choco install doxygen.install -y
    }
    [void] InstallGit($nptargs) {
        choco install git -y
    }
    [bool] CheckRequirements() {
        return $this.CheckRequirements(@())
    }
    [bool] CheckRequirements($nptargs) {
        $InstallReqs = [MinRequirements]::new();
        $InstallReqs.RunAsAdmin = $this.RunAsAdmin;
        $InstallReqs.RequiredFiles += "$env:ChocolateyInstall\bin\choco.exe"
        $InstallReqs.RequiredFiles += "$env:ChocolateyInstall\lib\msys2\tools\msys2.exe"
        $InstallReqs.RequiredDirectories += "$env:ChocolateyInstall\bin"
        $InstallReqs.RequiredDirectories += "$env:ChocolateyInstall\lib\msys2\tools"
        return [CboxSetup]::CheckRequirements($InstallReqs).Values -notcontains $false
    }
}
#endregion cboxclasses

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

# function New-DynamicParam {
#     param ([string]$Name, [int]$position, [type]$type)
#     process {
#         $_params = [System.Management.Automation.RuntimeDefinedParameterDictionary]::New()
#         $_params.Add($Name, [System.Management.Automation.RuntimeDefinedParameter]::new(
#                 $Name, $type, @((
#                         New-Object System.Management.Automation.ParameterAttribute -Property @{
#                             Position          = $position
#                             Mandatory         = $false
#                             ValueFromPipeline = $false
#                             ParameterSetName  = $PSCmdlet.ParameterSetName
#                             HelpMessage       = "hlp msg"
#                         }
#                     ),
#                     [System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new()
#                 )
#             )
#         )
#         return $_params
#     }
# }

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
            $TaskResult = BackgroundTask($Job, $Errors);
            $_Success = $false; $LogMsg += " Completed with errors.`n`t$errormessages`n`t$errStackTrace"
        } else {
            $TaskResult = BackgroundTask($Job)
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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()][Alias('o')]
        $InputObject,

        [Parameter(Mandatory = $false, Position = 1)]
        [Alias('s')][ValidateNotNullOrEmpty()]
        [bool]$IsSuccess = 0,

        [Parameter(Mandatory = $false, Position = 2)]
        [Alias('e')][ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    begin {
        class TaskResult {
            # .EXAMPLE
            #     New-Object TaskResult((Start-Job -ScriptBlock { start-sleep -seconds 2; return 100 }))
            [bool]$IsSuccess = $false
            [string]$JobName = [string]::Empty
            [System.Array]$ErrorRecord = @()
            hidden [System.Collections.Generic.List[String]]$Commands = @()
            [PSDataCollection[psobject]]$Output = [PSDataCollection[psobject]]::new()
            TaskResult() { $this.SetJobState() }
            TaskResult($InputObject) {
                $t = [TaskResult]::Create($InputObject)
                $this.PSObject.Properties.Name.ForEach({ $this."$_" = $t."$_" }); $this.SetJobState()
            }
            TaskResult($InputObject, [ErrorRecord]$ErrorRecord) {
                $t = [TaskResult]::Create($InputObject, $ErrorRecord)
                $this.PSObject.Properties.Name.ForEach({ $this."$_" = $t."$_" }); $this.SetJobState()
            }
            TaskResult($InputObject, [bool]$IsSuccess, [ErrorRecord]$ErrorRecord) {
                $t = [TaskResult]::Create($InputObject, $IsSuccess, $ErrorRecord)
                $this.PSObject.Properties.Name.ForEach({ $this."$_" = $t."$_" }); $this.SetJobState()
            }
            static [TaskResult] Create($InputObject) {
                if ($InputObject -is [array]) {
                    Write-Verbose "InputObject is an array"
                    $_Params = [hashtable]::new()
                    $_Params.IsSuccess = $InputObject.Where({ $_ -is [bool] });
                    $_Params.ErrorRecord = $InputObject.Where({ $_ -is [ErrorRecord] });
                    $_Params.InputObject = $InputObject[0];
                    return [TaskResult]::Create($_Params.InputObject, $_Params.IsSuccess, $_Params.ErrorRecord)
                }
                return [TaskResult]::Create($InputObject, $false, $null)
            }
            static [TaskResult] Create($InputObject, [ErrorRecord]$ErrorRecord) {
                return [TaskResult]::Create($InputObject, $false, $ErrorRecord)
            }
            static [TaskResult] Create($InputObject, [bool]$IsSuccess, [ErrorRecord]$ErrorRecord) {
                $tresult = [TaskResult]::new(); $err = $null; if ($null -eq $InputObject) { $InputObject = [PSObject]::new() }
                if ($null -ne $ErrorRecord) { $tresult.ErrorRecord += $ErrorRecord };
                if ($InputObject -is [job]) {
                    $tresult.JobName = $InputObject.Name;
                    $tresult.Commands.Add($InputObject.Command) | Out-Null
                    $InputObject = $InputObject.ChildJobs | Receive-Job -Wait -ErrorAction SilentlyContinue -ErrorVariable Err
                    $tresult.IsSuccess = $null -eq $Err; if (!$tresult.IsSuccess) { $tresult.ErrorRecord += $err }
                    if ($InputObject -is [bool]) { $tresult.IsSuccess = $InputObject }
                }
                $tresult.Output.Add($InputObject) | Out-Null
                $tresult.SetJobState()
                $tresult.IsSuccess = $tresult.ErrorRecord.Count -eq 0 -and $($tresult.State -ne "Failed")
                return $tresult
            }
            [void] SetJobState() {
                $this.PsObject.Properties.Add([psscriptproperty]::new('State', { return $(switch ($true) { $(![string]::IsNullOrWhiteSpace($this.JobName)) { $(Get-Job -Name $this.JobName).State.ToString(); break } $($this.IsSuccess) { "Completed"; break } Default { "Failed" } }) }, { throw [System.InvalidOperationException]::new("Cannot set State") }))
            }
        }
        $_BoundParams = [hashtable]$PSCmdlet.MyInvocation.BoundParameters
        if ($InputObject -is [array] -and (!$IsSuccess.IsPresent -and !$ErrorRecord)) {
            $_BoundParams.IsSuccess = $InputObject.Where({ $_ -is [bool] });
            $_BoundParams.ErrorRecord = $InputObject.Where({ $_ -is [System.Management.Automation.ErrorRecord] });
            $_BoundParams.InputObject = $InputObject[0]
        }
        $tresult = [TaskResult]::new()
    }

    process {
        if ($null -eq $InputObject) { $InputObject = New-Object PSObject }
        if ($InputObject -is [job]) {
            $tresult.JobName = $InputObject.Name
            $tresult.Commands.Add($InputObject.Command) | Out-Null
            $_output = $InputObject.ChildJobs | Receive-Job -Wait -ErrorAction SilentlyContinue -ErrorVariable Err
            $_BoundParams.ErrorRecord = $Err; $tresult.IsSuccess = $null -eq $Err
            if ($_output -is [bool]) { $tresult.IsSuccess = $_output }
            $tresult.Output.Add($_output) | Out-Null
        } else {
            [void]$tresult.Output.Add($InputObject);
        }
        $_HasErrors = $null -ne $_BoundParams.ErrorRecord -or $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('ErrorRecord')
        if ($_HasErrors) { $tresult.ErrorRecord = $_BoundParams.ErrorRecord }; $tresult.SetJobState()
        $tresult.IsSuccess = !$_HasErrors -and $($tresult.State -ne "Failed")
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