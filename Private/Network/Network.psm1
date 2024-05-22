class DownloadOptions {
    [bool]$ShowProgress = $true
    [int]$ProgressBarLength = [int]([Console]::WindowWidth * 0.7)
    [string]$ProgressMessage = [string]::Empty
    [int]$RetryTimeout = 1000 #(milliseconds)
    [hashtable]$Headers = @{}
    [System.Object]$Proxy = $null
    [bool]$Force = $false
    static [DownloadOptions]$currentOptions
    DownloadOptions() {}
}

class NetworkManager {
    [string] $HostName
    static [System.Net.IPAddress[]] $IPAddresses
    static [DownloadOptions] $DownloadOptions = [DownloadOptions]::new()
    NetworkManager() {}
    NetworkManager ([string]$HostName) {
        $this.HostName = $HostName
        $this::IPAddresses = [System.Net.Dns]::GetHostAddresses($HostName)
    }
    static [string] GetResponse ([string]$URL) {
        [System.Net.HttpWebRequest]$Request = [System.Net.HttpWebRequest]::Create($URL)
        $Request.Method = "GET"
        $Request.Timeout = 10000 # 10 seconds
        [System.Net.HttpWebResponse]$Response = [System.Net.HttpWebResponse]$Request.GetResponse()
        if ($Response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
            [System.IO.Stream]$ReceiveStream = $Response.GetResponseStream()
            [System.IO.StreamReader]$ReadStream = [System.IO.StreamReader]::new($ReceiveStream)
            [string]$Content = $ReadStream.ReadToEnd()
            $ReadStream.Close()
            $Response.Close()
            return $Content
        } else {
            throw "The request failed with status code: $($Response.StatusCode)"
        }
    }
    static [void] UploadFile ([string]$SourcePath, [string]$DestinationURL) {
        Invoke-RestMethod -Uri $DestinationURL -Method Post -InFile $SourcePath
    }
    static [bool] Resolve_Ping_Dependencies () {
        # Prevent: error: System.PlatformNotSupportedException : The system's ping utility could not be found.
        # https://github.com/dotnet/runtime/issues/28572
        $result = [bool](Get-Command ping -ea SilentlyContinue)
        if ($result) { return $result }
        $HostOS = Get-HostOs
        switch ($HostOS) {
            "Linux" {
                $osID = (Get-Content -Path '/etc/os-release' | Where-Object { $_ -match '^ID=' }).Split('=')[1]
                [bool]$IsPingInstalled = ![string]::IsNullOrWhiteSpace($([string](which ping))); $result = $IsPingInstalled
                if (!$IsPingInstalled) {
                    Write-Host "[NetworkManager] Ping is not installed. Installing it now ..." -f Yellow
                    switch ($osID) {
                        "ubuntu" { sudo apt-get install iputils-ping }
                        "debian" { sudo apt-get install iputils-ping }
                        "fedora" { sudo dnf install iputils }
                        "centos" { sudo yum install iputils }
                        "rhel" { sudo yum install iputils }
                        "arch" { sudo pacman -S iputils }
                        "opensuse" { sudo zypper install iputils }
                        "alpine" { sudo apk add iputils }
                        Default { throw "Unsupported distribution: $osID" }
                    }
                    $result = $?
                    $IsBinInPATH = $env:PATH -split ':' -contains '/bin'
                    if (!$IsBinInPATH) {
                        Write-Output 'export PATH=$PATH:/bin' >> ~/.bashrc
                        source ~/.bashrc
                    }
                }
            }
            "Windows" {
                $result = $true
            }
            Default {
                Write-Host "[NetworkManager] Ping could not be installed on HostOS : $HostOS. Please install it manually."
            }
        }
        return $result
    }
    static [bool] TestConnection ([string]$HostName) {
        throw 'eerr'
    }
}

function Start-FileDownload {
    [CmdletBinding()]
    [OutputType([IO.FileInfo])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][Alias('l')]
        [uri]$url,

        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateScript({
                if ([string]::IsNullOrWhiteSpace($_)) {
                    throw [System.ArgumentNullException]::new("outFile", "Please provide a valid file path")
                }
            }
        )][Alias('o')]
        [string]$outFile
    )
    begin {
        if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('OutFile')) {
            # No $outFile? we create one ourselves, and use suffix to prevent duplicaltes
            $randomSuffix = [Guid]::NewGuid().Guid.subString(15).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
            $outFile = "$(Split-Path $url.AbsolutePath -Leaf)_$randomSuffix"
        }
    }

    process {
        $stream = $null; $fileStream = $null; $name = Split-Path $url -Leaf;
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0"
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 1024
        $outPath = (CryptoBase)::GetUnResolvedPath($outFile)
        if ([System.IO.Directory]::Exists($outFile)) {
            if (!$Force) { throw [System.ArgumentException]::new("Please provide valid file path, not a directory.", "outFile") }
            $outPath = Join-Path -Path $outFile -ChildPath $name
        }
        $Outdir = [IO.Path]::GetDirectoryName($outPath)
        if (![System.IO.Directory]::Exists($Outdir)) { [void][System.IO.Directory]::CreateDirectory($Outdir) }
        if ([IO.File]::Exists($outPath)) {
            if (!$Force) { throw "$outFile already exists" }
            Remove-Item $outPath -Force -ErrorAction Ignore | Out-Null
        }
        $fileStream = [System.IO.FileStream]::new($outPath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $totalBytesReceived = 0
        $totalBytesToReceive = $contentLength
        $OgForeground = (Get-Variable host).Value.UI.RawUI.ForegroundColor
        $Progress_Msg = [NetworkManager]::DownloadOptions.ProgressMessage
        if ([string]::IsNullOrWhiteSpace($Progress_Msg)) { $Progress_Msg = "[+] Downloading $name to $Outfile" }
        Write-Host $Progress_Msg -f Magenta
        (Get-Variable host).Value.UI.RawUI.ForegroundColor = [ConsoleColor]::Green
        while ($totalBytesToReceive -gt 0) {
            $bytesRead = $stream.Read($buffer, 0, 1024)
            $totalBytesReceived += $bytesRead
            $totalBytesToReceive -= $bytesRead
            $fileStream.Write($buffer, 0, $bytesRead)
            if ([NetworkManager]::DownloadOptions.ShowProgress) {
                Write-ProgressBar -p ([int]($totalBytesReceived / $contentLength * 100)) -l ([NetworkManager]::DownloadOptions.progressBarLength) -Update
            }
        }
        (Get-Variable host).Value.UI.RawUI.ForegroundColor = $OgForeground
        try { Invoke-Command -ScriptBlock { $stream.Close(); $fileStream.Close() } -ErrorAction SilentlyContinue } catch { $null }
    }

    end {
        return (Get-Item $outFile)
    }
}

function Set-DownloadOptions {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Options
    )
    process {
        if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Options')) {
            [DownloadOptions]::currentOptions = [DownloadOptions]::new()
        } else {
            $Options.Keys.ForEach({
                    [DownloadOptions]::currentOptions."$_" = $Options."$_"
                }
            )
        }
    }
}
function Get-DownloadOption {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    end {
        return [DownloadOptions]::currentOptions."$Name"
    }
}

function Block-AllOutboundConnections {
    [CmdletBinding()]
    [OutputType([void])]
    param ()

    process {
        $HostOs = Get-HostOs
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT DROP
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, blockoutbound
        }
    }
}

function Unblock-AllOutboundConnections {
    [CmdletBinding()]
    param ()
    process {
        $HostOs = Get-HostOs
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT ACCEPT
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, allowoutbound
        }
    }
}

function CheckConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('host')]
        [string]$HostName,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('msg')]
        [string]$Message = "Testing Connection"
    )

    begin {
        $results = $null;
        $tscript = [scriptblock]::Create({
                $cs = $null; $re = @{ true = @{ m = ' Success'; c = 'Green' }; false = @{ m = ' Failed'; c = 'Red' } }
                if (![bool]('System.Net.NetworkInformation.Ping' -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
                try {
                    [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("google.com");
                    $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
                } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
                    $cs = $false
                } catch {
                    $cs = $false;
                    Write-Error $_
                }
                $re = $re[$cs.ToString()]
                Write-Host $re.m -f $re.c
                return $cs
            }
        )
    }

    process {
        $cc = Show-Stack;
        $tscrSRC = $tscript.Ast.Extent.Text.Replace("google.com", $HostName, $true, [CultureInfo]::CurrentCulture)
        $tscript = [scriptblock]::Create("$tscrSRC")
        if (![NetworkManager]::resolve_ping_dependencies()) {
            ('{0} Could not resolve ping dependencies' -f $cc) | Write-Host -f Red
        }
        $results = Wait-Task -m $Message -s $tscript
    }

    end {
        return $results
    }
}
Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")