﻿#region Compile C# Type
Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Runtime.InteropServices;
public class NetStat
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_CLASS tblClass, int reserved);
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        MIB_TCPROW_OWNER_PID table;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        MIB_UDPROW_OWNER_PID table;
    }
    enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }
    enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_OWNER_MODULE
    }
    public enum State
    {
        Closed,
        Listening,
        SynSent,
        SynReceived,
        Established,
        Finished1,
        Finished2,
        CloseWait,
        Closing,
        LastAcknowledge,
        TimeWait,
        DeleteTcb,
        Unknown
    }
    public static Connection[] GetTCP()
    {
        MIB_TCPROW_OWNER_PID[] tTable;
        int AF_INET = 2;
        int buffSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buffTable = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedTcpTable(buffTable, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0)
            {
                Connection[] con = new Connection[0];
                return con;
            }
            MIB_TCPTABLE_OWNER_PID tab = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(buffTable, typeof(MIB_TCPTABLE_OWNER_PID));
            IntPtr rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(tab.dwNumEntries));
            tTable = new MIB_TCPROW_OWNER_PID[tab.dwNumEntries];
            for (int i = 0; i < tab.dwNumEntries; i++)
            {
                MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                tTable[i] = tcpRow;
                rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));   // next entry
            }
        }
        finally
        { Marshal.FreeHGlobal(buffTable); }
        Connection[] cons = new Connection[tTable.Length];
        for (int i = 0; i < tTable.Length; i++)
        {
            IPAddress localip = new IPAddress(BitConverter.GetBytes(tTable[i].dwLocalAddr));
            IPAddress remoteip = new IPAddress(BitConverter.GetBytes(tTable[i].dwRemoteAddr));
            byte[] barray = BitConverter.GetBytes(tTable[i].dwLocalPort);
            int localport = (barray[0] * 256) + barray[1];
            barray = BitConverter.GetBytes(tTable[i].dwRemotePort);
            int remoteport = (barray[0] * 256) + barray[1];
            State state;
            switch (tTable[i].dwState)
            {
                case 1:
                    state = State.Closed;
                    break;
                case 2:
                    state = State.Listening;
                    break;
                case 3:
                    state = State.SynSent;
                    break;
                case 4:
                    state = State.SynReceived;
                    break;
                case 5:
                    state = State.Established;
                    break;
                case 6:
                    state = State.Finished1;
                    break;
                case 7:
                    state = State.Finished2;
                    break;
                case 8:
                    state = State.CloseWait;
                    break;
                case 9:
                    state = State.Closing;
                    break;
                case 10:
                    state = State.LastAcknowledge;
                    break;
                case 11:
                    state = State.TimeWait;
                    break;
                case 12:
                    state = State.DeleteTcb;
                    break;
                default:
                    state = State.Unknown;
                    break;
            }
            Connection tmp = new Connection(localip, localport, remoteip, remoteport, (int)tTable[i].dwOwningPid, state);
            cons[i] = (tmp);
        }
        return cons;
    }
    public static Connection[] GetUDP()
    {
        MIB_UDPROW_OWNER_PID[] tTable;
        int AF_INET = 2; // IP_v4
        int buffSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        IntPtr buffTable = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedUdpTable(buffTable, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0)
            {//none found
                Connection[] con = new Connection[0];
                return con;
            }
            MIB_UDPTABLE_OWNER_PID tab = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(buffTable, typeof(MIB_UDPTABLE_OWNER_PID));
            IntPtr rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(tab.dwNumEntries));
            tTable = new MIB_UDPROW_OWNER_PID[tab.dwNumEntries];

            for (int i = 0; i < tab.dwNumEntries; i++)
            {
                MIB_UDPROW_OWNER_PID udprow = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                tTable[i] = udprow;
                rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(udprow));
            }
        }
        finally
        { Marshal.FreeHGlobal(buffTable); }
        Connection[] cons = new Connection[tTable.Length];
        for (int i = 0; i < tTable.Length; i++)
        {
            IPAddress localip = new IPAddress(BitConverter.GetBytes(tTable[i].dwLocalAddr));
            byte[] barray = BitConverter.GetBytes(tTable[i].dwLocalPort);
            int localport = (barray[0] * 256) + barray[1];
            Connection tmp = new Connection(localip, localport, (int)tTable[i].dwOwningPid);
            cons[i] = tmp;
        }
        return cons;
    }
}
public class Connection
{
    private IPAddress _localip, _remoteip;
    private int _localport, _remoteport, _pid;
    private NetStat.State _state;
    private string _proto;
    public Connection(IPAddress Local, int LocalPort, IPAddress Remote, int RemotePort, int PID, NetStat.State State)
    {
        _proto = "TCP";
        _localip = Local;
        _remoteip = Remote;
        _localport = LocalPort;
        _remoteport = RemotePort;
        _pid = PID;
        _state = State;
    }
    public Connection(IPAddress Local, int LocalPort, int PID)
    {
        _proto = "UDP";
        _localip = Local;
        _localport = LocalPort;
        _pid = PID;
    }
    public IPAddress LocalIP { get { return _localip; } }
    public IPAddress RemoteIP { get { return _remoteip; } }
    public int LocalPort { get { return _localport; } }
    public int RemotePort { get { return _remoteport; } }
    public int PID { get { return _pid; } }
    public NetStat.State State { get { return _state; } }
    public string Protocol { get { return _proto; } }
    public string PIDName { get { return (System.Diagnostics.Process.GetProcessById(_pid)).ProcessName; } }
}
"@
#endregion

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
    static [bool] TryResolvePingUtility () {
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

function Resolve-PingDependencies {
    # .SYNOPSIS
    #     Prevents error: System.PlatformNotSupportedException : The system's ping utility could not be found.
    # .DESCRIPTION
    #     Installs ping utility if not installed
    # .LINK
    #     https://github.com/dotnet/runtime/issues/28572
    [CmdletBinding()]
    [OutputType([bool])]
    param ()
    process {
        return [NetworkManager]::TryResolvePingUtility()
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
    # .EXAMPLE
    #     CheckConnection -host "github.com" -msg "[ProgramName] Check if offline" -IsOffline
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('host')]
        [string]$HostName,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('msg')]
        [string]$Message = "Testing Connection",

        [Parameter(Mandatory = $true, ParameterSetName = 'IsOnline')]
        [switch]$IsOnline,

        [Parameter(Mandatory = $true, ParameterSetName = 'IsOffline')]
        [switch]$IsOffline
    )

    begin {
        if ($IsOnline.IsPresent -and $IsOffline.IsPresent) {
            Throw [System.Management.Automation.ParameterBindingException]::new('Can not use IsOnline and IsOffline SwitchParameters at the same time!')
        }
        $results = $null; $re = @{ true = @{ m = ''; c = 'Green' }; false = @{ m = ' Failed'; c = 'Red' } }
        $tscript = [scriptblock]::Create({
                # .SYNOPSIS
                # Returns conection state as a boolean
                $cs = $null; ; if (![bool]('System.Net.NetworkInformation.Ping' -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
                try {
                    [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("google.com");
                    $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
                } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
                    $cs = $false
                } catch {
                    $cs = $false;
                    Write-Error $_
                }
                return $cs
            }
        )
    }

    process {
        $tscrSRC = $tscript.Ast.Extent.Text.Replace("google.com", $HostName, $true, [CultureInfo]::CurrentCulture)
        $tscript = [scriptblock]::Create("$tscrSRC")
        if (!(Resolve-PingDependencies)) { Write-Host "$(Show-Stack) Could not resolve ping dependencies" -f Red }
        $results = Wait-Task -m "$Message" -s $tscript
        if ($IsOnline.IsPresent) {
            $results.Output = $results.Output -as [bool]
        }
        if ($IsOffline.IsPresent) {
            $results.Output = !$results.Output
        }
        $re = $re[$results.Output.ToString()]
        Write-Host $re.m -f $re.c
    }

    end {
        return $results
    }
}

function Resolve-HostNameProperty {
    # .SYNOPSIS
    #   Batch-resolves IP addresses to host names
    # .DESCRIPTION
    #   Takes *any* object and resolves IP addresses in *any* of its properties
    # .PARAMETER Property
    #   List of properties to resolve. Can be one property name or a comma-separated list
    # .PARAMETER ThrottleLimit
    #   Number of parallel threads. Defaults to 80.
    # .PARAMETER InputObject
    #   The object with the properties to resolve
    # .PARAMETER PassThru
    #   When specified, no resolution takes place, and the objects are passed through unchanged
    #   This can be useful if you want to use this command inside a pipeline and resolve based on
    #   some user-submitted parameter.
    # .EXAMPLE
    #   1..255 | ForEach-Object { [PSCustomObject]@{IP1 = "192.168.2.$_"; IP2 = "40.112.72.$_" } } | Resolve-HostNameProperty -Property IP1, IP2
    #   Creates dummy objects with properties IP1 and IP2 containing dummy IP addresses.
    #   Next,properties IP1 and IP2 of all of these objects are resolved.
    #   This typically would take many minutes. Thanks to caching and multithreading, it takes only a few seconds.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Property,

        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 80,

        [switch]$PassThru
    )

    begin {
        # if the user specified -PassThru then do nothing special, pass incoming objects on
        if ($PassThru.IsPresent -eq $false) {
            # else, set up multithreading with a runspace pool for queueing:
            $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $state, $Host)
            $pool.Open()

            # thread-safe dictionary to cache resolved IP addresses and not resolve repeating IP addresses again:
            $cache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()

            # list of background threads:
            $threads = [System.Collections.ArrayList]::new()

            # code to be executed inside a background thread:
            $ScriptBlock = {
                # .SYNOPSIS
                #  Takes object, list of properties to resolve, and reference to
                #  DNS cache dictionary:
                param($object, $property, $lookup)
                foreach ($name in $property) {
                    # read property content as string:
                    $value = $object.$name.ToString()
                    # if it is not empty...
                    if ([string]::IsNullOrEmpty($value) -eq $false) {
                        if ($lookup.ContainsKey($value) -eq $false) {
                            # if the content is new...
                            # ...try and resolve the new content first:
                            $lookup[$value] = try { [System.Net.Dns]::GetHostEntry($value).HostName } catch { $value }
                        }
                        if ($value -ne $lookup[$value]) {
                            # if the content can be resolved...
                            $object | Add-Member -MemberType NoteProperty -Name $name -Value $lookup[$value] -Force
                        }
                    }
                }
                return $object
            }

            # function checks threads in the background to see if there are any
            # pending, and to see if there are results reads to get:
            function Get-Results {
                # when -Wait is specified, waits for the last thread to finish before it returns:
                param([switch]$wait)

                # when -Wait is specified, iterate until all threads are finished and no more
                # data needs to be retrieved. Without -Wait, the loop runs only once:
                do {
                    $hasdata = $false
                    # check each background thread:
                    foreach ($thread in $threads) {
                        # for any thread that has completed...
                        if ($null -ne $thread.Handle -and $thread.Handle.isCompleted) {
                            # read the results the thread produced:
                            $thread.powershell.EndInvoke($thread.Handle)
                            # remove the thread from memory:
                            $thread.powershell.dispose()
                            # blank the thread in the $threads list:
                            $thread.Handle = $null
                            $thread.powershell = $null
                        } elseif ($null -ne $thread.Handle) {
                            # if there are any threads that haven't completed,
                            # set a flag indicating that we need to check again later:
                            $hasdata = $true
                        }
                    }
                    # if there is going to be a reiteration, wait 100ms before checking again:
                    if ($hasdata -and $wait) { Start-Sleep -Milliseconds 100 }
                    # repeat if -Wait was specified and there are still threads pending:
                } while ($hasdata -and $wait)
            }
        }
    }

    process {
        # take any number of objects via the pipeline OR the parameter -InputObject:
        foreach ($object in $InputObject) {
            if ($PassThru.IsPresent) {
                $object
            } else {
                # Do object manipulation (resolving) in a background thread:
                # create a new background thread, add the prepared scriptblock, and submit the
                # arguments to it:
                $p = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($_).AddArgument($Property).AddArgument($cache)
                # attach the runspace pool to it so the background thread won't run by itself but instead is queued
                # and uses a thread from the pool one one becomes available:
                $p.RunspacePool = $pool
                # remember the background thread so we can check its state later:
                $rv = [PSCustomObject]@{
                    PowerShell = $p
                    Handle     = $p.BeginInvoke()
                }
                # save the thread info in the threads list:
                [void]$threads.Add($rv)

                # go check whether there are results reads from any of the previously
                # launched threads by chance:
                Get-Results
            }
        }
    }

    end {
        # if -PassThru was NOT specified...
        if ($PassThru.IsPresent -eq $false) {
            # ...check a last time for pending background jobs, and this time *wait*
            # until all background threads have been completed:
            Get-Results -Wait
            # close the pool:
            $pool.Close()
        }
    }
}

function Get-NetStat {
    # .SYNOPSIS
    #   Implements part of the functionality found in netstat.exe on Windows
    #   based on .NET Core so it runs cross-platform

    # .DESCRIPTION
    #   returns list of connections and ports

    # .PARAMETER LocalPort
    #   Lists all connections with the specified local port

    # .PARAMETER RemotePort
    #   Lists all connections with the specified remote port

    # .PARAMETER State
    #   Describe parameter -State.

    # .PARAMETER PidName
    #   Lists all connections with the specified state

    # .PARAMETER ProcessId
    #   Lists all connections with the specified process id

    # .PARAMETER TCP
    #   Limit to TCP connections only

    # .PARAMETER UDP
    #   Limit to UDP connections only

    # .PARAMETER Resolve
    #   Resolve ip addresses to host names

    # .PARAMETER IncludeOrigin
    #   Reports remote ip address owner information

    # .EXAMPLE
    #   Get-NetStat
    #   Lists all connections and ports

    # .EXAMPLE
    #   Get-NetStat -Resolve -IncludeOrigin
    #   Lists all connections and ports, resolves IP addresses, and includes owner information for remote ip addresses.

    # .EXAMPLE
    #   Get-NetStat -TCP
    #   Lists TCP connections and ports

    # .EXAMPLE
    #   Get-NetStat -LocalPort 5985
    #   Checks local port 5985 (PowerShell Remoting) to see whether it is accepting incoming requests

    # .EXAMPLE
    #   (Get-NetStat -LocalPort 5985).State -eq [NetStat+State]::Listening
    #   Check whether PowerShell Remoting port 5985 is in state "Listening"

    # .EXAMPLE
    #   Get-NetStat -State Listening
    #   List all ports in state "Listening"

    # .EXAMPLE
    #   Get-NetStat -State Established -Resolve
    #   List all established connections, and resolve local and remote IP addresses to host names

    # .EXAMPLE
    #   Get-NetStat -PidName chrome -Resolve
    #   List all connections used by the "chrome" browser, and resolve IP addresses

    # .NOTES
    #   When -Resolve is specified, both LocalIP and RemoteIP is resolved. DNS resolution typically is slow
    #   (especially for non-responding systems). Thats why multithreading is used with support for up to
    #   80 parallel name resolutions.
    [CmdletBinding(DefaultParameterSetName = 'TCP')]
    param(
        [Parameter(Mandatory = $false)]
        [UInt16]$LocalPort,

        [Parameter(Mandatory = $false)]
        [UInt16]$RemotePort,

        [Parameter(Mandatory = $false)]
        [NetStat+State]$State,

        [Parameter(Mandatory = $false)]
        [string]$PidName,

        [Parameter(Mandatory = $false)]
        [Alias('Pid')]
        [int]$ProcessId,

        [Parameter(ParameterSetName = 'TCP')]
        [switch]$TCP,

        [Parameter(ParameterSetName = 'UDP')]
        [switch]$UDP,

        [switch]$Resolve,

        [switch]$IncludeOrigin
    )

    # there are TWO sources for information: GetTCP() and GetUDP().
    # I'd like to output either both or just one of them, based on user parameters
    # a great trick to do so is to place the calls into a scriptblock and
    # call it with "&".
    & {
        if (!$UDP) { [Netstat]::GetTCP() }
        if (!$TCP) { [Netstat]::GetUDP() }
    } |
        # for convenience, a function should always include the most commonly used
        # where-object filters so the user doesn't have to add code
        # as a best practice, the filter parameters should be named like the
        # properties that they filter.
        # the filter will be active ONLY when the user specified the appropriate
        # filter parameter:
        Where-Object { (!$PSBoundParameters.ContainsKey('LocalPort')) -or ($_.LocalPort -eq $LocalPort) } |
        Where-Object { (!$PSBoundParameters.ContainsKey('RemotePort')) -or ($_.RemotePort -eq $RemotePort) } |
        Where-Object { (!$PSBoundParameters.ContainsKey('State')) -or ($_.State -eq $State) } |
        Where-Object { (!$PSBoundParameters.ContainsKey('PidName')) -or ($_.PidName -like $PidName) } |
        Where-Object { (!$PSBoundParameters.ContainsKey('ProcessId')) -or ($_.Pid -eq $ProcessId) } |
        # if -IncludeOrigin is specified, query the origin information by a webservice
        ForEach-Object {
            $origin = ''
            if ($IncludeOrigin) {
                $_.PSTypeNames.Add('connectionOrigin')
                $null = $_.PSTypeNames.Remove('Connection')
                try {
                    $ip = $_.RemoteIp
                    if ([string]::IsNullOrEmpty($ip) -eq $false -and ($ip -ne '0.0.0.0') -and ([System.Net.IPAddress]::IsLoopback($ip) -eq $false)) {
                        $info = Invoke-RestMethod -Uri "http://ipinfo.io/$ip/json" -UseBasicParsing -ErrorAction Ignore
                        $origin = $info.org.Trim()
                    }
                } catch {}
            }
            $_ | Add-Member -MemberType NoteProperty -Name Origin -Value $origin -PassThru
        } | Resolve-HostNameProperty -Property RemoteIp, LocalIp -PassThru:$(!$Resolve.IsPresent)
    # this command takes ANY object and tries to resolve ANY property.
    # In this specific case, the properties RemoteIp and LocalIp will be resolved
    # The command uses multithreading to resolve up to 80 host names in parallel
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")