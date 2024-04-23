using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Runtime.InteropServices

#Requires -Version 5.1
#reson: https://learn.microsoft.com/en-us/answers/questions/444991/powershell-system-security-cryptography-aesgcm-not

# Load localizedData:
$dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine((Get-Variable -ValueOnly ExecutionContext).SessionState.path.CurrentLocation.Path, "en-US", "argoncage.strings.psd1"))
if ($dataFile.Exists) {
    $script:localizedData = [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke()
} else {
    Write-Warning 'FileNotFound: Unable to find the LocalizedData file argoncage.strings.psd1.'
}
#region    Classes
#region    enums

enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}
enum keyStoreMode {
    Vault
    KeyFile
    SecureString
}
enum KeyExportPolicy {
    NonExportable
    ExportableEncrypted
    Exportable
}
enum KeyProtection {
    None
    Protect
    ProtectHigh
    ProtectFingerPrint
}
enum KeyUsage {
    None
    EncipherOnly
    CRLSign
    CertSign
    KeyAgreement
    DataEncipherment
    KeyEncipherment
    NonRepudiation
    DigitalSignature
    DecipherOnly
}
enum ExpType {
    Milliseconds
    Years
    Months
    Days
    Hours
    Minutes
    Seconds
}
# Only Encryption algorithms that are widely trusted and used in real-world
enum CryptoAlgorithm {
    AesGCM # AES-GCM (Galois/Counter Mode). A strong encryption on its own that doesn't necessarily with its built-in authentication functions. Its a mode of operation for AES that provides both confidentiality and authenticity for the encrypted data. GCM provides faster encryption and decryption compared to CBC mode and is widely used for secure communication, especially in VPN and TLS/SSL apps.
    ChaCha20 # ChaCha20 + SHA256 in this case. I would prefer ChaCha20Poly1305 but the Poly1305 class is still not working/usable. But no wories, ChaCha20 is like the salsa of the cryptography world, it's got the moves to keep your data secure and grooving to its own beat! :) Get it? [ref] to the dance-like steps performed in the algorithm's mixing process? Nevermind ... Its a symmetric key encryption algorithm, based on salsa20 algorithm. ChaCha20 provides the encryption, while Poly1305 (or SHA256 in this case) provides the authentication. This combination provides both confidentiality and authenticity for the encrypted data.
    RsaAesHMAC # RSA + AES + HMAC: This combination uses RSA for key exchange, AES for encryption, and HMAC (hash-based message authentication code) for authentication. This provides a secure mechanism for exchanging keys and encrypting data, as well as a way to verify the authenticity of the data. ie: By combining RSA and AES, one can take advantage of both algorithms' strengths: RSA is used to securely exchange the AES key, while AES is be used for the actual encryption and decryption of the data. This way, RSA provides security for key exchange, and AES provides fast encryption and decryption for the data.
    RsaECDSA # RSA + ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
    RsaOAEP # RSA-OAEP (Optimal Asymmetric Encryption Padding)
}
# System.Security.Cryptography.RSAEncryptionPadding Names
enum RSAPadding {
    Pkcs1
    OaepSHA1
    OaepSHA256
    OaepSHA384
    OaepSHA512
}
enum Compression {
    Gzip
    Deflate
    ZLib
    # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}

enum CredType {
    Generic = 1
    DomainPassword = 2
    DomainCertificate = 3
    DomainVisiblePassword = 4
    GenericCertificate = 5
    DomainExtended = 6
    Maximum = 7
    MaximumEx = 1007 # (Maximum + 1000)
}

enum CredentialPersistence {
    Session = 1
    LocalComputer = 2
    Enterprise = 3
}

#endregion enums

class InvalidArgumentException : System.Exception {
    [string]$paramName
    [string]$Message
    InvalidArgumentException() {
        $this.message = 'Invalid argument'
    }
    InvalidArgumentException([string]$paramName) {
        $this.paramName = $paramName
        $this.message = "Invalid argument: $paramName"
    }
    InvalidArgumentException([string]$paramName, [string]$message) {
        $this.paramName = $paramName
        $this.message = $message
    }
}

# Static class for calling the native credential functions
class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
    [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
    CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
    CredentialNotFoundException([string]$message) { $this.Message = $message }
    CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
    CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [System.Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}
class IntegrityCheckFailedException : System.Exception {
    [string]$Message; [Exception]$InnerException;
    IntegrityCheckFailedException() { }
    IntegrityCheckFailedException([string]$message) { $this.Message = $message }
    IntegrityCheckFailedException([string]$message, [Exception]$innerException) { $this.Message = $message; $this.InnerException = $innerException }
}
class InvalidPasswordException : System.Exception {
    [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [System.Exception]$InnerException
    InvalidPasswordException() { $this.Message = "Invalid password" }
    InvalidPasswordException([string]$Message) { $this.message = $Message }
    InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [string]$Passw0rd, [System.Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
    InvalidPasswordException([string]$Message, [securestring]$Password, [System.Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
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
# [progressUtil]::WaitJob("waiting", { Start-Sleep -Seconds 3 })
#
class ProgressUtil {
    static hidden [string] $_block = '■';
    static hidden [string] $_back = "`b";
    static hidden [string[]] $_twirl = @(
        "+■0", "-\\|/", "|/-\\"
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
    static [System.Management.Automation.Job] WaitJob([string]$progressMsg, [scriptblock]$Job) {
        return [ProgressUtil]::WaitJob($progressMsg, $(Start-Job -ScriptBlock $Job))
    }
    static [System.Management.Automation.Job] WaitJob([string]$progressMsg, [System.Management.Automation.Job]$Job) {
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
        Write-Host "`b$progressMsg ... " -NoNewline -f Magenta
        [System.Management.Automation.Runspaces.RemotingErrorRecord[]]$Errors = $Job.ChildJobs.Where({
                $null -ne $_.Error
            }
        ).Error;
        if ($Job.JobStateInfo.State -eq "Failed" -or $Errors.Count -gt 0) {
            $errormessages = [string]::Empty
            if ($null -ne $Errors) {
                $errormessages = $Errors.Exception.Message -join "`n"
            }
            Write-Host "Completed with errors.`n`t$errormessages" -f Red
        } else {
            Write-Host "Done." -f Green
        }
        [Console]::CursorVisible = $true;
        return $Job
    }
}
class NetworkManager {
    [string] $HostName
    static [System.Net.IPAddress[]] $IPAddresses
    static [RecordMap] $DownloadOptions = [RecordMap]::New(@{
            ShowProgress      = $true
            ProgressBarLength = [int]([Console]::WindowWidth * 0.7)
            ProgressMessage   = [string]::Empty
            RetryTimeout      = 1000 #(milliseconds)
            Headers           = @{}
            Proxy             = $null
            Force             = $false
        }
    )
    static [string] $caller

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
    static [void] BlockAllOutbound() {
        $HostOs = [cryptobase]::Get_Host_Os()
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT DROP
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, blockoutbound
        }
    }
    static [void] UnblockAllOutbound() {
        $HostOs = [cryptobase]::Get_Host_Os()
        if ($HostOs -eq "Linux") {
            sudo iptables -P OUTPUT ACCEPT
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound, allowoutbound
        }
    }
    static [IO.FileInfo] DownloadFile([uri]$url) {
        # No $outFile so we create ones ourselves, and use suffix to prevent duplicaltes
        $randomSuffix = [Guid]::NewGuid().Guid.subString(15).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
        return [NetworkManager]::DownloadFile($url, "$(Split-Path $url.AbsolutePath -Leaf)_$randomSuffix");
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile) {
        return [NetworkManager]::DownloadFile($url, $outFile, $false)
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile, [bool]$Force) {
        [ValidateNotNullOrEmpty()][uri]$url = $url; [ValidateNotNull()][bool]$Force = ($Force -as [bool])
        [ValidateNotNullOrEmpty()][string]$outFile = $outFile; $stream = $null;
        $fileStream = $null; $name = Split-Path $url -Leaf;
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0"
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 1024
        $outPath = [CryptoBase]::GetUnResolvedPath($outFile)
        if ([System.IO.Directory]::Exists($outFile)) {
            if (!$Force) { throw [InvalidArgumentException]::new("outFile", "Please provide valid file path, not a directory.") }
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
                [ProgressUtil]::WriteProgressBar([int]($totalBytesReceived / $contentLength * 100), $true, [NetworkManager]::DownloadOptions.progressBarLength);
            }
        }
        (Get-Variable host).Value.UI.RawUI.ForegroundColor = $OgForeground
        try { Invoke-Command -ScriptBlock { $stream.Close(); $fileStream.Close() } -ErrorAction SilentlyContinue } catch { $null }
        return (Get-Item $outFile)
    }
    static [void] UploadFile ([string]$SourcePath, [string]$DestinationURL) {
        Invoke-RestMethod -Uri $DestinationURL -Method Post -InFile $SourcePath
    }
    static [bool] Resolve_Ping_Dependencies () {
        # Prevent: error: System.PlatformNotSupportedException : The system's ping utility could not be found.
        # https://github.com/dotnet/runtime/issues/28572
        $result = [bool](Get-Command ping -ea SilentlyContinue)
        if ($result) { return $result }
        $HostOS = [cryptobase]::Get_Host_Os()
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
        #GOAL: Be faster than (Test-Connection github.com -Count 1 -ErrorAction Ignore).status -ne "Success"
        if (![NetworkManager]::resolve_ping_dependencies()) {
            Write-Host "[NetworkManager] Could not resolve ping dependencies" -f Red
        }
        [ValidateNotNullOrEmpty()][string]$HostName = $HostName
        if (![bool]("System.Net.NetworkInformation.Ping" -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
        $cs = $null; $cc = [NetworkManager]::caller; $re = @{ true = @{ m = "Success"; c = "Green" }; false = @{ m = "Failed"; c = "Red" } }
        Write-Host "$cc Testing Connection ... " -f Blue -NoNewline
        try {
            [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send($HostName);
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
}

class EncodingBase : System.Text.ASCIIEncoding {
    EncodingBase() {}
    static [byte[]] GetBytes([string] $text) {
        return [EncodingBase]::new().GetBytes($text)
    }
    static [string] GetString([byte[]]$bytes) {
        return [EncodingBase]::new().GetString($bytes)
    }
    static [char[]] GetChars([byte[]]$bytes) {
        return [EncodingBase]::new().GetChars($bytes)
    }
}

#region    CryptoBase
class CryptoBase {
    static hidden [string] $caller
    [ValidateNotNull()][byte[]]hidden $_salt
    [ValidateNotNull()][byte[]]hidden $_bytes
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope
    [ValidateNotNull()][securestring]hidden $_Password
    [ValidateNotNull()][CryptoAlgorithm]hidden $_Algorithm

    CryptoBase() {}

    static [string] GetRandomName() {
        return [CryptoBase]::GetRandomName((Get-Random -min 16 -max 80));
    }
    static [string] GetRandomName([int]$Length) {
        return [string][CryptoBase]::GetRandomName($Length, $Length);
    }
    static [string] GetRandomName([bool]$IncludeNumbers) {
        $Length = Get-Random -min 16 -max 80
        return [string][CryptoBase]::GetRandomName($Length, $Length, $IncludeNumbers);
    }
    static [string] GetRandomName([int]$Length, [bool]$IncludeNumbers) {
        return [string][CryptoBase]::GetRandomName($Length, $Length, $IncludeNumbers);
    }
    static [string] GetRandomName([int]$minLength, [int]$maxLength) {
        return [string][CryptoBase]::GetRandomName($minLength, $maxLength, $false);
    }
    static [string] GetRandomName([int]$minLength, [int]$maxLength, [bool]$IncludeNumbers) {
        [int]$iterations = 2; $MinrL = 3; $MaxrL = 999 #Gotta have some restrictions, or one typo could slow down an entire script.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; Break }
        $samplekeys = if ($IncludeNumbers) {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
        } else {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }))
        }
        return [string][CryptoBase]::GetRandomSTR($samplekeys, $iterations, $minLength, $maxLength);
    }
    static [byte[]] GetDerivedBytes() {
        return [CryptoBase]::GetDerivedBytes(16)
    }
    static [byte[]] GetDerivedBytes([int]$Length) {
        return [CryptoBase]::GetDerivedBytes([xconvert]::ToSecurestring([CryptoBase]::GetRandomName(16)), $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password) {
        return [CryptoBase]::GetDerivedBytes($password, 16)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [int]$Length) {
        $pswd = [xconvert]::ToSecurestring($(switch ([CryptoBase]::EncryptionScope.ToString()) {
                    "Machine" {
                        [System.Text.Encoding]::UTF8.GetBytes([CryptoBase]::GetUniqueMachineId())
                    }
                    Default {
                        [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==")
                    }
                }
            )
        )
        $s6lt = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes([xconvert]::ToString($password))).GetBytes(16)
        return [CryptoBase]::GetDerivedBytes($pswd, $s6lt, $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [byte[]]$salt, [int]$Length) {
        return [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, 1000).GetBytes($Length);
    }
    static [byte[]] GetKey() {
        return [CryptoBase]::GetKey(16);
    }
    static [byte[]] GetKey([int]$Length) {
        return [CryptoBase]::GetKey([xconvert]::ToSecurestring([CryptoBase]::GeneratePassword()), $Length)
    }
    static [byte[]] GetKey([securestring]$password) {
        return [CryptoBase]::GetKey($password, 16)
    }
    static [byte[]] GetKey([securestring]$password, [int]$Length) {
        return [CryptoBase]::GetDerivedBytes($password, $Length)
    }
    static [byte[]] GetKey([securestring]$password, [byte[]]$salt) {
        return [CryptoBase]::GetKey($password, $salt, 16)
    }
    static [byte[]] GetKey([securestring]$password, [byte[]]$salt, [int]$Length) {
        return [CryptoBase]::GetDerivedBytes($password, $salt, $Length)
    }
    # can be used to generate random IV
    static [byte[]] GetRandomEntropy() {
        [byte[]]$entropy = [byte[]]::new(16);
        [void][System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($entropy)
        return $entropy;
    }
    static hidden [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$minLength, [int]$maxLength) {
        if ($maxLength -lt $minLength) { throw [System.ArgumentOutOfRangeException]::new('MinLength', "'MaxLength' cannot be less than 'MinLength'") }
        if ($iterations -le 0) { Write-Warning 'Negative and Zero Iterations are NOT Possible!'; return [string]::Empty }
        [char[]]$chars = [char[]]::new($InputSample.Length);
        $chars = $InputSample.ToCharArray();
        $Keys = [System.Collections.Generic.List[string]]::new();
        $rand = [Random]::new();
        [int]$size = $rand.Next([int]$minLength, [int]$maxLength);
        for ($i = 0; $i -lt $iterations; $i++) {
            [byte[]] $data = [Byte[]]::new(1);
            $crypto = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();
            $data = [Byte[]]::new($size);
            $crypto.GetNonZeroBytes($data);
            $result = [System.Text.StringBuilder]::new($size);
            foreach ($b In $data) { $result.Append($chars[$b % ($chars.Length - 1)]) };
            [void]$Keys.Add($result.ToString());
        }
        $STR = [string]::Join('', $keys)
        if ($STR.Length -gt $maxLength) {
            $STR = $STR.Substring(0, $maxLength);
        }
        return $STR;
    }
    static [string] GeneratePassword() {
        return [string][CryptoBase]::GeneratePassword(19);
    }
    static [string] GeneratePassword([int]$Length) {
        return [string][CryptoBase]::GeneratePassword($Length, $false, $false, $false, $false);
    }
    static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter) {
        return [string][CryptoBase]::GeneratePassword($Length, $StartWithLetter, $false, $false, $false);
    }
    static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter, [bool]$NoSymbols, [bool]$UseAmbiguousCharacters, [bool]$UseExtendedAscii) {
        # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
        [string]$possibleCharacters = [char[]](33..126 + 161..254); $MinrL = 14; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
        if ($Length -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater."; Break }
        if ($Length -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower."; Break }
        # Warn the user if they've specified mutually-exclusive options.
        if ($NoSymbols -and $UseExtendedAscii) { Write-Warning 'The -NoSymbols parameter was also specified.  No extended ASCII characters will be used.' }
        do {
            $Passw0rd = [string]::Empty; $x = $null; $r = 0
            #This person Wants a really good password, so We retry Until we get a 60% strong password.
            do {
                do {
                    do {
                        do {
                            do {
                                $x = [int][char][string][CryptoBase]::GetRandomSTR($possibleCharacters, 1, 1, 1);
                                # Write-Verbose "Use character: $([char]$x) : $x"
                            } While ($x -eq 127 -Or (!$UseExtendedAscii -and $x -gt 127))
                            # The above Do..While loop does this:
                            #  1. Don't allow ASCII 127 (delete).
                            #  2. Don't allow extended ASCII, unless the user wants it.
                        } While (!$UseAmbiguousCharacters -and ($x -In @(49, 73, 108, 124, 48, 79)))
                        # The above loop disallows 1 (ASCII 49), I (73), l (108),
                        # | (124), 0 (48) or O (79) -- unless the user wants those.
                    } While ($NoSymbols -and ($x -lt 48 -Or ($x -gt 57 -and $x -lt 65) -Or ($x -gt 90 -and $x -lt 97) -Or $x -gt 122))
                    # If the -NoSymbols parameter was specified, this loop will ensure
                    # that the character is neither a symbol nor in the extended ASCII
                    # character set.
                } While ($r -eq 0 -and $StartWithLetter -and !(($x -ge 65 -and $x -le 90) -Or ($x -ge 97 -and $x -le 122)))
                # If the -StartWithLetter parameter was specified, this loop will make
                # sure that the first character is an upper- or lower-case letter.
                $Passw0rd = $Passw0rd.Trim()
                $Passw0rd += [string][char]$x; $r++
            } until ($Passw0rd.length -eq $Length)
        } until ([int][CryptoBase]::GetPasswordStrength($Passw0rd) -gt 60)
        return $Passw0rd;
    }
    [int] static GetPasswordStrength([string]$passw0rd) {
        # Inspired by: https://www.security.org/how-secure-is-my-password/
        $passwordDigits = [System.Text.RegularExpressions.Regex]::new("\d", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordNonWord = [System.Text.RegularExpressions.Regex]::new("\W", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordUppercase = [System.Text.RegularExpressions.Regex]::new("[A-Z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordLowercase = [System.Text.RegularExpressions.Regex]::new("[a-z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd);
        if ($digits.Count -ge 2) { $strength += 10 };
        if ($digits.Count -ge 5) { $strength += 10 };
        if ($NonWords.Count -ge 2) { $strength += 10 };
        if ($NonWords.Count -ge 5) { $strength += 10 };
        if ($passw0rd.Length -gt 8) { $strength += 10 };
        if ($passw0rd.Length -ge 16) { $strength += 10 };
        if ($Lowercases.Count -ge 2) { $strength += 10 };
        if ($Lowercases.Count -ge 5) { $strength += 10 };
        if ($Uppercases.Count -ge 2) { $strength += 10 };
        if ($Uppercases.Count -ge 5) { $strength += 10 };
        return $strength;
    }
    static [bool] IsBase64String([string]$base64) {
        return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
    }
    static [bool] IsValidAES([System.Security.Cryptography.Aes]$aes) {
        return [bool]$(try { [CryptoBase]::CheckProps($aes); $? } catch { $false })
    }
    static hidden [void] CheckProps([System.Security.Cryptography.Aes]$Aes) {
        $MissingProps = @(); $throw = $false
        Write-Verbose "$([CryptoBase]::caller) [+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $Aes.Algo.$_) { $MissingProps += $_ } };
            if ($MissingProps.Count -eq 0) { "Done. All AES Props are Good." } else { $throw = $true; "System.ArgumentNullException: $([string]::Join(', ', $MissingProps)) cannot be null." }
        )"
        if ($throw) { throw [System.ArgumentNullException]::new([string]::Join(', ', $MissingProps)) }
    }
    static [string] GetResolvedPath([string]$Path) {
        return [CryptoBase]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
        if ($paths.Count -gt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
        } elseif ($paths.Count -lt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
        }
        return $paths[0].Path
    }
    static [string] GetUnResolvedPath([string]$Path) {
        return [CryptoBase]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
    static [System.Type] CreateEnum([string]$Name, [bool]$IsPublic, [string[]]$Members) {
        # Example:
        # $MacMseries = [cryptobase]::CreateEnum('Mseries', $true, ('M1', 'M2', 'M3'))
        # $MacMseries::M1 | gm
        # Todo: Explore more about [System.Reflection.Emit.EnumBuilder], so we can add more features. ex: Flags, instead of [string[]]$Members we can have [hastable]$Members etc.
        try {
            if ([string]::IsNullOrWhiteSpace($Name)) { throw [InvalidArgumentException]::new('Name', 'Name can not be null or space') }
            $DynAssembly = [System.Reflection.AssemblyName]::new("EmittedEnum")
            $AssmBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, ([System.Reflection.Emit.AssemblyBuilderAccess]::Save -bor [System.Reflection.Emit.AssemblyBuilderAccess]::Run)) # Only run in memory
            $ModulBuildr = $AssmBuilder.DefineDynamicModule("DynamicModule")
            $type_attrib = if ($IsPublic) { [System.Reflection.TypeAttributes]::Public }else { [System.Reflection.TypeAttributes]::NotPublic }
            $enumBuilder = [System.Reflection.Emit.EnumBuilder]$ModulBuildr.DefineEnum($name, $type_attrib, [System.Int32]);
            for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
            [void]$enumBuilder.CreateType()
        } catch {
            throw $_
        }
        return ($Name -as [Type])
    }
    static [System.Security.Cryptography.Aes] GetAes() { return [CryptoBase]::GetAes(1) }
    static [System.Security.Cryptography.Aes] GetAes([int]$Iterations) {
        $salt = $null; $password = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([CryptoBase]::GeneratePassword()));
        Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([CryptoBase]::GetDerivedBytes(16));
        return [CryptoBase]::GetAes($password, $salt, $Iterations)
    }
    static [System.Security.Cryptography.Aes] GetAes([securestring]$password, [byte[]]$salt, [int]$iterations) {
        $aes = $null; $M = $null; $P = $null; $k = $null;
        Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.AesManaged]::new());
        #Note: 'Zeros' Padding was avoided, see: https://crypto.stackexchange.com/questions/1486/how-to-choose-a-padding-mode-with-aes # Personally I prefer PKCS7 as the best padding.
        for ($i = 1; $i -le $iterations; $i++) { ($M, $P, $k) = ((Get-Random ('ECB', 'CBC')), (Get-Random ('PKCS7', 'ISO10126', 'ANSIX923')), (Get-Random (128, 192, 256))) }
        $aes.Mode = & ([scriptblock]::Create("[System.Security.Cryptography.CipherMode]::$M"));
        $aes.Padding = & ([scriptblock]::Create("[System.Security.Cryptography.PaddingMode]::$P"));
        $aes.keysize = $k;
        $aes.Key = [CryptoBase]::GetKey($password, $salt);
        $aes.IV = [CryptoBase]::GetRandomEntropy();
        return $aes
    }
    # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
    static [string] GetUniqueMachineId() {
        $Id = [string]($Env:MACHINE_ID)
        $vp = Get-Variable VerbosePreference -ValueOnly
        try {
            Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
            if ([string]::IsNullOrWhiteSpace($Id)) {
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
                switch ($HostOS) {
                    "Windows" {
                        $_Id = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                        $_Id = $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($_Id))));
                    }
                    "Linux" {
                        # $_Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
                        # Lets use mac addresses
                        $_Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
                        $_Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($_Id)))
                    }
                    "macOS" {
                        $_Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
                        $_Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($_Id)))
                    }
                    Default {
                        Write-Host "unknown"
                        throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
                    }
                }
                [System.Environment]::SetEnvironmentVariable("MACHINE_ID", $_Id, [System.EnvironmentVariableTarget]::Process)
            }
            $Id = [string]($Env:MACHINE_ID)
        } catch {
            throw $_
        } finally {
            if ($sha256) { $sha256.Clear(); $sha256.Dispose() }
            Set-Variable VerbosePreference -Value $vp
        }
        return $Id
    }
    static [string] Get_Host_Os() {
        # Todo: Should return one of these: [Enum]::GetNames([System.PlatformID])
        return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
    }
    static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
        $_Host_OS = [CryptoBase]::Get_Host_Os()
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
            throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
        }
        if (!$dataPath.Exists) { [CryptoBase]::Create_Dir($dataPath) }
        return $dataPath
    }
    static [void] Create_Dir([string]$Path) {
        [CryptoBase]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
    }
    static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
    }
    [securestring] static GetPassword() {
        $ThrowOnFailure = $true
        return [CryptoBase]::GetPassword($ThrowOnFailure);
    }
    [securestring] static GetPassword([string]$Prompt) {
        return [CryptoBase]::GetPassword($Prompt, $true)
    }
    [securestring] static GetPassword([bool]$ThrowOnFailure) {
        return [CryptoBase]::GetPassword("Password", $ThrowOnFailure)
    }
    static [securestring] GetPassword([string]$Prompt, [bool]$ThrowOnFailure) {
        if ([CryptoBase]::EncryptionScope.ToString() -eq "Machine") {
            return [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        } else {
            $pswd = [SecureString]::new(); $_caller = 'PasswordManager'; if (![string]::IsNullOrWhiteSpace([CryptoBase]::caller)) { $_caller = [CryptoBase]::caller }
            Set-Variable -Name pswd -Scope Local -Visibility Private -Option Private -Value $(Read-Host -Prompt "$_caller $Prompt" -AsSecureString);
            if ($ThrowOnFailure -and ($null -eq $pswd -or $([string]::IsNullOrWhiteSpace([xconvert]::ToString($pswd))))) {
                throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null or WhiteSpace.", $pswd, [System.ArgumentNullException]::new("Password"))
            }
            return $pswd;
        }
    }
    static [void] ValidateCompression([string]$Compression) {
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") };
    }
}
#endregion CryptoBase

#region    Custom_ObjectConverter
class xconvert : System.ComponentModel.TypeConverter {
    xconvert() {}
    static [string] Base32ToHex([string]$base32String) {
        return [System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($base32String)).Replace("-", "").ToLower()
    }
    static [string] Base32FromHex([string]$hexString) {
        return [System.Text.Encoding]::UTF8.GetString(([byte[]] -split ($hexString -replace '..', '0x$& ')))
    }
    static [string] GuidFromHex([string]$hexString) {
        return [System.Guid]::new(([byte[]] -split ($hexString -replace '..', '0x$& '))).ToString()
    }
    static [string] ToString([byte[]]$Bytes) {
        return [string][System.Convert]::ToBase64String($Bytes);
    }
    static [string[]] ToString([int[]]$CharCodes) {
        $String = @(); foreach ($n in $CharCodes) { $String += [string][char]$n }
        return $String
    }
    static [string] ToString([System.Security.SecureString]$SecureString) {
        [string]$Pstr = [string]::Empty;
        [IntPtr]$zero = [IntPtr]::Zero;
        if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
            return [string]::Empty;
        }
        try {
            Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
            Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
        } finally {
            if ($zero -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
            }
        }
        return $Pstr;
    }
    static [string] ToString([int[]]$CharCodes, [string]$separator) {
        return [string]::Join($separator, [xconvert]::ToString($CharCodes));
    }
    static [string] ToString([int]$value, [int]$toBase) {
        [char[]]$baseChars = switch ($toBase) {
            # Binary
            2 { @('0', '1') }
            # Hexadecimal
            16 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f') }
            # Hexavigesimal
            26 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p') }
            # Sexagesimal
            60 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x') }
            Default {
                throw [System.ArgumentException]::new("Invalid Base.")
            }
        }
        return [xconvert]::IntToString($value, $baseChars);
    }
    static [string] ToString([guid]$guid) {
        return [System.Text.Encoding]::UTF8.GetString([xconvert]::FromHexString($guid.ToString().Replace('-', '')))
        # I just assumed all guids use UTF8 for encoding, but idk maybe they are also encrypted?!
        # ie: This is just a way to reverse the ToGuid() method. does not apply on real guids.
    }
    static [guid] ToGuid([string]$InputText) {
        # Creates a string that passes guid regex checks (ie: not a real guid)
        if ($InputText.Trim().Length -ne 16) {
            throw [System.InvalidOperationException]::new('$InputText.Trim().Length Should Be exactly 16. Ex: [xconvert]::ToGuid([CryptoBase]::GetRandomName(16))')
        }
        return [guid]::new([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($InputText)).Replace("-", "").ToLower().Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"))
    }
    static [SecureString] ToSecurestring([string]$String) {
        $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        if (![string]::IsNullOrEmpty($String)) {
            $Chars = $String.toCharArray()
            ForEach ($Char in $Chars) {
                $SecureString.AppendChar($Char)
            }
        }
        $SecureString.MakeReadOnly();
        return $SecureString
    }
    static [int[]] StringToCharCode([string[]]$string) {
        [bool]$encoderShouldEmitUTF8Identifier = $false; $Codes = @()
        $Encodr = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        for ($i = 0; $i -lt $string.Count; $i++) {
            $Codes += [int[]]$($Encodr.GetBytes($string[$i]))
        }
        return $Codes;
    }
    static [datetime] ToDateTime([string]$dateString) {
        # Dynamically detect the system's date and time format and use it to parse the $dateString.
        $currentCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        $dateTimeFormat = $currentCulture.DateTimeFormat; $datetime = @()
        $dateFormats = $dateTimeFormat.GetAllDateTimePatterns()
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($format in $dateFormats) {
            try {
                $datetime += [DateTime]::ParseExact($dateString, $format, $culture);
            } catch {
                continue
            }
        }
        if ($datetime.Count -ne 1) {
            throw 'An error occurred while parsing the input $dateString to a DateTime object.'
        }
        return $datetime[0]
    }
    static [bool] StringToBoolean([string]$Text) {
        $Text = switch -Wildcard ($Text) {
            "1*" { "true"; break }
            "0*" { "false"; break }
            "yes*" { "true"; break }
            "no*" { "false"; break }
            "true*" { "true"; break }
            "false*" { "false"; break }
            "*true*" { "true"; break }
            "*false*" { "false"; break }
            "yeah*" { "true"; break }
            "y*" { "true"; break }
            "n*" { "false"; break }
            Default { "false" }
        }
        return [convert]::ToBoolean($Text)
    }
    static [string] ToCaesarCipher([string]$Text, [int]$Key) {
        [ValidateNotNullOrEmpty()][string]$Text = $Text; $Cipher = [string]::Empty;
        $alphabet = $null; New-Variable -Name alphabet -Option Constant -Value "abcdefghijklmnopqrstuvwxyz" -Force;
        for ($i = 0; $i -lt $Text.Length; $i++) {
            if ($Text[$i] -eq " ") {
                $Cipher += " ";
            } else {
                [int]$index = $alphabet.IndexOf($text[$i]) + $Key
                if ($index -gt 26) {
                    $index = $index - 26
                }
                $Cipher += $alphabet[$index];
            }
        }
        return $Cipher
    }
    static [string] FromCaesarCipher([string]$Cipher, [int]$Key) {
        [ValidateNotNullOrEmpty()][string]$Cipher = $Cipher.ToLower(); $Output = [string]::Empty;
        $alphabet = $null; New-Variable -Name alphabet -Value "abcdefghijklmnopqrstuvwxyz" -Option Constant -Force;
        for ($i = 0; $i -lt $Cipher.Length; $i++) {
            if ($Cipher[$i] -eq " ") {
                $Output += " ";
            } else {
                $Output += $alphabet[($alphabet.IndexOf($Cipher[$i]) - $Key)];
            }
        };
        return $Output;
    }
    static [string] ToPolybiusCipher([string]$Text, [string]$Key) {
        [ValidateNotNullOrEmpty()][string]$Text = $Text.ToLower();
        [ValidateNotNullOrEmpty()][string]$Key = $Key.ToLower(); $Cipher = [string]::Empty
        [xconvert]::ValidatePolybiusCipher($Text, $Key, "Encrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $Text = $Text.Replace(" ", "");
        for ($i = 0; $i -lt $Text.Length; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                for ($k = 0; $k -lt 5; $k++) {
                    if ($polybiusTable[$j, $k] -eq $Text[$i]) {
                        $Cipher += [string]$j + [string]$k + " ";
                    }
                }
            }
        }
        return $Cipher
    }
    static [string] FromPolybiusCipher([string]$Cipher, [string]$Key) {
        [ValidateNotNullOrEmpty()][string]$Cipher = $Cipher.ToLower();
        [ValidateNotNullOrEmpty()][string]$Key = $Key.ToLower(); $Output = [string]::Empty
        [xconvert]::ValidatePolybiusCipher($Cipher, $Key, "Decrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $SplitInput = $Cipher.Split(" ");
        foreach ($pair in $SplitInput) {
            $Output += $polybiusTable[[convert]::ToInt32($pair[0], 10), [convert]::ToInt32($pair[1], 10)];
        };
        return $Output;
    }
    static hidden [void] ValidatePolybiusCipher([string]$Text, [string]$Key, [string]$Action) {
        if ($Text -notmatch "^[a-z ]*$" -and ($Action -ne 'Decrypt')) {
            throw('Text must only have alphabetical characters');
        }
        if ($Key.Length -ne 25) {
            throw('Key must be 25 characters in length');
        }
        if ($Key -notmatch "^[a-z]*$") {
            throw('Key must only have alphabetical characters');
        }
        for ($i = 0; $i -lt 25; $i++) {
            for ($j = 0; $j -lt 25; $j++) {
                if (($Key[$i] -eq $Key[$j]) -and ($i -ne $j)) {
                    throw('Key must have no repeating letters');
                }
            }
        }
    }
    static [string] StringToBinStR ([string]$string) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $false)
    }
    static [string] StringToBinStR ([string]$string, [bool]$Tidy) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $Tidy)
    }
    static [string] StringFromBinStR ([string]$BinStR) {
        return [xconvert]::BinaryToString([xconvert]::BinaryFromBinStR($BinStR))
    }
    static [string] ToObfuscated([string]$inputString) {
        $Inpbytes = [System.Text.Encoding]::UTF8.GetBytes($inputString); $rn = [System.Random]::new(); # Hides Byte Array in a random String
        return [string]::Join('', $($Inpbytes | ForEach-Object { [string][char]$rn.Next(97, 122) + $_ }));
    }
    static [string] ToDeObfuscated([string]$obfuscatedString) {
        $az = [int[]](97..122) | ForEach-Object { [string][char]$_ };
        $outbytes = [byte[]][string]::Concat($(($obfuscatedString.ToCharArray() | ForEach-Object { if ($_ -in $az) { [string][char]32 } else { [string]$_ } }) | ForEach-Object { $_ })).Trim().split([string][char]32);
        return [System.Text.Encoding]::UTF8.GetString($outbytes)
    }
    [PSCustomObject[]] static ToPSObject([xml]$XML) {
        $Out = @(); foreach ($Object in @($XML.Objects.Object)) {
            $PSObject = [PSCustomObject]::new()
            foreach ($Property in @($Object.Property)) {
                $PSObject | Add-Member NoteProperty $Property.Name $Property.InnerText
            }
            $Out += $PSObject
        }
        return $Out
    }
    static [string] ToCsv([System.Object]$Obj) {
        return [xconvert]::ToCsv($Obj, @('pstypenames', 'BaseType'), 2, 0)
    }
    static [string] ToCsv([System.Object]$Obj, [int]$depth) {
        return [xconvert]::ToCsv($Obj, @('pstypenames', 'BaseType'), $depth, 0)
    }
    static [string] ToCsv([System.Object]$Obj, [string[]]$excludedProps, [int]$depth, [int]$currentDepth = 0) {
        $get_Props = [scriptblock]::Create({
                param([Object]$Objct, [string[]]$excluded)
                $Props = $Objct | Get-Member -Force -MemberType Properties; if ($excluded.Count -gt 0) { $Props = $Props | Where-Object { $_.Name -notin $excluded } }
                $Props = $Props | Select-Object -ExpandProperty Name
                return $Props
            }
        )
        $Props = $get_Props.Invoke($Obj, $excludedProps)
        $csv = [string]::Empty
        $csv += '"' + ($Props -join '","') + '"' + "`n";
        $vals = @()
        foreach ($name in $Props) {
            $_props = $get_Props.Invoke($Obj.$name, $excludedProps)
            if ($null -ne $_props) {
                if ($_props.count -gt 0 -and $currentDepth -lt $depth) {
                    $currentDepth++
                    $vals += [xconvert]::ToCsv($Obj.$name, $excludedProps, $depth, $currentDepth)
                } elseif ($null -ne $Obj.$name) {
                    $vals += $Obj.$name.Tostring()
                } else {
                    $vals += $name.Tostring()
                }
            }
        }
        $fs = '"{' + ((0 .. ($vals.Count - 1)) -join '}","{') + '}"';
        $csv += $fs -f $vals
        return $csv
    }
    static [PsObject] FromCsv([string]$text) {
        $obj = $null
        $lines = $text -split "\r?\n"
        if ($lines.Count -lt 2) {
            throw "CSV contains no data"
        }
        $header = $lines[0] -split ','
        $objs = foreach ($line in $lines[1..($lines.Count - 1)]) {
            $values = $line -split ','
            $obj = New-Object psobject
            for ($i = 0; $i -lt $header.Length; $i++) {
                $prop = $header[$i].Trim('"')
                if ($null -ne $values[$i]) {
                    $val = $values[$i].Trim('"')
                    if (![string]::IsNullOrEmpty($val)) {
                        $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $val
                    }
                }
            }
            $obj
        }
        return $objs
    }
    static [byte[]] FromBase32String([string]$string) {
        [ValidateNotNullOrEmpty()][string]$string = $string;
        $string = $string.ToLower(); $B32CHARSET = "abcdefghijklmnopqrstuvwxyz234567"
        $B32CHARSET_Pattern = "^[A-Z2-7 ]+_*$"; [byte[]]$result = $null
        if (!($string -match $B32CHARSET_Pattern)) {
            Throw "Invalid Base32 data encountered in input stream."
        }
        $InputStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($string), 0, $string.Length)
        $BinaryReader = [System.IO.BinaryReader]::new($InputStream)
        $OutputStream = [System.IO.MemoryStream]::new()
        $BinaryWriter = [System.IO.BinaryWriter]::new($OutputStream)
        Try {
            While ([System.Char[]]$CharsRead = $BinaryReader.ReadChars(8)) {
                [System.Byte[]]$B32Bytes = , 0x00 * 5
                [System.UInt16]$CharLen = 8 - ($CharsRead -Match "_").Count
                [System.UInt16]$ByteLen = [Math]::Floor(($CharLen * 5) / 8)
                [System.Byte[]]$BinChunk = , 0x00 * $ByteLen
                if ($CharLen -lt 8) {
                    [System.Char[]]$WorkingChars = , "a" * 8
                    [Array]::Copy($CharsRead, $WorkingChars, $CharLen)
                    [Array]::Resize([ref]$CharsRead, 8)
                    [Array]::Copy($WorkingChars, $CharsRead, 8)
                }
                $B32Bytes[0] = (($B32CHARSET.IndexOf($CharsRead[0]) -band 0x1F) -shl 3) -bor (($B32CHARSET.IndexOf($CharsRead[1]) -band 0x1C) -shr 2)
                $B32Bytes[1] = (($B32CHARSET.IndexOf($CharsRead[1]) -band 0x03) -shl 6) -bor (($B32CHARSET.IndexOf($CharsRead[2]) -band 0x1F) -shl 1) -bor (($B32CHARSET.IndexOf($CharsRead[3]) -band 0x10) -shr 4)
                $B32Bytes[2] = (($B32CHARSET.IndexOf($CharsRead[3]) -band 0x0F) -shl 4) -bor (($B32CHARSET.IndexOf($CharsRead[4]) -band 0x1E) -shr 1)
                $B32Bytes[3] = (($B32CHARSET.IndexOf($CharsRead[4]) -band 0x01) -shl 7) -bor (($B32CHARSET.IndexOf($CharsRead[5]) -band 0x1F) -shl 2) -bor (($B32CHARSET.IndexOf($CharsRead[6]) -band 0x18) -shr 3)
                $B32Bytes[4] = (($B32CHARSET.IndexOf($CharsRead[6]) -band 0x07) -shl 5) -bor ($B32CHARSET.IndexOf($CharsRead[7]) -band 0x1F)
                [System.Buffer]::BlockCopy($B32Bytes, 0, $BinChunk, 0, $ByteLen)
                $BinaryWriter.Write($BinChunk)
            }
            $result = $OutputStream.ToArray()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            Break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $BinaryWriter.Close()
            $BinaryWriter.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $OutputStream.Close()
            $OutputStream.Dispose()
        }
        return $result
    }
    static [string] ToBase32String([byte[]]$bytes) {
        return [xconvert]::ToBase32String($bytes, $false)
    }
    static [string] ToBase32String([string]$String) {
        return [xconvert]::ToBase32String($String, $false)
    }
    static [string] ToBase32String([byte[]]$bytes, [bool]$Formatt) {
        return [xconvert]::ToBase32String([System.IO.MemoryStream]::New($bytes), $Formatt)
    }
    static [string] ToBase32String([string]$String, [bool]$Formatt) {
        return [xconvert]::ToBase32String([System.Text.Encoding]::ASCII.GetBytes($String), $Formatt)
    }
    static [string] ToBase32String([System.IO.Stream]$Stream, [bool]$Formatt) {
        $BinaryReader = [System.IO.BinaryReader]::new($Stream);
        $Base32Output = [System.Text.StringBuilder]::new(); $result = [string]::Empty
        $B32CHARSET = "abcdefghijklmnopqrstuvwxyz234567"
        Try {
            While ([byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.Boolean]$AtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 5) {
                    [byte[]]$WorkingBytes = , 0x00 * 5
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 5)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 5)
                }
                [System.Char[]]$B32Chars = , 0x00 * 8
                [System.Char[]]$B32Chunk = , "_" * 8
                $B32Chars[0] = ($B32CHARSET[($BytesRead[0] -band 0xF8) -shr 3])
                $B32Chars[1] = ($B32CHARSET[(($BytesRead[0] -band 0x07) -shl 2) -bor (($BytesRead[1] -band 0xC0) -shr 6)])
                $B32Chars[2] = ($B32CHARSET[($BytesRead[1] -band 0x3E) -shr 1])
                $B32Chars[3] = ($B32CHARSET[(($BytesRead[1] -band 0x01) -shl 4) -bor (($BytesRead[2] -band 0xF0) -shr 4)])
                $B32Chars[4] = ($B32CHARSET[(($BytesRead[2] -band 0x0F) -shl 1) -bor (($BytesRead[3] -band 0x80) -shr 7)])
                $B32Chars[5] = ($B32CHARSET[($BytesRead[3] -band 0x7C) -shr 2])
                $B32Chars[6] = ($B32CHARSET[(($BytesRead[3] -band 0x03) -shl 3) -bor (($BytesRead[4] -band 0xE0) -shr 5)])
                $B32Chars[7] = ($B32CHARSET[$BytesRead[4] -band 0x1F])
                [Array]::Copy($B32Chars, $B32Chunk, ([Math]::Ceiling(($ByteLength / 5) * 8)))
                if ($BinaryReader.BaseStream.Position % 8 -eq 0 -and $Formatt -and !$AtEnd) {
                    [void]$Base32Output.Append($B32Chunk)
                    [void]$Base32Output.Append("`r`n")
                } else {
                    [void]$Base32Output.Append($B32Chunk)
                }
            }
            [string]$result = $Base32Output.ToString()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            Break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $Stream.Close()
            $Stream.Dispose()
        }
        return $result
    }
    [PsCustomObject] static ToPSObject([System.Object]$Obj) {
        $PSObj = [PSCustomObject]::new();
        $Obj | Get-Member -MemberType Properties | ForEach-Object {
            $Name = $_.Name; $PSObj | Add-Member -Name $Name -MemberType NoteProperty -Value $(if ($null -ne $Obj.$Name) { if ("Deserialized" -in (($Obj.$Name | Get-Member).TypeName.Split('.') | Sort-Object -Unique)) { $([xconvert]::ToPSObject($Obj.$Name)) } else { $Obj.$Name } } else { $null })
        }
        return $PSObj
    }
    static [System.Object] FromPSObject([PSCustomObject]$PSObject) {
        return [xconvert]::FromPSObject($PSObject, $PSObject.PSObject.TypeNames[0])
    }
    static [System.Object] FromPSObject([PSCustomObject]$PSObject, [string]$typeName) {
        # /!\ not working as expected /!\
        $Type = [Type]::GetType($typeName, $false)
        if ($Type) {
            $Obj = [Activator]::CreateInstance($Type)
            $PSObject.PSObject.Properties | ForEach-Object {
                $Name = $_.Name
                $Value = $_.Value
                if ($Value -is [PSCustomObject]) {
                    $Value = [xconvert]::FromPSObject($Value)
                }
                $Obj.$Name = $Value
            }
            return $Obj
        } else {
            return $PSObject
        }
    }
    static [byte[]] ToProtected([byte[]]$Bytes) {
        $p = [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        return [AesGCM]::Encrypt($Bytes, $p, [CryptoBase]::GetDerivedBytes($p))
    }
    static [byte[]] ToUnProtected([byte[]]$Bytes) {
        $p = [xconvert]::ToSecurestring([CryptoBase]::GetUniqueMachineId())
        return [AesGCM]::Decrypt($Bytes, $p, [CryptoBase]::GetDerivedBytes($p))
    }
    static [byte[]] ToCompressed([byte[]]$Bytes) {
        return [xconvert]::ToCompressed($Bytes, 'Gzip');
    }
    static [string] ToCompressed([string]$Plaintext) {
        return [convert]::ToBase64String([xconvert]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
    }
    static [byte[]] ToCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $outstream = [System.IO.MemoryStream]::new()
        $Comstream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
        }
        [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes) {
        return [xconvert]::ToDeCompressed($Bytes, 'Gzip');
    }
    static [string] ToDecompressed([string]$Base64Text) {
        return [System.Text.Encoding]::UTF8.GetString([xconvert]::ToDecompressed([convert]::FromBase64String($Base64Text)));
    }
    static [byte[]] ToDeCompressed([byte[]]$Bytes, [string]$Compression) {
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
        }
        $inpStream = [System.IO.MemoryStream]::new($Bytes)
        $ComStream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
        }
        $outStream = [System.IO.MemoryStream]::new();
        [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    static [string] ToRegexEscapedString([string]$LiteralText) {
        if ([string]::IsNullOrEmpty($LiteralText)) { $LiteralText = [string]::Empty }
        return [regex]::Escape($LiteralText);
    }
    static [System.Collections.Hashtable] FromRegexCapture([System.Text.RegularExpressions.Match]$Match, [regex]$Regex) {
        if (!$Match.Groups[0].Success) {
            throw New-Object System.ArgumentException('Match does not contain any captures.', 'Match')
        }
        $h = @{}
        foreach ($name in $Regex.GetGroupNames()) {
            if ($name -eq 0) {
                continue
            }
            $h.$name = $Match.Groups[$name].Value
        }
        return $h
    }
    static [System.Collections.Hashtable] ToHashTable([PsObject]$object) {
        $ht = @{}; foreach ($property in $object.PsObject.Properties) {
            $ht[$property.Name] = $property.Value
        }
        return $ht
    }
    static hidden [string] IntToString([Int]$value, [char[]]$baseChars) {
        [int]$i = 32;
        [char[]]$buffer = [Char[]]::new($i);
        [int]$targetBase = $baseChars.Length;
        do {
            $buffer[--$i] = $baseChars[$value % $targetBase];
            $value = $value / $targetBase;
        } while ($value -gt 0);
        [char[]]$result = [Char[]]::new(32 - $i);
        [Array]::Copy($buffer, $i, $result, 0, 32 - $i);
        return [string]::new($result)
    }
    static [string] ToHexString([byte[]]$Bytes) {
        return [string][System.BitConverter]::ToString($bytes).replace('-', [string]::Empty).Tolower();
    }
    static [byte[]] FromHexString([string]$HexString) {
        $outputLength = $HexString.Length / 2;
        $output = [byte[]]::new($outputLength);
        $numeral = [char[]]::new(2);
        for ($i = 0; $i -lt $outputLength; $i++) {
            $HexString.CopyTo($i * 2, $numeral, 0, 2);
            $output[$i] = [Convert]::ToByte([string]::new($numeral), 16);
        }
        return $output;
    }
    static [byte[]] Serialize($Obj) {
        return [Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($Obj))
    }
    static [Object] Deserialize([byte[]]$data) {
        return [System.Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString($data))
    }
    static [Object[]] DeserializeAsList([byte[]]$data) {
        return [System.Management.Automation.PSSerializer]::DeserializeAsList([Text.Encoding]::UTF8.GetString($data))
    }
    [System.Collections.BitArray] static BinaryFromString([string]$string) {
        [string]$BinStR = [string]::Empty;
        foreach ($ch In $string.ToCharArray()) {
            $BinStR += [Convert]::ToString([int]$ch, 2).PadLeft(8, '0');
        }
        return [xconvert]::BinaryFromBinStR($BinStR)
    }
    static [string] BinaryToString([System.Collections.BitArray]$BitArray) {
        [string]$finalString = [string]::Empty;
        # Manually read the first 8 bits and
        while ($BitArray.Length -gt 0) {
            $ba_tempBitArray = [System.Collections.BitArray]::new($BitArray.Length - 8);
            $int_binaryValue = 0;
            if ($BitArray[0]) { $int_binaryValue += 1 };
            if ($BitArray[1]) { $int_binaryValue += 2 };
            if ($BitArray[2]) { $int_binaryValue += 4 };
            if ($BitArray[3]) { $int_binaryValue += 8 };
            if ($BitArray[4]) { $int_binaryValue += 16 };
            if ($BitArray[5]) { $int_binaryValue += 32 };
            if ($BitArray[6]) { $int_binaryValue += 64 };
            if ($BitArray[7]) { $int_binaryValue += 128 };
            $finalString += [Char]::ConvertFromUtf32($int_binaryValue);
            $int_counter = 0;
            for ($i = 8; $i -lt $BitArray.Length; $i++) {
                $ba_tempBitArray[$int_counter++] = $BitArray[$i];
            }
            $BitArray = $ba_tempBitArray;
        }
        return $finalString;
    }
    static [string] BytesToBinStR([byte[]]$Bytes) {
        return [xconvert]::BytesToBinStR($Bytes, $true);
    }
    static [string] BytesToBinStR([byte[]]$Bytes, [bool]$Tidy) {
        $bitArray = [System.Collections.BitArray]::new($Bytes);
        return [xconvert]::BinaryToBinStR($bitArray, $Tidy);
    }
    static [byte[]] BytesFromBinStR([string]$binary) {
        $binary = [string]::Join('', $binary.Split())
        $length = $binary.Length; if ($length % 8 -ne 0) {
            Throw [System.IO.InvalidDataException]::new("Your string is invalid. Make sure it has no typos.")
        }
        $list = [System.Collections.Generic.List[Byte]]::new()
        for ($i = 0; $i -lt $length; $i += 8) {
            [string]$binStr = $binary.Substring($i, 8)
            [void]$list.Add([Convert]::ToByte($binStr, 2));
        }
        return $list.ToArray();
    }
    static [byte[]] BytesFromBinary([System.Collections.BitArray]$binary) {
        return [xconvert]::BytesFromBinStR([xconvert]::BinaryToBinStR($binary))
    }
    static [string] BinaryToBinStR([System.Collections.BitArray]$binary) {
        $BinStR = [string]::Empty # (Binary String)
        for ($i = 0; $i -lt $binary.Length; $i++) {
            if ($binary[$i]) {
                $BinStR += "1 ";
            } else {
                $BinStR += "0 ";
            }
        }
        return $BinStR.Trim()
    }
    static [string] BinaryToBinStR([System.Collections.BitArray]$binary, [bool]$Tidy) {
        [string]$binStr = [xconvert]::BinaryToBinStR($binary)
        if ($Tidy) { $binStr = [string]::Join('', $binStr.Split()) }
        return $binStr
    }
    [System.Collections.BitArray] static BinaryFromBinStR([string]$binary) {
        return [System.Collections.BitArray]::new([xconvert]::BytesFromBinStR($binary))
    }
    static [void] ObjectToFile($Object, [string]$OutFile) {
        [xconvert]::ObjectToFile($Object, $OutFile, $false);
    }
    static [void] ObjectToFile($Object, [string]$OutFile, [bool]$encrypt) {
        try {
            $OutFile = [CryptoBase]::GetUnResolvedPath($OutFile)
            try {
                $resolved = [CryptoBase]::GetResolvedPath($OutFile);
                if ($?) { $OutFile = $resolved }
            } catch [System.Management.Automation.ItemNotFoundException] {
                New-Item -Path $OutFile -ItemType File | Out-Null
            } catch {
                throw $_
            }
            Export-Clixml -InputObject $Object -Path $OutFile
            if ($encrypt) { $(Get-Item $OutFile).Encrypt() }
        } catch {
            Write-Error $_
        }
    }
    [Object[]] static ToOrdered($InputObject) {
        $obj = $InputObject
        $convert = [scriptBlock]::Create({
                Param($obj)
                if ($obj -is [System.Management.Automation.PSCustomObject]) {
                    # a custom object: recurse on its properties
                    $oht = [ordered]@{}
                    foreach ($prop in $obj.psobject.Properties) {
                        $oht.Add($prop.Name, $(Invoke-Command -ScriptBlock $convert -ArgumentList $prop.Value))
                    }
                    return $oht
                } elseif ($obj -isnot [string] -and $obj -is [System.Collections.IEnumerable] -and $obj -isnot [System.Collections.IDictionary]) {
                    # A collection of sorts (other than a string or dictionary (hash table)), recurse on its elements.
                    return @(foreach ($el in $obj) { Invoke-Command -ScriptBlock $convert -ArgumentList $el })
                } else {
                    # a non-custom object, including .NET primitives and strings: use as-is.
                    return $obj
                }
            }
        )
        return $(Invoke-Command -ScriptBlock $convert -ArgumentList $obj)
    }
    [object] static ObjectFromFile([string]$FilePath) {
        return [xconvert]::ObjectFromFile($FilePath, $false)
    }
    [object] static ObjectFromFile([string]$FilePath, [string]$Type) {
        return [xconvert]::ObjectFromFile($FilePath, $Type, $false);
    }
    [object] static ObjectFromFile([string]$FilePath, [bool]$Decrypt) {
        $FilePath = [CryptoBase]::GetResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = Import-Clixml -Path $FilePath
        } catch {
            Write-Error $_
        }
        return $Object
    }
    [object] static ObjectFromFile([string]$FilePath, [string]$Type, [bool]$Decrypt) {
        $FilePath = [CryptoBase]::GetResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = (Import-Clixml -Path $FilePath) -as "$Type"
        } catch {
            Write-Error $_
        }
        return $Object
    }
    static [byte[]] StreamToByteArray([System.IO.Stream]$Stream) {
        $ms = [System.IO.MemoryStream]::new();
        $Stream.CopyTo($ms);
        $arr = $ms.ToArray();
        if ($null -ne $ms) { $ms.Flush(); $ms.Close(); $ms.Dispose() } else { Write-Warning "[x] MemoryStream was Not closed!" };
        return $arr;
    }
    [string]hidden static Reverse([string]$text) {
        [char[]]$array = $text.ToCharArray(); [array]::Reverse($array);
        return [String]::new($array);
    }
}
#endregion Custom_ObjectConverter

#region    Base85
# .SYNOPSIS
#     Base85 encoding
# .DESCRIPTION
#     A binary-to-text encoding scheme that uses 85 printable ASCII characters to represent binary data
# .EXAMPLE
#     $b = [System.Text.Encoding]::UTF8.GetBytes("Hello world")
#     [base85]::Encode($b)
#     [System.Text.Encoding]::UTF8.GetString([base85]::Decode("87cURD]j7BEbo7"))
# .EXAMPLE
#     [Base85]::GetString([Base85]::Decode([Base85]::Encode('Hello world!'))) | Should -Be 'Hello world!'
class Base85 : EncodingBase {
    static [String] $NON_A85_Pattern = "[^\x21-\x75]"

    Base85() {}
    static [string] Encode([string]$text) {
        return [Base85]::Encode([Base85]::new().GetBytes($text), $false)
    }
    static [string] Encode([byte[]]$Bytes) {
        return [Base85]::Encode($Bytes, $false)
    }
    static [string] Encode([byte[]]$Bytes, [bool]$Format) {
        # Using Format means we'll add "<~" Prefix and "~>" Suffix marks to output text
        [System.IO.Stream]$InputStream = New-Object -TypeName System.IO.MemoryStream(, $Bytes)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$Ascii85Output = [System.Text.StringBuilder]::new()
        if ($Format) {
            [void]$Ascii85Output.Append("<~")
            [System.UInt16]$LineLen = 2
        }
        $EncodedString = [string]::Empty
        Try {
            Write-Debug "[base85] Encoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([Byte[]]$BytesRead = $BinaryReader.ReadBytes(4)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 4) {
                    [System.Byte[]]$WorkingBytes = , 0x00 * 4
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 4)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 4)
                }
                if ([BitConverter]::IsLittleEndian) {
                    [Array]::Reverse($BytesRead)
                }
                [System.Char[]]$A85Chars = , 0x00 * 5
                [System.UInt32]$Sum = [BitConverter]::ToUInt32($BytesRead, 0)
                [System.UInt16]$ByteLen = [Math]::Ceiling(($ByteLength / 4) * 5)
                if ($ByteLength -eq 4 -And $Sum -eq 0) {
                    [System.Char[]]$A85Chunk = "z"
                } else {
                    [System.Char[]]$A85Chunk = , 0x00 * $ByteLen
                    $A85Chars[0] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 4)) % 85) + 33)[0]
                    $A85Chars[1] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 3)) % 85) + 33)[0]
                    $A85Chars[2] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85, 2)) % 85) + 33)[0]
                    $A85Chars[3] = [Base85]::GetChars([Math]::Floor(($Sum / 85) % 85) + 33)[0]
                    $A85Chars[4] = [Base85]::GetChars([Math]::Floor($Sum % 85) + 33)[0]
                    [Array]::Copy($A85Chars, $A85Chunk, $ByteLen)
                }
                forEach ($A85Char in $A85Chunk) {
                    [void]$Ascii85Output.Append($A85Char)
                    if (!$Format) {
                        if ($LineLen -eq 64) {
                            [void]$Ascii85Output.Append("`r`n")
                            $LineLen = 0
                        } else {
                            $LineLen++
                        }
                    }
                }
            }
            if ($Format) {
                if ($LineLen -le 62) {
                    [void]$Ascii85Output.Append("~>")
                } else {
                    [void]$Ascii85Output.Append("~`r`n>")
                }
            }
            $EncodedString = $Ascii85Output.ToString()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break;
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Encoding completed in $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Debug $TimeLapse
        }
        return $EncodedString
    }
    static [void] Encode([IO.FileInfo]$File) {
        [Base85]::Encode($File, $false, $File.FullName);
    }
    static [void] Encode([IO.FileInfo]$File, [bool]$Protect) {
        [Base85]::Encode($File, $Protect, $File.FullName);
    }
    static [void] Encode([IO.FileInfo]$File, [bool]$Protect, [string]$OutFile) {
        [Base85]::Encode($File, [securestring]$(if ($Protect) { [AesGCM]::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Encode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = [CryptoBase]::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [CryptoBase]::GetResolvedPath($File.FullName);
        if (![string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))) { [AesGCM]::Encrypt($File, $Password, $File.FullName) };
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        $encodedString = [Base85]::Encode($ba)
        $encodedBytes = [EncodingBase]::new().GetBytes($encodedString);
        $streamWriter = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encodedBytes, 0, $encodedBytes.Length);
        [void]$streamWriter.Close()
    }
    static [byte[]] Decode([string]$text) {
        $text = $text.Replace(" ", "").Replace("`r`n", "").Replace("`n", "")
        $decoded = $null; if ($text.StartsWith("<~") -or $text.EndsWith("~>")) {
            $text = $text.Replace("<~", "").Replace("~>", "")
        }
        if ($text -match $([Base85]::NON_A85_Pattern)) {
            Throw "Invalid Ascii85 data detected in input stream."
        }
        [System.Object]$InputStream = New-Object -TypeName System.IO.MemoryStream([System.Text.Encoding]::ASCII.GetBytes($text), 0, $text.Length)
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$OutputStream = New-Object -TypeName System.IO.MemoryStream
        [System.Object]$BinaryWriter = New-Object -TypeName System.IO.BinaryWriter($OutputStream)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        Try {
            Write-Debug "[base85] Decoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([System.Byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 5) {
                    [System.Byte[]]$WorkingBytes = , 0x75 * 5
                    [System.Buffer]::BlockCopy($BytesRead, 0, $WorkingBytes, 0, $ByteLength)
                    [Array]::Resize([ref]$BytesRead, 5)
                    [System.Buffer]::BlockCopy($WorkingBytes, 0, $BytesRead, 0, 5)
                }
                [System.UInt16]$ByteLen = [Math]::Floor(($ByteLength * 4) / 5)
                [System.Byte[]]$BinChunk = , 0x00 * $ByteLen
                if ($BytesRead[0] -eq 0x7A) {
                    $BinaryWriter.Write($BinChunk)
                    [bool]$IsAtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                    if (!$IsAtEnd) {
                        $BinaryReader.BaseStream.Position = $BinaryReader.BaseStream.Position - 4
                        Continue
                    }
                } else {
                    [System.UInt32]$Sum = 0
                    $Sum += ($BytesRead[0] - 33) * [Math]::Pow(85, 4)
                    $Sum += ($BytesRead[1] - 33) * [Math]::Pow(85, 3)
                    $Sum += ($BytesRead[2] - 33) * [Math]::Pow(85, 2)
                    $Sum += ($BytesRead[3] - 33) * 85
                    $Sum += ($BytesRead[4] - 33)
                    [System.Byte[]]$A85Bytes = [System.BitConverter]::GetBytes($Sum)
                    if ([BitConverter]::IsLittleEndian) {
                        [Array]::Reverse($A85Bytes)
                    }
                    [System.Buffer]::BlockCopy($A85Bytes, 0, $BinChunk, 0, $ByteLen)
                    $BinaryWriter.Write($BinChunk)
                }
            }
            $decoded = $OutputStream.ToArray()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $BinaryWriter.Close()
            $BinaryWriter.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $OutputStream.Close()
            $OutputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Decoding completed after $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Debug $TimeLapse
        }
        return $decoded
    }
    static [void] Decode([IO.FileInfo]$File) {
        [Base85]::Decode($File, $false, $File);
    }
    static [void] Decode([IO.FileInfo]$File, [bool]$UnProtect) {
        [Base85]::Decode($File, $UnProtect, $File);
    }
    static [void] Decode([IO.FileInfo]$File, [bool]$UnProtect, [string]$OutFile) {
        [Base85]::Decode($File, [securestring]$(if ($UnProtect) { [AesGCM]::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Decode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = [CryptoBase]::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [CryptoBase]::GetResolvedPath($File.FullName);
        [byte[]]$ba = [IO.FILE]::ReadAllBytes($File.FullName)
        [byte[]]$da = [Base85]::Decode([EncodingBase]::new().GetString($ba))
        [void][IO.FILE]::WriteAllBytes($OutFile, $da)
        if (![string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))) { [AesGCM]::Decrypt([IO.FileInfo]::new($OutFile), $Password, $OutFile) }
    }
}
#endregion Base85

# Custom cli writer class and stuff
# .EXAMPLE
# [cli]::Preffix = [CipherTron]::Tmp.emojis.bot
# [void][cli]::Write('animations and stuff', [ConsoleColor]::Magenta)
class cli {
    static hidden [ValidateNotNull()][string]$Preffix
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
        return [convert]::ToBase64String([xconvert]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes([base85]::Encode($ArtBytes))))
    }
    static [string] ToBase64String([IO.FileInfo]$Artfile) {
        return [CliArt]::ToBase64String([IO.File]::ReadAllBytes($Artfile.FullName))
    }
    static [string] FromBase64String([string]$B64String) {
        return [System.Text.Encoding]::UTF8.GetString([Base85]::Decode([System.Text.Encoding]::UTF8.GetString([xconvert]::ToDeCompressed([convert]::FromBase64String($B64String)))))
    }
    [string] ToString() {
        return [CliArt]::FromBase64String($this.Base64String)
    }
}


#region    Shuffl3r
# .SYNOPSIS
#     Shuffles bytes and nonce into a jumbled byte[] mess that can be split using a password.
#     Can be used to Combine the encrypted data with the initialization vector (IV) and other data.
# .DESCRIPTION
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible. ie: As long as your source code isn't leaked :)
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
# .EXAMPLE
#     $_bytes = [System.text.Encoding]::UTF8.GetBytes('** _H4ck_z3_W0rld_ **');
#     $Nonce1 = [CryptoBase]::GetRandomEntropy();
#     $Nonce2 = [CryptoBase]::GetRandomEntropy();
#     $Passwd = [xconvert]::ToSecurestring('OKay_&~rVJ+T?NpJ(8TqL');
#     $shuffld = [Shuffl3r]::Combine([Shuffl3r]::Combine($_bytes, $Nonce2, $Passwd), $Nonce1, $Passwd);
#     ($b,$n1) = [Shuffl3r]::Split($shuffld, $Passwd, $Nonce1.Length);
#     ($b,$n2) = [Shuffl3r]::Split($b, $Passwd, $Nonce2.Length);
#     [System.text.Encoding]::UTF8.GetString($b) -eq '** _H4ck_z3_W0rld_ **' # should be $true
class Shuffl3r {
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
        return [Shuffl3r]::Combine($bytes, $Nonce, [xconvert]::ToString($Passwod))
    }
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
        # if ($Bytes.Length -lt 16) { throw [InvalidArgumentException]::New('Bytes', 'Input bytes.length should be > 16. ie: $minLength = 17, since the common $nonce length is 16') }
        if ($bytes.Length -lt ($Nonce.Length + 1)) {
            Write-Debug "Bytes.Length = $($Bytes.Length) but Nonce.Length = $($Nonce.Length)" -Debug
            throw [System.ArgumentOutOfRangeException]::new("Nonce", 'Make sure $Bytes.length > $Nonce.Length')
        }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new($Nonce.Length);
        Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
        [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
        for ([int]$i = 0; $i -lt $Indices.Length; $i++) {
            $combined[$Indices[$i]] = $Nonce[$i]
        }
        $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
        foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
        return $combined
    }
    static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
        return [Shuffl3r]::Split($ShuffledBytes, [xconvert]::ToString($Passwod), [int]$NonceLength);
    }
    static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
        if ($null -eq $ShuffledBytes) { throw [System.ArgumentNullException]::new('$ShuffledBytes') }
        if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
        [int[]]$Indices = [int[]]::new([int]$NonceLength);
        Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
        $Nonce = [Byte[]]::new($NonceLength);
        $bytes = [Byte[]]$((0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices } | Select-Object *, @{l = 'bytes'; e = { $ShuffledBytes[$_] } }).bytes
        for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
        return ($bytes, $Nonce)
    }
    static [string] Scramble([string]$string, [securestring]$password) {
        if ([string]::IsNullOrWhiteSpace($string)) {
            throw [System.Management.Automation.ValidationMetadataException]::new("The variable cannot be validated because the value '$string' is not a valid value for the `$string variable.")
        }; [ValidateNotNullOrEmpty()][securestring]$password = $password
        $in = [shuffl3r]::GenerateIndices($string, $password) + 0
        $ca = $string.ToCharArray()
        return [string]::Join('', $in.ForEach({ $ca[$_] }))
    }
    static [string] UnScramble([string]$string, [securestring]$password) {
        if ([string]::IsNullOrWhiteSpace($string)) {
            throw [System.Management.Automation.ValidationMetadataException]::new("The variable cannot be validated because the value '$string' is not a valid value for the `$string variable.")
        }; [ValidateNotNullOrEmpty()][securestring]$password = $password
        $in = [shuffl3r]::GenerateIndices($string, $password) + 0
        $ca = $string.ToCharArray()
        $re = @(); 0..$ca.Count | ForEach-Object {
            $re += [PSCustomObject]@{
                char  = $ca[$_]
                index = $in[$_]
            }
        }
        return [string]::Join('', ($re | Sort-Object -Property index).char)
    }
    static [int[]] GenerateIndices([string]$string, [securestring]$password) {
        return [Shuffl3r]::GenerateIndices(($string.Length - 1), [convert]::ToBase64String([cryptobase]::GetDerivedBytes($password)), $string.Length)
    }
    static [int[]] GenerateIndices([int]$Count, [string]$string, [int]$HighestIndex) {
        if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [System.ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
        if ([string]::IsNullOrWhiteSpace($string)) { throw [System.ArgumentNullException]::new('$string') }
        [Byte[]]$hash = [Shuffl3r]::ComputeHash($string)
        [int[]]$indices = [int[]]::new($Count)
        for ($i = 0; $i -lt $Count; $i++) {
            [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
            while ($indices -contains $nextIndex) {
                $nextIndex = ($nextIndex + 1) % $HighestIndex
            }
            $indices[$i] = $nextIndex
        }
        return $indices
    }
    static [byte[]] ComputeHash([string]$string) {
        # returns the same hash even if the input string is scrambled.
        return [System.Security.Cryptography.SHA1]::Create().ComputeHash($([System.Text.Encoding]::UTF8.GetBytes([string]$string) | Sort-Object))
    }
}
#endregion Shuffl3r

#region    AesGCM
# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $bytes = GetbytesFromObj('Text_Message1'); $Password = [xconvert]::ToSecurestring('X-aP0jJ_:No=08TfdQ'); $salt = [CryptoBase]::GetRandomEntropy();
#     $enc = [AesGCM]::Encrypt($bytes, $Password, $salt)
#     $dec = [AesGCM]::Decrypt($enc, $Password, $salt)
#     echo ([System.Text.Encoding]::UTF8.GetString($dec).Trim()) # should be: Text_Message1
# .EXAMPLE
#     $bytes = [System.Text.Encoding]::UTF8.GetBytes("S3crEt message...")
#     $enc = [Aesgcm]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#     $secmessage = [convert]::ToBase64String($enc)
#
#     # On recieving PC:
#     $dec = [AesGcm]::Decrypt([convert]::FromBase64String($secmessage), (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo ([System.Text.Encoding]::UTF8.GetString($dec)) # should be: S3crEt message...
# .NOTES
#  Todo: Find a working/cross-platform way to protect bytes (Like DPAPI for windows but better) then
#  add static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [bool]$Protect, [string]$Compression, [int]$iterations)
class AesGCM : CryptoBase {
    # static hidden [byte[]]$_salt = [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==");
    static hidden [EncryptionScope] $Scope = [EncryptionScope]::User
    static [byte[]] Encrypt([byte[]]$bytes) {
        if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        return [AesGCM]::Encrypt($bytes, [AesGCM]::GetPassword());
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = $bytes;
            $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$([AesGCM]::caller) [+] Encryption [$i/$iterations] ... Done" -f Yellow
                # if ($Protect) { $_bytes = [xconvert]::ToProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Generate a random IV for each iteration:
                [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
                $tag = [byte[]]::new($TAG_SIZE);
                $Encrypted = [byte[]]::new($_bytes.Length);
                [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
                $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
            }
        } catch {
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        if (![string]::IsNullOrWhiteSpace($Compression)) {
            $_bytes = [xconvert]::ToCompressed($_bytes, $Compression);
        }
        return $_bytes
    }
    static [void] Encrypt([IO.FileInfo]$File) {
        if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        [AesGCM]::Encrypt($File, [AesGCM]::GetPassword());
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password) {
        [AesGCM]::Encrypt($File, $Password, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath) {
        [AesGCM]::Encrypt($File, $password, $OutPath, 1, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
        [AesGCM]::Encrypt($File, $password, $OutPath, $iterations, $null);
    }
    static [void] Encrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
        [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
        if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        Write-Verbose "$([AesGCM]::caller) Begin file encryption:"
        Write-Verbose "[-]  File    : $File"
        Write-Verbose "[-]  OutFile : $OutPath"
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password);
        $encryptdbytes = [AesGCM]::Encrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
        $streamWriter = [System.IO.FileStream]::new($OutPath, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encryptdbytes, 0, $encryptdbytes.Length);
        [void]$streamWriter.Close()
        [void]$streamReader.Dispose()
        [void]$streamWriter.Dispose()
    }
    static [byte[]] Decrypt([byte[]]$bytes) {
        if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        return [AesGCM]::Decrypt($bytes, [AesGCM]::GetPassword());
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
        return [System.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password)
        return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
        return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
    }
    static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
        [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
        [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { [xconvert]::ToDecompressed($bytes, $Compression) } else { $bytes }
            $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$([AesGCM]::caller) [+] Decryption [$i/$iterations] ... Done" -f Yellow
                # if ($UnProtect) { $_bytes = [xconvert]::ToUnProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Split the real encrypted bytes from nonce & tags then decrypt them:
                ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                $Decrypted = [byte[]]::new($b.Length);
                $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                $_bytes = $Decrypted;
            }
        } catch {
            if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                Write-Host "$([AesGCM]::caller) Wrong password" -f Yellow
            }
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        return $_bytes
    }
    static [void] Decrypt([IO.FileInfo]$File) {
        if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
        [AesGCM]::Decrypt($File, [AesGCM]::GetPassword());
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$password) {
        [AesGCM]::Decrypt($File, $password, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath) {
        [AesGCM]::Decrypt($File, $password, $OutPath, 1, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
        [AesGCM]::Decrypt($File, $password, $OutPath, $iterations, $null);
    }
    static [void] Decrypt([IO.FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
        [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
        if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
        $streamReader = [System.IO.FileStream]::new($File.FullName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        Write-Verbose "$([AesGCM]::caller) Begin file decryption:"
        Write-Verbose "[-]  File    : $File"
        Write-Verbose "[-]  OutFile : $OutPath"
        [byte[]]$_salt = [AesGCM]::GetDerivedBytes($Password);
        $decryptdbytes = [AesGCM]::Decrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
        $streamWriter = [System.IO.FileStream]::new($OutPath, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($decryptdbytes, 0, $decryptdbytes.Length);
        [void]$streamWriter.Close()
        [void]$streamReader.Dispose()
        [void]$streamWriter.Dispose()
    }
}
#endregion AesGCM

#region     GitHub
class GitHub {
    static $webSession
    static [string] $UserName
    static hidden [bool] $IsInteractive = $false
    static hidden [string] $TokenFile = [GitHub]::GetTokenFile()

    static [PSObject] createSession() {
        return [Github]::createSession([Github]::UserName)
    }
    static [PSObject] createSession([string]$UserName) {
        [GitHub]::SetToken()
        return [GitHub]::createSession($UserName, [GitHub]::GetToken())
    }
    static [Psobject] createSession([string]$GitHubUserName, [securestring]$clientSecret) {
        [ValidateNotNullOrEmpty()][string]$GitHubUserName = $GitHubUserName
        [ValidateNotNullOrEmpty()][string]$GithubToken = $GithubToken = [xconvert]::Tostring([securestring]$clientSecret)
        $encodedAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($GitHubUserName):$($GithubToken)"))
        $web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        [void]$web_session.Headers.Add('Authorization', "Basic $($encodedAuth)")
        [void]$web_session.Headers.Add('Accept', 'application/vnd.github.v3+json')
        [GitHub]::webSession = $web_session
        return $web_session
    }
    static [void] SetToken() {
        [GitHub]::SetToken([xconvert]::Tostring((Read-Host -Prompt "[GitHub] Paste/write your api token" -AsSecureString)), $(Read-Host -Prompt "[GitHub] Paste/write a Password to encrypt the token" -AsSecureString))
    }
    static [void] SetToken([string]$token, [securestring]$password) {
        if (![IO.File]::Exists([GitHub]::TokenFile)) { New-Item -Type File -Path ([GitHub]::TokenFile) -Force | Out-Null }
        [IO.File]::WriteAllText([GitHub]::TokenFile, [convert]::ToBase64String([AesGCM]::Encrypt([system.Text.Encoding]::UTF8.GetBytes($token), $password)), [System.Text.Encoding]::UTF8);
    }
    static [securestring] GetToken() {
        $sectoken = $null; $session_pass = [xconvert]::ToSecurestring('123');
        try {
            if ([GitHub]::IsInteractive) {
                if ([string]::IsNullOrWhiteSpace((Get-Content ([GitHub]::TokenFile) -ErrorAction Ignore))) {
                    Write-Host "[GitHub] You'll need to set your api token first. This is a One-Time Process :)" -f Green
                    [GitHub]::SetToken()
                    Write-Host "[GitHub] Good, now let's use the api token :)" -f DarkGreen
                } elseif ([GitHub]::ValidateBase64String([IO.File]::ReadAllText([GitHub]::TokenFile))) {
                    Write-Host "[GitHub] Encrypted token found in file: $([GitHub]::TokenFile)" -f DarkGreen
                } else {
                    throw [System.Exception]::New("Unable to read token file!")
                }
                $session_pass = Read-Host -Prompt "[GitHub] Input password to use your token" -AsSecureString
            } else {
                #Fix: Temporary Workaround: Thisz a pat from one of my GitHub a/cs.It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!!
                $et = "+yDHse2ViCRxp7dBqhOa6Lju6Ww67ldUU2OaxG8w8aKqLsCmvsQB92Kv5YmYD7RFklr7Bc1dTeQlji38W3ha6RF9PneH1+7xd/8IFCkknVB6POZZANiSiaflmzq1dWxMIUzI6dzDBwNi6Xi0MSsRr6kjI+dqcQ5wZA=="
                [GitHub]::SetToken([system.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($et), $session_pass)), $session_pass)
            }
            $sectoken = [xconvert]::ToSecurestring([system.Text.Encoding]::UTF8.GetString(
                    [AesGCM]::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText([GitHub]::GetTokenFile())), $session_pass)
                )
            )
        } catch {
            throw $_
        }
        return $sectoken
    }
    static [PsObject] GetUserInfo([string]$UserName) {
        if ([string]::IsNullOrWhiteSpace([GitHub]::userName)) { [GitHub]::createSession() }
        $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    static [PsObject] GetGist([uri]$Uri) {
        $l = [GistFile]::Create($Uri)
        return [GitHub]::GetGist($l.Owner, $l.Id)
    }
    static [PsObject] GetGist([string]$UserName, [string]$GistId) {
        $t = [GitHub]::GetToken()
        if ($null -eq ([GitHub]::webSession)) {
            [GitHub]::webSession = $(if ($null -eq $t) {
                    [GitHub]::createSession($UserName)
                } else {
                    [GitHub]::createSession($UserName, $t)
                }
            )
        }
        if (!((Test-Connection github.com -Count 1 -ErrorAction Ignore).status -eq "Success")) {
            throw [System.Net.NetworkInformation.PingException]::new("PingException, PLease check your connection!");
        }
        if ([string]::IsNullOrWhiteSpace($GistId) -or $GistId -eq '*') {
            return Get-Gists -UserName $UserName -SecureToken $t
        }
        return Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
    }
    Static [string] GetGistContent([string]$FileName, [uri]$GistUri) {
        return [GitHub]::GetGist($GistUri).files.$FileName.content
    }
    static [PsObject] CreateGist([string]$description, [array]$files) {
        $url = 'https://api.github.com/gists'
        $body = @{
            description = $description
            files       = @{}
        }
        foreach ($file in $files) {
            $body.files[$file.Name] = @{
                content = $file.Content
            }
        }
        $response = Invoke-RestMethod -Uri $url -WebSession ([GitHub]::webSession) -Method Post -Body ($body | ConvertTo-Json) -Verbose:$false
        return $response
    }
    static [PsObject] UpdateGist([GistFile]$gist, [string]$NewContent) {
        return ''
    }
    static [string] GetTokenFile() {
        if (![IO.File]::Exists([GitHub]::TokenFile)) {
            [GitHub]::TokenFile = [IO.Path]::Combine([GitHub]::Get_dataPath('Github', 'clicache'), "token");
        }
        return [GitHub]::TokenFile
    }
    static [PsObject] GetUserRepositories() {
        if ($null -eq [GitHub]::webSession) { [Github]::createSession() }
        $response = Invoke-RestMethod -Uri 'https://api.github.com/user/repos' -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    static [psobject] ParseLink([string]$text, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][string]$text = $text
        $uri = $text -as 'Uri'; if ($uri -isnot [Uri] -and $throwOnFailure) {
            throw [System.InvalidOperationException]::New("Could not create uri from text '$text'.")
        }; $Scheme = $uri.Scheme
        if ([regex]::IsMatch($text, '^(\/[a-zA-Z0-9_-]+)+|([a-zA-Z]:\\(((?![<>:"\/\\|?*]).)+\\?)*((?![<>:"\/\\|?*]).)+)$')) {
            if ($text.ToCharArray().Where({ $_ -in [IO.Path]::InvalidPathChars }).Count -eq 0) {
                $Scheme = 'file'
            } else {
                Write-Debug "'$text' has invalidPathChars in it !" -Debug
            }
        }
        $IsValid = $Scheme -in @('file', 'https')
        $IsGistUrl = [Regex]::IsMatch($text, 'https?://gist\.github\.com/\w+/[0-9a-f]+')
        $OutptObject = [pscustomobject]@{
            FullName = $text
            Scheme   = [PSCustomObject]@{
                Name      = $Scheme
                IsValid   = $IsValid
                IsGistUrl = $IsGistUrl
            }
        }
        return $OutptObject
    }
    static [string] Get_Host_Os() {
        # Should return one of these: [Enum]::GetNames([System.PlatformID])
        return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
    }
    static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
        $_Host_OS = [GitHub]::Get_Host_Os()
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
            throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
        }
        if (!$dataPath.Exists) { [GitHub]::Create_Dir($dataPath) }
        return $dataPath
    }
    static [void] Create_Dir([string]$Path) {
        [GitHub]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
    }
    static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
    }
    static [bool] ValidateBase64String([string]$base64) {
        return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
    }
    static [bool] IsConnected() {
        if (![bool]("System.Net.NetworkInformation.Ping" -as 'type')) { Add-Type -AssemblyName System.Net.NetworkInformation };
        $cs = $null; $re = @{ true = @{ m = "Success"; c = "Green" }; false = @{ m = "Failed"; c = "Red" } }
        Write-Host "[Github] Testing Connection ... " -f Blue -NoNewline
        try {
            [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("github.com");
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
}
class GistFile {
    [string]$Name # with extention
    [string]$language
    [string]$type
    [string]$Owner
    [string]$raw_url
    [bool]$IsPublic
    [bool]$truncated
    [string]$Id
    [int]$size
    [GistFile[]]$files
    hidden [string]$content
    static [string]$UserName
    static [PsObject]$ChildItems
    GistFile([string]$filename) {
        $this.Name = $filename
    }
    GistFile([PsObject]$GistInfo) {
        $this.language = $GistInfo.language
        $this.IsPublic = $GistInfo.IsPublic
        $this.raw_url = $GistInfo.raw_url
        $this.type = $GistInfo.type
        $this.Name = $GistInfo.filename
        $this.size = $GistInfo.size
        $this.Id = $GistInfo.Id
        $this.Owner = $GistInfo.Owner
        if ([string]::IsNullOrWhiteSpace($this.Owner)) {
            if (![string]::IsNullOrWhiteSpace([GistFile]::UserName)) {
                $this.Owner = [GistFile]::UserName
            } else {
                Write-Warning "Gist Owner was not set!"
            }
        }
        if ($null -eq ([GistFile]::ChildItems) -and ![string]::IsNullOrWhiteSpace($this.Id)) {
            [GistFile]::ChildItems = [GitHub]::GetGist($this.Owner, $this.Id).files
        }
        if ($null -ne [GistFile]::ChildItems) {
            $_files = $null; [string[]]$filenames = [GistFile]::ChildItems | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            try {
                $_files = [GistFile[]]$filenames.Foreach({
                        $_Item = [GistFile]::ChildItems."$_"
                        $_Gist = [GistFile]::new($_Item.filename)
                        $_Gist.language = $_Item.language
                        $_Gist.Ispublic = $this.IsPublic
                        $_Gist.raw_url = $_Item.raw_url
                        $_Gist.type = $_Item.type
                        $_Gist.size = $_Item.size
                        $_Gist.content = $_Item.content
                        $_Gist.Owner = $this.Owner; $_Gist.Id = $this.Id
                        $_Gist
                    }
                )
            } finally {
                [GistFile]::ChildItems = $null
                $this.files = $_files
                if ([string]::IsNullOrWhiteSpace($this.Name)) {
                    $this.Name = $filenames[0]
                }
            }
        }
    }
    static [GistFile] Create([uri]$GistUri) {
        $res = $null; $ogs = $GistUri.OriginalString
        $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
        $seg = $GistUri.Segments
        $res = $(if ($IsRawUri) {
                $_name = $seg[-1]
                $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                $rtri = $rtri.Remove($rtri.Length - 1)
                $info = [GitHub]::GetGist([uri]::new($rtri))
                $file = $info.files."$_name"
                [PsCustomObject]@{
                    language = $file.language
                    IsPublic = $info.IsPublic
                    raw_url  = $file.raw_url
                    Owner    = $info.owner.login
                    type     = $file.type
                    filename = $_name
                    size     = $file.size
                    Id       = $seg[2].Replace('/', '')
                }
            } else {
                # $info = [GitHub]::GetGist($GistUri)
                [PsCustomObject]@{
                    language = ''
                    IsPublic = $null
                    raw_url  = ''
                    Owner    = $seg[1].Split('/')[0]
                    type     = ''
                    filename = ''
                    size     = ''
                    Id       = $seg[-1]
                }
            }
        )
        if (![string]::IsNullOrWhiteSpace($res.Owner)) {
            [GistFile]::UserName = $res.Owner
        }
        return [GistFile]::New($res)
    }
    [string] ShowFileInfo() {
        return "File: $($this.Name)"
    }
}

class Gist {
    [uri] $Uri
    [string] $Id
    [string] $Owner
    [string] $Description
    [bool] $IsPublic
    [GistFile[]] $Files = @()

    Gist() {}
    Gist([string]$Name) {
        $this.AddFile([GistFile]::new($Name))
    }
    [psobject] Post() {
        $gisfiles = @()
        $this.Files.Foreach({
                $gisfiles += @{
                    $_.Name = @{
                        content = $_.Content
                    }
                }
            }
        )
        $data = @{
            files       = $gisfiles
            description = $this.Description
            public      = $this.IsPublic
        } | ConvertTo-Json

        Write-Verbose ($data | Out-String)
        Write-Verbose "[PROCESS] Posting to https://api.github.com/gists"
        $invokeParams = @{
            Method      = 'Post'
            Uri         = "https://api.github.com/gists"
            WebSession  = [GitHub]::webSession
            Body        = $data
            ContentType = 'application/json'
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod @invokeParams
        $r = $r | Select-Object @{Name = "Url"; Expression = { $_.html_url } }, Description, Public, @{Name = "Created"; Expression = { $_.created_at -as [datetime] } }
        return $r
    }
    [void] AddFile([GistFile]$file) {
        $this.Files += $file
    }
    [string] ShowInfo() {
        $info = "Gist ID: $($this.Id)"
        $info += "`nDescription: $($this.Description)"
        $info += "`nFiles:"
        foreach ($file in $this.Files.Values) {
            $info += "`n  - $($file.ShowFileInfo())"
        }
        return $info
    }
}

#endregion GitHub

class RecordMap {
    hidden [uri] $Remote # usually a gist uri
    hidden [string] $File
    hidden [bool] $IsSynchronized
    [datetime] $LastWriteTime = [datetime]::Now
    static hidden [string] $caller = '[RecordMap]'
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
            $pass = $null; if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = [RecordMap]::caller }
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordMap]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
            $_ob = [xconvert]::Deserialize([xconvert]::ToDeCompressed([AesGCM]::Decrypt([base85]::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
            $this.Set([hashtable[]]$_ob.Properties.Name.ForEach({ @{ $_ = $_ob.$_ } }))
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
    }
    [void] Import([String]$FilePath) {
        Write-Host "$([RecordMap]::caller) Import records: $FilePath ..." -f Green
        $this.Set([RecordMap]::Read($FilePath))
        Write-Host "$([RecordMap]::caller) Import records Complete" -f Green
    }
    [void] Upload() {
        if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [InvalidArgumentException]::new('remote') }
        # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
        # [GitHub]::UpdateGist($gisturi, $content)
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
        $pass = $null; $cfg = $null; $FilePath = [AesGCM]::GetResolvedPath($FilePath);
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [FileNotFoundException]::new("File not found: $FilePath") }
        if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = 'ArgonCage' }
        Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordMap]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
        $txt = [IO.File]::ReadAllText($FilePath)
        $_ob = [xconvert]::Deserialize([xconvert]::ToDeCompressed([AesGCM]::Decrypt([base85]::Decode($txt), $pass)))
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
        $FilePath = [AesGCM]::GetResolvedPath($FilePath);
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [FileNotFoundException]::new("File not found: $FilePath") }
        $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
        try {
            [NetworkManager]::BlockAllOutbound()
            if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -f Magenta }
            $parsed_content = [RecordMap]::Read("$FilePath");
            [ValidateNotNullOrEmpty()][hashtable[]]$parsed_content = $parsed_content
            $parsed_content | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
            if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
            $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
        } finally {
            [NetworkManager]::UnblockAllOutbound()
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
            Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value ([FileMonitor]::GetLogSummary()) | Out-Null
            if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -f Magenta }
            if ($null -ne $config_ob) { $result = $config_ob.ForEach({ [xconvert]::ToHashTable($_) }) }
            if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -f Magenta }
        }
        return $result
    }
    [void] Save() {
        $pass = $null;
        try {
            Write-Host "$([RecordMap]::caller) Saving records to file: $($this.File) ..." -f Blue
            Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([CryptoBase]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordMap]::caller) Paste/write a Password to encrypt configs" -AsSecureString } else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
            $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, [Base85]::Encode([AesGCM]::Encrypt([xconvert]::ToCompressed($this.ToByte()), $pass)), [System.Text.Encoding]::UTF8)
            Write-Host "$([RecordMap]::caller) Saving records " -f Blue -NoNewline; Write-Host "Completed." -f Green
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Pass -Force -ErrorAction SilentlyContinue
        }
    }
    [byte[]] ToByte() {
        return [xconvert]::Serialize($this)
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
class SessionTmp {
    [ValidateNotNull()][RecordMap]$vars
    [ValidateNotNull()][System.Collections.Generic.List[string]]$Paths
    SessionTmp() {
        $this.vars = [RecordMap]::new()
        $this.Paths = [System.Collections.Generic.List[string]]::new()
    }
    [void] Clear() {
        $this.vars = [RecordMap]::new()
        $this.Paths | ForEach-Object { Remove-Item "$_" -ErrorAction SilentlyContinue }; $this.Paths = [System.Collections.Generic.List[string]]::new()
    }
}
class FileMonitor {
    static [bool] $FileClosed = $true
    static [bool] $FileLocked = $false
    static [System.ConsoleKeyInfo[]] $Keys = @()
    static [ValidateNotNull()][IO.FileInfo] $FileTowatch
    static [ValidateNotNull()][string] $LogvariableName = $(if ([string]::IsNullOrWhiteSpace([FileMonitor]::LogvariableName)) {
            $n = ('fileMonitor_log_' + [guid]::NewGuid().Guid).Replace('-', '_');
            Set-Variable -Name $n -Scope Global -Value ([string[]]@()); $n
        } else {
            [FileMonitor]::LogvariableName
        }
    )
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File) {
        return [FileMonitor]::monitorFile($File, { Write-Host "[+] File monitor Completed" -f Green })
    }
    static [System.IO.FileSystemWatcher] MonitorFile([string]$File, [scriptblock]$Action) {
        [ValidateNotNull()][IO.FileInfo]$File = [IO.FileInfo][CryptoBase]::GetUnResolvedPath($File)
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

class SecretStore {
    [string]$Name
    [uri]$Url
    static hidden [ValidateNotNullOrEmpty()][string]$DataPath

    SecretStore([string]$Name) {
        $this.Name = $Name
        if ([string]::IsNullOrWhiteSpace([SecretStore]::DataPath)) {
            [SecretStore]::DataPath = [IO.Path]::Combine([cryptobase]::Get_dataPath('ArgonCage', 'Data'), 'secrets')
        }
        $this.psobject.Properties.Add([psscriptproperty]::new('File', {
                    return [IO.FileInfo]::new([IO.Path]::Combine([SecretStore]::DataPath, $this.Name))
                }, {
                    param($value)
                    if ($value -is [IO.FileInfo]) {
                        [SecretStore]::DataPath = $value.Directory.FullName
                        $this.Name = $value.Name
                    } else {
                        throw "Invalid value assigned to File property"
                    }
                }
            )
        )
        $this.psobject.Properties.Add([psscriptproperty]::new('Size', {
                    if ([IO.File]::Exists($this.File.FullName)) {
                        $this.File = Get-Item $this.File.FullName
                        return $this.File.Length
                    }
                    return 0
                }, { throw "Cannot set Size property" }
            )
        )
    }
}
#region    HKDF2
# .SYNOPSIS
#     A custom HMAC Key Derivation class (System.Security.Cryptography.HKDF) using PBKDF2 algorithm.
# .DESCRIPTION
#     Here's a basic scenario of why I use this:
#     IRL when a user inputs a password, instead of storing the password in cleartext, we hash the password and store the username and hash pair in the database table.
#     When the user logs in, we hash the input password and compare the calculated hash with what we have in the database.
#     Cool and that's what this class does but also checks if the password has expired or not.
#
#     The token basically stores expiration date and hash of the Password.
#     but the token is encryptd /jumbled and can only be read if the InputPassword's hash matches the CalculatedHash.
#
#     This class can also be used to check the validity of the input password before deriving it.
# .EXAMPLE
#
#     The main use is to never store the actual input password, rather keep its hash
#     # STEP 1. Create Hash and Store it somewhere secure.
#     $hashSTR = [HKDF2]::GetToken((Read-Host -Prompt "password" -AsSecureString))
#     $hashSTR | Out-File ReallySecureFilePath; # keep the hash string it in a file Or in a database
#
#     # STEP 2. Use the Hash to verify if $InputPassword is legit, then login/orNot
#     [SecureString]$InputPassword = Read-Host -Prompt "password" -AsSecureString
#     $IsValidPasswd = [HKDF2]::VerifyToken((cat ReallySecureFilePath), $InputPassword)
#
#    Real Use case:
#    # STEP 1.
#    $InputPass = Read-Host -Prompt "Password to encrypt" -AsSecureString
#    [HKDF2]::GetToken($InputPass) | Out-File ReallySecureFilePath; # keep the hash string it in a file Or in a database
#    $Password2Use = [HKDF2]::Resolve($InputPass, (cat ReallySecureFilePath)) # get derived password, and use itinstead of input password
#
#    # STEP 2.
#    $Password2Use = [HKDF2]::Resolve((Read-Host -Prompt "password ro decrypt" -AsSecureString), (cat ReallySecureFilePath))
# .NOTES
#     Inspired by: - https://asecuritysite.com/powershell/enc07
#                  - https://stackoverflow.com/questions/51941509/what-is-the-process-of-checking-passwords-in-databases/51961121#51961121
class HKDF2 {
    [byte[]] $Salt
    [int] $IterationCount
    [int] $BlockSize
    [UInt32] $BlockIndex
    [byte[]] $BufferBytes
    [int] $BufferStartIndex
    [int] $BufferEndIndex
    [System.Security.Cryptography.HMAC] $Algorithm

    HKDF2() {}
    HKDF2([byte[]]$bytes) {
        $ob = [HKDF2]::Create($bytes)
        $this.PsObject.Properties.Name.ForEach({ $this.$_ = $ob.$_ })
    }
    HKDF2([securestring]$secretKey) {
        $ob = [HKDF2]::Create($secretKey)
        $this.PsObject.Properties.Name.ForEach({ $this.$_ = $ob.$_ })
    }
    HKDF2([securestring]$secretKey, [byte[]]$salt) {
        $ob = [HKDF2]::Create($secretKey, $salt)
        $this.PsObject.Properties.Name.ForEach({ $this.$_ = $ob.$_ })
    }
    [byte[]] GetBytes() {
        return $this.GetBytes(32)
    }
    [byte[]] GetBytes([int]$count) {
        # Returns a pseudo-random key. $count is number of bytes to return.
        $result = [byte[]]::New($count)
        $resultOffset = 0
        $bufferCount = $this.BufferEndIndex - $this.BufferStartIndex

        if ($bufferCount -gt 0) {
            if ($count -lt $bufferCount) {
                [Buffer]::BlockCopy($this.BufferBytes, $this.BufferStartIndex, $result, 0, $count)
                $this.BufferStartIndex += $count
                return $result
            }
            [Buffer]::BlockCopy($this.BufferBytes, $this.BufferStartIndex, $result, 0, $bufferCount)
            $this.BufferStartIndex = $this.BufferEndIndex = 0
            $resultOffset += $bufferCount
        }
        while ($resultOffset -lt $count) {
            $needCount = $count - $resultOffset
            $this.BufferBytes = $this.GetHashBuffer()
            if ($needCount -gt $this.BlockSize) {
                [Buffer]::BlockCopy($this.BufferBytes, 0, $result, $resultOffset, $this.BlockSize)
                $resultOffset += $this.BlockSize
            } else {
                [Buffer]::BlockCopy($this.BufferBytes, 0, $result, $resultOffset, $needCount)
                $this.BufferStartIndex = $needCount
                $this.BufferEndIndex = $this.BlockSize
                return $result
            }
        }
        return $result
    }
    [byte[]] GetHashBuffer() {
        $hash1Input = [byte[]]::New(($this.Salt.Length + 4))
        [Buffer]::BlockCopy($this.Salt, 0, $hash1Input, 0, $this.Salt.Length)
        [Buffer]::BlockCopy($this.GetBytesFromInt($this.BlockIndex), 0, $hash1Input, $this.Salt.Length, 4)
        $hash1 = $this.Algorithm.ComputeHash($hash1Input)

        $finalHash = $hash1
        for ($i = 2; $i -le $this.IterationCount; $i++) {
            $hash1 = $this.Algorithm.ComputeHash($hash1, 0, $hash1.Length)
            for ($j = 0; $j -lt $this.BlockSize; $j++) {
                $finalHash[$j] = [byte]($finalHash[$j] -bxor $hash1[$j])
            }
        }
        if ($this.BlockIndex -eq [UInt32]::MaxValue) { throw "Derived key too long." }
        $this.BlockIndex += 1
        return $finalHash
    }
    [byte[]] GetBytesFromInt([UInt32] $i) {
        $bytes = [BitConverter]::GetBytes($i)
        if ([BitConverter]::IsLittleEndian) {
            return @($bytes[3], $bytes[2], $bytes[1], $bytes[0])
        } else {
            return $bytes
        }
    }
    static [HKDF2] Create([byte[]]$bytes) {
        $dsalt = [cryptobase]::GetDerivedBytes([xconvert]::ToSecurestring([System.Text.Encoding]::UTF8.GetString($bytes)))
        return [HKDF2]::Create($bytes, $dsalt)
    }
    static [HKDF2] Create([securestring]$secretKey) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([xconvert]::Tostring($secretKey))
        $dsalt = [cryptobase]::GetDerivedBytes([xconvert]::ToSecurestring([System.Text.Encoding]::UTF8.GetString($bytes)))
        return [HKDF2]::Create($bytes, $dsalt)
    }
    static [HKDF2] Create([byte[]]$secretKey, [byte[]]$salt) {
        return [HKDF2]::Create([byte[]]$secretKey, [System.Security.Cryptography.HMACSHA256]::new(), [byte[]]$salt, 10000)
    }
    static [HKDF2] Create([securestring]$secretKey, [byte[]]$salt) {
        return [HKDF2]::Create([System.Text.Encoding]::UTF8.GetBytes([xconvert]::Tostring($secretKey)), $salt)
    }
    static [HKDF2] Create([byte[]]$secretKey, [System.Security.Cryptography.HMAC]$algorithm, [byte[]]$salt, [int]$iterations) {
        if (!$algorithm) { throw "Algorithm cannot be null." }
        if (!$salt) { throw "Salt cannot be null." }
        if (!$secretKey) { throw "secretKey cannot be null." }
        $ob = [HKDF2]::new()
        $ob.Algorithm = $algorithm
        $ob.Algorithm.Key = $secretKey
        $ob.Salt = $salt
        $ob.IterationCount = $iterations
        $ob.BlockSize = $ob.Algorithm.HashSize / 8
        $ob.BufferBytes = [byte[]]::new($ob.BlockSize)
        return $ob
    }
    static [string] GetToken([string]$secretKey) {
        return [HKDF2]::GetToken([xconvert]::ToSecurestring($secretKey))
    }
    static [string] GetToken([securestring]$secretKey) {
        return [HKDF2]::GetToken($secretKey, [cryptobase]::GetDerivedBytes($secretKey))
    }
    static [string] GetToken([securestring]$secretKey, [int]$seconds) {
        return [HKDF2]::GetToken($secretKey, [CryptoBase]::GetDerivedBytes($secretKey), $seconds)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt) {
        return [HKDF2]::GetToken($secretKey, $salt, [timespan]::new(365 * 68, 0, 0, 0))
    }
    static [string] GetToken([securestring]$secretKey, [timespan]$expires) {
        return [HKDF2]::GetToken($secretKey, [CryptoBase]::GetDerivedBytes($secretKey), $expires.TotalSeconds)
    }
    static [string] GetToken([securestring]$secretKey, [datetime]$expires) {
        return [HKDF2]::GetToken($secretKey, ($expires - [datetime]::Now).TotalSeconds)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt, [int]$seconds) {
        $_mdhsbytes = [HKDF2]::new($secretKey, $salt).GetBytes(4)
        $_secretKey = [cryptoBase]::GetKey([xconvert]::ToSecurestring([xconvert]::ToHexString($_mdhsbytes)))
        $_token_str = [xconvert]::ToBase32String([shuffl3r]::Combine([System.Text.Encoding]::UTF8.GetBytes([Datetime]::Now.AddSeconds($seconds).ToFileTime()), $_mdhsbytes, $_secretKey)).Replace("_", '')
        return [Shuffl3r]::Scramble($_token_str, $secretKey)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt, [timespan]$expires) {
        if ($expires.TotalSeconds -gt [int]::MaxValue) {
            Throw [InvalidArgumentException]::new('Expires', "Token max timespan is $([Math]::Floor([timespan]::new(0, 0, 0, [int]::MaxValue).TotalDays/365)) years.")
        }
        return [HKDF2]::GetToken($secretKey, $salt, $expires.TotalSeconds)
    }
    static [bool] VerifyToken([string]$TokenSTR, [securestring]$secretKey) {
        return [HKDF2]::VerifyToken($TokenSTR, $secretKey, [CryptoBase]::GetDerivedBytes($secretKey))
    }
    static [bool] VerifyToken([string]$TokenSTR, [securestring]$secretKey, [byte[]]$salt) {
        $_calcdhash = [HKDF2]::new($secretKey, $salt).GetBytes(4)
        $_secretKey = [cryptoBase]::GetKey([xconvert]::ToSecurestring([xconvert]::ToHexString($_calcdhash)))
        $_Token_STR = [Shuffl3r]::UnScramble($TokenSTR.Trim(), $secretKey)
        ($fb, $mdh) = [shuffl3r]::Split([xconvert]::FromBase32String(($_Token_STR + '_' * 4)), $_secretKey, 4)
        $ht = [DateTime]::FromFileTime([long]::Parse([System.Text.Encoding]::UTF8.GetString($fb)))
        $rs = ($ht - [Datetime]::Now).TotalSeconds
        $NotExpired = $rs -ge 0
        Write-Verbose $("[HKDF2] The token {0} on: {1}" -f $(if ($NotExpired) { "will expire" } else { "expired" }), [datetime]::Now.AddSeconds($rs))
        return $NotExpired -and [HKDF2]::TestEqualByteArrays($_calcdhash, $mdh)
    }
    static [securestring] Resolve([securestring]$Password, [string]$TokenSTR) {
        return [HKDF2]::Resolve($Password, $TokenSTR, [CryptoBase]::GetDerivedBytes($Password))
    }
    static [securestring] Resolve([securestring]$Password, [string]$TokenSTR, [byte[]]$salt) {
        $derivedKey = [securestring]::new(); [System.IntPtr]$handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        Add-Type -AssemblyName System.Runtime.InteropServices
        Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToString($Password));
        Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
        [ValidateNotNullOrEmpty()][string] $TokenSTR = $TokenSTR
        [ValidateNotNullOrEmpty()][string] $Passw0rd = $Passw0rd
        if ([HKDF2]::VerifyToken($TokenSTR, $Password, $salt)) {
            try {
                if ([System.Environment]::UserInteractive) { (Get-Variable host).Value.UI.WriteDebugLine("  [i] Using Password, With token: $TokenSTR") }
                $derivedKey = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, $salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)));
            } catch {
                Write-Error ($error[1].exception.ErrorRecord)
                throw $_
            } finally {
                Remove-Variable -Name Passw0rd -Force -ErrorAction Ignore
                # Zero out the memory used by the variable(just to be safe).
                [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($handle);
            }
            return $derivedKey
        } else {
            Throw [System.UnauthorizedAccessException]::new('Wrong Password.', [InvalidPasswordException]::new());
        }
    }
    static [bool] TestEqualByteArrays([byte[]]$a, [byte[]]$b) {
        # Compares two byte arrays for equality, specifically written so that the loop is not optimized.
        if ($a -eq $b) {
            return $true
        }
        if ($null -eq $a -or $null -eq $b -or $a.Length -ne $b.Length) {
            return $false
        }
        $areSame = $true
        for ($i = 0; $i -lt $a.Length; $i++) {
            $areSame = $areSame -band ($a[$i] -eq $b[$i])
        }
        return $areSame
    }
}
#endregion HKDF2

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
class ArgonCage : CryptoBase {
    [ValidateNotNullOrEmpty()][RecordMap] $Config
    [ValidateNotNullOrEmpty()][version] $Version
    static hidden [ValidateNotNull()][SessionTmp] $Tmp
    static [SecretStore] $SecretStore = [SecretStore]::new("secret_Info")
    static [System.Collections.ObjectModel.Collection[CliArt]] $banners = @()
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope = [EncryptionScope]::User

    ArgonCage() {
        $this.Version = [ArgonCage]::GetVersion()
        $this.PsObject.properties.add([psscriptproperty]::new('DataPath', [scriptblock]::Create({ $path = [ArgonCage]::Get_dataPath('ArgonCage', 'Data'); [SecretStore]::DataPath = [IO.Path]::Combine($path, 'secrets'); return $path })))
        $this.SetTMPvariables(); # $this.SyncConfigs()
        $this.PsObject.properties.add([psscriptproperty]::new('IsOffline', [scriptblock]::Create({ return ((Test-Connection github.com -Count 1).status -ne "Success") })))
    }
    static [void] ShowMenu() {
        [ArgonCage]::GetSecretStore()
        [ArgonCage]::WriteBanner()
        # code for menu goes here ...
    }
    static [void] WriteBanner() {
        if ($null -eq [ArgonCage]::banners -or ([ArgonCage]::banners.Count -eq 0)) {
            [void][ArgonCage]::banners.Add([CliArt]::new('H4sIAAAAAAAAA7VXaXOiQBD9ThU/wlVLjGGNxuBNopZJFmIw3B5RdzUEchiv/P+dwaiAAw6m8mWqeoQ3j9dvulvLzLwOZHEcm3HNyEXbMjPmY6iQJODGAmywkmW24iNFepg2lU8ufb0OheHlKhiMJLAOyybz34Eoi5Z5X00rCn+mDbrJWMIyhSKnqDfGyA5JwrURXdmPy9MkPQ+nxXbDSB8r57J3Kr7MPQRxQ5JQtVQhEvZsJ1vMjIBQUdnR0E1gMOhSHwqUM/vbcCUQhIq+KOzTh2KXpl4feuQM4IuZkeay7hFM/uifpzDcyeT25G6VnnHVhVqEdwPKnfhvX5//8XxrsJxY6gZC7NsxzE1F5CZQzmPc4IbA4+vLliSOfnvD9lBGFIlWa7AUmMjLDisZSfTGucQLqFXLmr2BDgXG64btrwWUnCHV/YIIX6uc7sR//GATwHIDunYeSd+3jwTw9WWLzsiPyenD1rcJ4Kv7M3KGVRfD4Bt1efU5YfGz1sTiDaaWf6GNTqdYfpqQxH13Um60Z9F4W7us9sX8eXPQ2VJ5tHFi/NXQX5qtnEFfw9bVoXjGXaQmYZJKfZTQx/YaaZwKvgw5XxyZ1EMGR/H1ZXvYF9++I4eoALZYPfXus02BYS77FIXjDyMllZPMLiQJz0boMGLLeXiMR6sLp9sKDSFAz5CnQzGGhgDzmVK819ugZ0QKltlYDZHWWsMFgcFB3AfMXXIQfPUl7RzeFZnRof3n3nGtiMynrs1EB1in3uwjRtcHjzu3YLtJt0rfylJL+OXLdtMQi4uZPGD/vcfXBFaGPOgnhZOO64BKZt2gy6eP4ABqCR+OgPlCXtBm3VGhQoPtbmqk7gHzvWut8mu2Ypm5xI39hSQB3dvZcwOc5fW/EQkKVgNh6kkW306c/5QkVYlyo8plDmqxgQPoGQ+YvvauE8z9t+HLWkG1YVplu0m45OGSS4mv89FdnNJnWom5YvV8tlcjCV3rnVLCzUj4FDhTrgrcvMsKvDFfSRpvsGC5ncC3KRsCLlm41LZhgyRs4HbuIkbp7+Z7Y4cuTsZvZyAdLUYa/wf3K1M5Uw8AAA=='))
        }
        [ArgonCage]::banners[(Get-Random (0..([ArgonCage]::banners.Count - 1)))].Tostring() | Write-Host -f Magenta
        [void][cli]::Write('[!] https://github.com/alainQtec/argoncage', [ConsoleColor]::Red)
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
        [AesGCM]::caller = '[ArgonCage]'; [void]$this.Config.Edit()
    }
    [void] SyncConfigs() {
        if ($null -eq $this.Config) { $this.SetConfigs() };
        if (!$this.Config.remote.IsAbsoluteUri) { $this.SetConfigs() }
        # if ($this.Config.Remote.LastWriteTime -gt $this.Config.LastWriteTime) {
        # }
        # Imports remote configs into current ones, then uploads the updated version to github gist
        # Compare REMOTE's lastWritetime with [IO.File]::GetLastWriteTime($this.File)
        if (!$this.Config.remote.IsAbsoluteUri) { throw [System.InvalidOperationException]::new('Could not resolve remote uri') }
        [RecordMap]::caller = '[ArgonCage]'; $this.Config.Import($this.Config.Remote)
        $this.Config.Save()
        if ($?) { Write-Host "[ArgonCage] Config Syncing" -NoNewline -f Blue; Write-Host " Completed." -f Green }
    }
    [void] ImportConfigs() {
        [RecordMap]::caller = '[ArgonCage]'; [void]$this.Config.Import($this.Config.File)
    }
    [void] ImportConfigs([uri]$raw_uri) {
        # $e = "GIST_CUD = {0}" -f ([AesGCM]::Decrypt("AfXkvWiCce7hAIvWyGeU4TNQyD6XLV8kFYyk87X4zqqhyzb7DNuWcj2lHb+2mRFdN/1aGUHEv601M56Iwo/SKhkWLus=", $(Read-Host -Prompt "pass" -AsSecureString), 1)); $e >> ./.env
        [RecordMap]::caller = '[ArgonCage]'; $this.Config.Import($raw_uri)
    }
    [bool] DeleteConfigs() {
        return [bool]$(
            try {
                $configFiles = ([GitHub]::GetTokenFile() | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ($this.DataPath | Get-ChildItem -File -Recurse).FullName
                $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose });
                $true
            } catch { $false }
        )
    }
    [void] SetConfigs() { $this.SetConfigs([string]::Empty, $false) }
    [void] SetConfigs([string]$ConfigFile) { $this.SetConfigs($ConfigFile, $true) }
    [void] SetConfigs([bool]$throwOnFailure) { $this.SetConfigs([string]::Empty, $throwOnFailure) }
    [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
        [AesGCM]::caller = "[$($this.GetType().Name)]"
        if ($null -eq $this.Config) { $this.Config = [RecordMap]::new([ArgonCage]::Get_default_Config()) }
        if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = [ArgonCage]::GetUnResolvedPath($ConfigFile) }
        if (![IO.File]::Exists($this.Config.File)) {
            if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
                throw [System.IO.FileNotFoundException]::new("Unable to find file '$($this.Config.File)'")
            }; [void](New-Item -ItemType File -Path $this.Config.File)
        }
        if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($this.Config.File).Trim())) { $this.Config.Save() }
    }
    # Method to validate the password: This Just checks if its a good enough password
    static [bool] ValidatePassword([SecureString]$password) {
        $IsValid = $false; $minLength = 8; $handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        try {
            Add-Type -AssemblyName System.Runtime.InteropServices
            Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToString($Password));
            Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
            # Set the required character types
            $requiredCharTypes = [System.Text.RegularExpressions.Regex]::Matches("$Passw0rd", "[A-Za-z]|[0-9]|[^A-Za-z0-9]") | Select-Object -ExpandProperty Value
            # Check if the password meets the minimum length requirement and includes at least one of each required character type
            $IsValid = ($Passw0rd.Length -ge $minLength -and $requiredCharTypes.Count -ge 3)
        } catch {
            throw $_.Exeption
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
            $passw0rdHash = (New-Object System.Security.Cryptography.SHA3Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes([xconvert]::Tostring($password)))
        } else {
            # Hash the password using an online SHA-3 hash generator
            $passw0rdHash = ((Invoke-WebRequest -Method Post -Uri "https://passwordsgenerator.net/sha3-hash-generator/" -Body "text=$([xconvert]::Tostring($password))").Content | ConvertFrom-Json).sha3
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
    static [SecretStore] GetSecretStore() {
        if ($null -eq [ArgonCage]::SecretStore.Url) {
            [ArgonCage]::SecretStore = [ArgonCage]::GetSecretStore([ArgonCage]::SecretStore.Name)
        }
        return [ArgonCage]::SecretStore
    }
    static [SecretStore] GetSecretStore([string]$FileName) {
        $result = [SecretStore]::new($FileName); $__FilePath = [ArgonCage]::GetUnResolvedPath($FileName)
        $result.File = $(if ([IO.File]::Exists($__FilePath)) {
                Write-Host "    Found secrets file '$([IO.Path]::GetFileName($__FilePath))'" -f Green
                Get-Item $__FilePath
            } else {
                [ArgonCage]::SecretStore.File
            }
        )
        $result.Name = [IO.Path]::GetFileName($result.File.FullName)
        $result.Url = $(if ($null -eq [ArgonCage]::SecretStore.Url) { [ArgonCage]::GetSecretsRawUri() } else { [ArgonCage]::SecretStore.Url })
        if (![IO.File]::Exists($result.File.FullName)) {
            if ([ArgonCage]::Tmp.vars.UseVerbose) { "[+] Fetching secrets from gist ..." | Write-Host -f Magenta }
            [NetworkManager]::DownloadOptions.Set('ShowProgress', $true)
            $og_PbLength = [NetworkManager]::DownloadOptions.ProgressBarLength
            $og_pbMsg = [NetworkManager]::DownloadOptions.ProgressMessage
            $Progress_Msg = "[+] Downloading secrets to {0}" -f $result.File.FullName
            [NetworkManager]::DownloadOptions.Set(@{
                    ProgressBarLength = $Progress_Msg.Length - 7
                    ProgressMessage   = $Progress_Msg
                }
            )
            $result.File = [NetworkManager]::DownloadFile($result.Url, $result.File.FullName)
            [NetworkManager]::DownloadOptions.Set(@{
                    ProgressBarLength = $og_PbLength
                    ProgressMessage   = $og_pbMsg
                }
            )
            [Console]::Write([Environment]::NewLine)
        }
        return $result
    }
    static [uri] GetSecretsRawUri() {
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        if ($null -eq [ArgonCage]::Tmp.vars) {
            [void][ArgonCage]::SetTMPvariables([ArgonCage]::Get_default_Config())
        }
        $rem_gist = $null; $raw_uri = [string]::Empty -as [uri]
        $rem_cUri = [ArgonCage]::Tmp.vars.config.Remote
        if ([string]::IsNullOrWhiteSpace($rem_cUri)) {
            throw "Failed to get remote uri"
        }
        try {
            $rem_gist = [GitHub]::GetGist($rem_cUri)
        } catch {
            Write-Host "[-] Error: $_" -f Red
        } finally {
            if ($null -ne $rem_gist) {
                $raw_uri = [uri]::new($rem_gist.files.$([ArgonCage]::SecretStore.Name).raw_url)
            }
        }
        return $raw_uri
    }
    static [RecordMap[]] ReadCredsCache() {
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        if ($null -eq [ArgonCage]::Tmp.vars.SessionId) { Write-Verbose "Creating new session ..."; [ArgonCage]::SetTMPvariables([RecordMap]::new([ArgonCage]::Get_default_Config())) }
        $sc = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNullOrEmpty()][RecordMap]$sc = $sc
        #TODO: sessionConfig should be kept as securestring
        #This line should be decrypting the sessionConfig. ie: $sc object.
        if (!$sc.SaveCredsCache) { throw "Please first enable credential Caching in your config. or run [ArgonCage]::Tmp.vars.Set('SaveCredsCache', `$true)" }
        return [ArgonCage]::ReadCredsCache([xconvert]::ToSecurestring($sc.CachedCredsPath))
    }
    static [RecordMap[]] ReadCredsCache([securestring]$CachedCredsPath) {
        $FilePath = ''; $credspath = '';
        Set-Variable -Name "FilePath" -Visibility Public -Value ([xconvert]::Tostring($CachedCredsPath))
        if ([string]::IsNullOrWhiteSpace($FilePath)) { throw "InvalidArgument: `$FilePath" }
        Set-Variable -Name "credspath" -Visibility Public -Value ([IO.Path]::GetDirectoryName($FilePath))
        if ([string]::IsNullOrWhiteSpace($credspath)) { throw "InvalidArgument: `$credspath" }
        if (!(Test-Path -Path $credspath -PathType Container -ErrorAction Ignore)) { [ArgonCage]::Create_Dir($credspath) }
        $ca = @(); if (![IO.File]::Exists($FilePath)) {
            Write-Host "[ArgonCage] FileNotFoundException: No such file.`n$(' '*12)File name: $FilePath" -f Yellow
            return $ca
        }
        $_p = [xconvert]::ToSecurestring([ArgonCage]::GetUniqueMachineId())
        $da = [byte[]][AesGCM]::Decrypt([Base85]::Decode([IO.FILE]::ReadAllText($FilePath)), $_p, [AesGCM]::GetDerivedBytes($_p), $null, 'Gzip', 1)
        $([System.Text.Encoding]::UTF8.GetString($da) | ConvertFrom-Json).ForEach({ $ca += [RecordMap]::new([xconvert]::ToHashTable($_)) })
        return $ca
    }
    static [RecordMap[]] UpdateCredsCache([string]$userName, [securestring]$password, [string]$TagName) {
        return [ArgonCage]::UpdateCredsCache([pscredential]::new($userName, $password), $TagName, $false)
    }
    static [RecordMap[]] UpdateCredsCache([string]$userName, [securestring]$password, [string]$TagName, [bool]$Force) {
        return [ArgonCage]::UpdateCredsCache([pscredential]::new($userName, $password), $TagName, $Force)
    }
    static [RecordMap[]] UpdateCredsCache([pscredential]$Credential, [string]$TagName, [bool]$Force) {
        $sessionConfig = [ArgonCage]::Tmp.vars.SessionConfig
        [ValidateNotNullOrEmpty()][RecordMap]$sessionConfig = $sessionConfig
        $c_array = @()
        $c_array += @{ $TagName = $Credential }
        if (![IO.File]::Exists($sessionConfig.CachedCredsPath)) {
            if (![string]::IsNullOrWhiteSpace([cryptobase]::GetUniqueMachineId())) {
                $c_array += @{ "rwsu" = [pscredential]::new((whoami), [xconvert]::ToSecurestring([environment]::GetEnvironmentVariable("MACHINE_ID"))) }
            }
        }
        $results = @(); $c_array.keys | ForEach-Object {
            $_TagName = $_; $_Credential = $c_array.$_
            if ([string]::IsNullOrWhiteSpace($_TagName)) { throw "InvalidArgument : TagName" }
            [ValidateNotNullOrEmpty()][pscredential]$_Credential = $_Credential
            $results += [ArgonCage]::ReadCredsCache()
            $IsNewTag = $_TagName -notin $results.Tag
            if ($IsNewTag) {
                if (!$Force) {
                    Throw [System.InvalidOperationException]::new("CACHE_NOT_FOUND! Please make sure the tag already exist, or use -Force to auto add.")
                }
                Write-Verbose "Create new file: '$($sessionConfig.CachedCredsPath)'."
            }
            Write-Verbose "$(if ($IsNewTag) { "Adding new" } else { "Updating" }) tag: '$_TagName' ..."
            if ($results.Count -eq 0 -or $IsNewTag) {
                $results += [RecordMap]::new(@{
                        User  = $_Credential.UserName
                        Tag   = $_TagName
                        Token = [HKDF2]::GetToken($_Credential.Password)
                    }
                )
            } else {
                $results.Where({ $_.Tag -eq $_TagName }).Set('Token', [HKDF2]::GetToken($_Credential.Password))
            }
            if ($sessionConfig.SaveCredsCache) {
                $_p = [xconvert]::ToSecurestring([ArgonCage]::GetUniqueMachineId())
                Set-Content -Value $([Base85]::Encode([AesGCM]::Encrypt(
                            [System.Text.Encoding]::UTF8.GetBytes([string]($results | ConvertTo-Json)),
                            $_p, [AesGCM]::GetDerivedBytes($_p), $null, 'Gzip', 1
                        )
                    )
                ) -Path ($sessionConfig.CachedCredsPath) -Encoding utf8BOM
                Write-Verbose "Saved Credential hash to CACHE"
            }
        }
        return $results
    }
    static [bool] CheckCredCache([string]$TagName) {
        return [ArgonCage]::Tmp.vars.CachedCreds.Tag -contains $TagName
    }
    static [void] ClearCredsCache() {
        [ArgonCage]::Tmp.vars.SessionConfig.CachedCredsPath | Remove-Item -Force -ErrorAction Ignore
    }
    static [PsObject] GetSecrets() {
        if (![IO.File]::Exists([ArgonCage]::SecretStore.File) -or ($null -eq [ArgonCage]::SecretStore.Url)) { [ArgonCage]::SecretStore = [ArgonCage]::GetSecretStore() }
        return [ArgonCage]::GetSecrets([ArgonCage]::SecretStore.File)
    }
    static [PsObject] GetSecrets([String]$Path) {
        # $IsCached = [ArgonCage]::checkCredCache($Path)
        $password = [AesGCM]::GetPassword("[ArgonCage] password to read secrets")
        return [ArgonCage]::GetSecrets($Path, $password, [string]::Empty)
    }
    static [PsObject] GetSecrets([String]$Path, [securestring]$password, [string]$Compression) {
        [ValidateNotNullOrEmpty()][string]$Path = [ArgonCage]::GetResolvedPath($Path)
        if (![IO.File]::Exists($Path)) { throw [System.IO.FileNotFoundException]::new("File '$path' does not exist") }
        if (![string]::IsNullOrWhiteSpace($Compression)) { [ArgonCage]::ValidateCompression($Compression) }
        $da = [byte[]][AesGCM]::Decrypt([Base85]::Decode([IO.FILE]::ReadAllText($Path)), $Password, [AesGCM]::GetDerivedBytes($Password), $null, $Compression, 1)
        return $(ConvertFrom-Csv ([System.Text.Encoding]::UTF8.GetString($da).Split('" "'))) | Select-Object -Property @{ l = 'link'; e = { if ($_.link.Contains('"')) { $_.link.replace('"', '') } else { $_.link } } }, 'user', 'pass'
    }
    static [void] EditSecrets() {
        if (![IO.File]::Exists([ArgonCage]::SecretStore.File.FullName) -or ($null -eq [ArgonCage]::SecretStore.Url)) { [ArgonCage]::SecretStore = [ArgonCage]::GetSecretStore() }
        [ArgonCage]::EditSecrets([ArgonCage]::SecretStore.File.FullName)
    }
    static [void] EditSecrets([String]$Path) {
        $private:secrets = $null; $fswatcher = $null; $process = $null; $outFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        try {
            [NetworkManager]::BlockAllOutbound()
            if ([ArgonCage]::Tmp.vars.UseVerbose) { "[+] Edit secrets started .." | Write-Host -f Magenta }
            [ArgonCage]::GetSecrets($Path) | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
            if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
            $private:secrets = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
        } finally {
            [NetworkManager]::UnblockAllOutbound()
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
            if ([ArgonCage]::Tmp.vars.UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -f Magenta }
            if ($null -ne $secrets) { [ArgonCage]::UpdateSecrets($secrets, $Path) }
            if ([ArgonCage]::Tmp.vars.UseVerbose) { "[+] Edit secrets completed." | Write-Host -f Magenta }
        }
    }
    static [void] UpdateSecrets([psObject]$InputObject, [string]$outFile) {
        $password = [AesGCM]::GetPassword("[ArgonCage] password to save secrets")
        [ArgonCage]::UpdateSecrets($InputObject, [ArgonCage]::GetUnResolvedPath($outFile), $password, '')
    }
    static [void] UpdateSecrets([psObject]$InputObject, [string]$outFile, [securestring]$Password, [string]$Compression) {
        if ([ArgonCage]::Tmp.vars.UseVerbose) { "[+] Updating secrets .." | Write-Host -f Green }
        if (![string]::IsNullOrWhiteSpace($Compression)) { [ArgonCage]::ValidateCompression($Compression) }
        [Base85]::Encode([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes([string]($InputObject | ConvertTo-Csv)), $Password, [AesGCM]::GetDerivedBytes($Password), $null, $Compression, 1)) | Out-File $outFile -Encoding utf8BOM
    }
    static [securestring] ResolveSecret([securestring]$secret, [string]$cacheTag) {
        $cache = [ArgonCage]::ReadCredsCache().Where({ $_.Tag -eq $cacheTag })
        if ($null -eq $cache) {
            throw "Secret not found in cache. Please make sure creds caching is enabled."
        }
        $TokenSTR = $cache.Token
        return [HKDF2]::Resolve($secret, $TokenSTR)
    }
    static [ConsoleKeyInfo] ReadInput() {
        $originalTreatControlCAsInput = [System.Console]::TreatControlCAsInput
        if (![console]::KeyAvailable) { [System.Console]::TreatControlCAsInput = $true }
        $key = [ConsoleKeyInfo]::new(' ', [System.ConsoleKey]::None, $false, $false, $false)
        Write-Host "Press a key :)" -f Green
        [FileMonitor]::Keys += $key = [System.Console]::ReadKey($true)
        Write-Host $("Pressed {0}{1}" -f $(if ($key.Modifiers -ne 'None') { $key.Modifiers.ToString() + '^' }), $key.Key) -f Green
        [System.Console]::TreatControlCAsInput = $originalTreatControlCAsInput
        return $key
    }
    hidden [void] SetTMPvariables() {
        if ($null -eq $this.Config) { $this.SetConfigs() }
        [ArgonCage]::SetTMPvariables($this.Config)
    }
    static hidden [void] SetTMPvariables([RecordMap]$Config) {
        # Sets default variables and stores them in $this::Tmp.vars
        # Makes it way easier to clean & manage variables without worying about scopes and not dealing with global variables.
        [ValidateNotNullOrEmpty()][RecordMap]$Config = $Config
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        [ArgonCage]::Tmp.vars.Set(@{
                Users         = @{}
                Host_Os       = [ArgonCage]::Get_Host_Os()
                ExitCode      = 0
                UseWhatIf     = [bool]$((Get-Variable WhatIfPreference -ValueOnly) -eq $true)
                SessionId     = [string]::Empty
                UseVerbose    = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
                OfflineMode   = [NetworkManager]::Testconnection("github.com");
                CachedCreds   = $null
                SessionConfig = $Config
                OgWindowTitle = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
                Finish_reason = [string]::Empty
            }
        )
        if ($Config.SaveCredsCache) {
            if ([IO.File]::Exists($Config.CachedCredsPath)) {
                [ArgonCage]::Tmp.vars.Set('CachedCreds', [ArgonCage]::ReadCredsCache([xconvert]::ToSecurestring($Config.CachedCredsPath)))
            } else {
                <# Action when all if and elseif conditions are false #>
            }
        }
    }
    static hidden [hashtable] Get_default_Config() {
        return [ArgonCage]::Get_default_Config("Config.enc")
    }
    static hidden [hashtable] Get_default_Config([string]$Config_FileName) {
        Write-Host "[ArgonCage] Get default Config ..." -f Blue
        $default_DataDir = [ArgonCage]::Get_dataPath('ArgonCage', 'Data')
        $default_Config = @{
            File            = [ArgonCage]::GetUnResolvedPath([IO.Path]::Combine($default_DataDir, $Config_FileName))
            FileName        = $Config_FileName # Config is stored locally and all it's contents are always encrypted.
            Remote          = [string]::Empty
            GistUri         = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
            ERROR_NAMES     = ('No_Internet', 'Failed_HttpRequest', 'Empty_API_key') # If exit reason is in one of these, the bot will appologise and close.
            NoApiKeyHelp    = 'Get your OpenAI API key here: https://platform.openai.com/account/api-keys'
            ThrowNoApiKey   = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
            UsageHelp       = "Usage:`nHere's an example of how to use this Password manager:`n   `$pm = [ArgonCage]::new()`n   `$pm.login()`n`nAnd make sure you have Internet."
            SaveCredsCache  = $true
            SaveEditorLogs  = $true
            CachedCredsPath = [IO.Path]::Combine($default_DataDir.FullName, "CredsCache.enc")
            LastWriteTime   = [datetime]::Now
        }
        try {
            Write-Host "     Set Remote uri for config ..." -f Blue
            $l = [GistFile]::Create([uri]::New($default_Config.GistUri)); [GitHub]::UserName = $l.UserName
            if ($?) {
                $default_Config.Remote = [uri]::new([GitHub]::GetGist($l.Owner, $l.Id).files."$Config_FileName".raw_url)
            }
            Write-Host "     Set Remote uri " -f Blue -NoNewline; Write-Host "Completed." -f Green
        } catch {
            Write-Host "     Set Remote uri Failed!" -f Red
            Write-Host "            $($_.Exception.PsObject.TypeNames[0]) $($_.Exception.Message)" -f Red
        }
        return $default_Config
    }
    static [version] GetVersion() {
        # Returns the current version of the chatbot.
        return [version]::New($script:localizedData.ModuleVersion)
    }
    static [bool] IsCTRLQ([System.ConsoleKeyInfo]$key) {
        return ($key.modifiers -band [consolemodifiers]::Control) -and ($key.key -eq 'q')
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
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
if ([IO.path]::GetExtension($MyInvocation.MyCommand.Path) -eq '.psm1') {
    # Export Public Functions
    $Param = @{
        Function = $Public.BaseName
        Variable = '*'
        Cmdlet   = '*'
        Alias    = '*'
    }
    Export-ModuleMember @Param -Verbose
}