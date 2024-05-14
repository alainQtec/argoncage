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
        [Base85]::Encode($File, [securestring]$(if ($Protect) { (AesGCM)::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Encode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = (CryptoBase)::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = (CryptoBase)::GetResolvedPath($File.FullName);
        if (![string]::IsNullOrWhiteSpace((xconvert)::ToString($Password))) { (AesGCM)::Encrypt($File, $Password, $File.FullName) };
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
        [Base85]::Decode($File, [securestring]$(if ($UnProtect) { (AesGCM)::GetPassword() }else { [securestring]::new() }), $OutFile)
    }
    static [void] Decode([IO.FileInfo]$File, [securestring]$Password, [string]$OutFile) {
        [ValidateNotNullOrEmpty()][string]$OutFile = (CryptoBase)::GetUnResolvedPath($OutFile);
        [ValidateNotNullOrEmpty()][IO.FileInfo]$File = (CryptoBase)::GetResolvedPath($File.FullName);
        [byte[]]$ba = [IO.FILE]::ReadAllBytes($File.FullName)
        [byte[]]$da = [Base85]::Decode([EncodingBase]::new().GetString($ba))
        [void][IO.FILE]::WriteAllBytes($OutFile, $da)
        if (![string]::IsNullOrWhiteSpace((xconvert)::ToString($Password))) { (AesGCM)::Decrypt([IO.FileInfo]::new($OutFile), $Password, $OutFile) }
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
        return [convert]::ToBase64String((xconvert)::ToCompressed([System.Text.Encoding]::UTF8.GetBytes([base85]::Encode($ArtBytes))))
    }
    static [string] ToBase64String([IO.FileInfo]$Artfile) {
        return [CliArt]::ToBase64String([IO.File]::ReadAllBytes($Artfile.FullName))
    }
    static [string] FromBase64String([string]$B64String) {
        return [System.Text.Encoding]::UTF8.GetString([Base85]::Decode([System.Text.Encoding]::UTF8.GetString((xconvert)::ToDeCompressed([convert]::FromBase64String($B64String)))))
    }
    [string] ToString() {
        return [CliArt]::FromBase64String($this.Base64String)
    }
}

#region     GitHub
class GitHub {
    static $webSession
    static [string] $UserName
    static hidden [bool] $IsInteractive = $false
    static hidden [EncryptionScope] $EncryptionScope = "Machine"
    static hidden [string] $TokenFile = [GitHub]::GetTokenFile()

    GitHub() {}
    static [PSObject] createSession() {
        return [Github]::createSession([Github]::UserName)
    }
    static [PSObject] createSession([string]$UserName) {
        [GitHub]::SetToken()
        return [GitHub]::createSession($UserName, [GitHub]::GetToken())
    }
    static [Psobject] createSession([string]$GitHubUserName, [securestring]$clientSecret) {
        [ValidateNotNullOrEmpty()][string]$GitHubUserName = $GitHubUserName
        [ValidateNotNullOrEmpty()][string]$GithubToken = $GithubToken = (xconvert)::Tostring([securestring]$clientSecret)
        $encodedAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($GitHubUserName):$($GithubToken)"))
        $web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        [void]$web_session.Headers.Add('Authorization', "Basic $($encodedAuth)")
        [void]$web_session.Headers.Add('Accept', 'application/vnd.github.v3+json')
        [GitHub]::webSession = $web_session
        return $web_session
    }
    static [void] SetToken() {
        [GitHub]::SetToken((xconvert)::Tostring((Read-Host -Prompt "[GitHub] Paste/write your api token" -AsSecureString)), $(Read-Host -Prompt "[GitHub] Paste/write a Password to encrypt the token" -AsSecureString))
    }
    static [void] SetToken([string]$token, [securestring]$password) {
        if (![IO.File]::Exists([GitHub]::TokenFile)) { New-Item -Type File -Path ([GitHub]::TokenFile) -Force | Out-Null }
        [IO.File]::WriteAllText([GitHub]::TokenFile, [convert]::ToBase64String((AesGCM)::Encrypt([system.Text.Encoding]::UTF8.GetBytes($token), $password)), [System.Text.Encoding]::UTF8);
    }
    static [securestring] GetToken() {
        $sectoken = $null; $session_pass = (xconvert)::ToSecurestring('123');
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
                [GitHub]::SetToken([system.Text.Encoding]::UTF8.GetString((AesGCM)::Decrypt([convert]::FromBase64String($et), $session_pass)), $session_pass)
            }
            $sectoken = (xconvert)::ToSecurestring([system.Text.Encoding]::UTF8.GetString(
                    (AesGCM)::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText([GitHub]::GetTokenFile())), $session_pass)
                )
            )
        } catch {
            throw $_
        }
        return $sectoken
    }
    static [PsObject] GetUserInfo([string]$UserName) {
        Push-Stack "GitHub"; if ([string]::IsNullOrWhiteSpace([GitHub]::userName)) { [GitHub]::createSession() }
        $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    static [PsObject] GetGist([uri]$Uri) {
        $l = [GistFile]::Create($Uri)
        return [GitHub]::GetGist($l.Owner, $l.Id)
    }
    static [PsObject] GetGist([string]$UserName, [string]$GistId) {
        Push-Stack "GitHub"; $t = [GitHub]::GetToken()
        if ($null -eq ([GitHub]::webSession)) {
            [GitHub]::webSession = $(if ($null -eq $t) {
                    [GitHub]::createSession($UserName)
                } else {
                    [GitHub]::createSession($UserName, $t)
                }
            )
        }
        if (!$(Retry-Command -s { [GitHub]::IsConnected() } -m "GitHub.IsConnected()").Output) {
            throw [System.Net.NetworkInformation.PingException]::new("PingException, PLease check your connection!");
        }
        if ([string]::IsNullOrWhiteSpace($GistId) -or $GistId -eq '*') {
            return Get-Gists -UserName $UserName -SecureToken $t
        }
        $FetchGistId = [scriptblock]::Create({
                param (
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()][string]$Id
                )
                return Invoke-RestMethod -Uri "https://api.github.com/gists/$Id" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
            }
        )
        return $(Retry-Command -s $FetchGistId -args @($GistId) -m "GitHub.FetchGist()  ").Output
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
        $CreateGist = [scriptblock]::Create({
                param (
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()][uri]$UriObj,
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()][string]$JSONBODY
                )
                return Invoke-RestMethod -Uri $UriObj -WebSession ([GitHub]::webSession) -Method Post -Body $JSONBODY -Verbose:$false
            }
        )
        return $(Retry-Command -s $CreateGist -args @($url, ($body | ConvertTo-Json)) -m "CreateGist").Output
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
        $cs = $null; Write-Host "[Github] Testing Connection ... " -f Blue -NoNewline
        try {
            [System.Net.NetworkInformation.PingReply]$PingReply = [System.Net.NetworkInformation.Ping]::new().Send("github.com");
            $cs = $PingReply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
        } catch [System.Net.Sockets.SocketException], [System.Net.NetworkInformation.PingException] {
            $cs = $false
        } catch {
            $cs = $false;
            Write-Error $_
        }
        # [TaskMan]::WriteLog($cs)
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
            $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt([base85]::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
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
        Push-Stack -class "ArgonCage"; $pass = $null; $cfg = $null; $FilePath = (AesGCM)::GetResolvedPath($FilePath);
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [FileNotFoundException]::new("File not found: $FilePath") }
        Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([ArgonCage]::Tmp.GetSessionKey('configrw', [PSCustomObject]@{
                    caller = Show-Stack
                    prompt = "Paste/write a Password to decrypt configs"
                }
            )
        )
        $txt = [IO.File]::ReadAllText($FilePath)
        $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt([base85]::Decode($txt), $pass)))
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
        if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [FileNotFoundException]::new("File not found: $FilePath") }
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
            $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
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
            Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value ([FileMonitor]::GetLogSummary()) | Out-Null
            if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -f Magenta }
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
            $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, [Base85]::Encode((AesGCM)::Encrypt((xconvert)::ToCompressed($this.ToByte()), $pass)), [System.Text.Encoding]::UTF8)
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
class SessionTmp {
    [ValidateNotNull()][RecordMap]$vars
    [ValidateNotNull()][System.Collections.Generic.List[string]]$Paths
    static hidden [EncryptionScope] $EncryptionScope = "Machine"
    SessionTmp() {
        $this.vars = [RecordMap]::new()
        $this.Paths = [System.Collections.Generic.List[string]]::new()
    }
    [void] SaveSessionKey([string]$Name, [SecureString]$Value) {
        [ValidateNotNullOrEmpty()][string]$Name = $Name
        if ($null -eq $this.vars.SessionKeys) {
            $this.vars.Set('SessionKeys', [RecordMap]::new())
            $this.vars.SessionKeys.Add(@{ $Name = $Value })
        } else {
            $this.vars.SessionKeys.Set(@{ $Name = $Value })
        }
    }
    [SecureString] GetSessionKey([string]$Name) {
        return [ArgonCage]::Tmp.GetSessionKey($Name, [PSCustomObject]@{
                caller = Show-Stack
                prompt = "Paste/write a Password"
            }
        )
    }
    [SecureString] GetSessionKey([string]$Name, [psobject]$Options) {
        [ValidateNotNullOrEmpty()][string]$Name = $Name
        [ValidateNotNullOrEmpty()][psobject]$Options = $Options
        if ($null -eq $this.vars.SessionKeys) {
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
        return $this.vars.SessionKeys.$Name
    }
    static hidden [EncryptionScope] Get_Enc_Scope([string]$caller) {
        $_scope = [scriptblock]::Create("return $($caller)::EncryptionScope").Invoke();
        if ([string]::IsNullOrWhiteSpace("$_scope")) {
            return [SessionTmp]::EncryptionScope
        }
        return $_scope
    }
    [void] Clear() {
        $this.vars = [RecordMap]::new()
        $this.Paths | ForEach-Object { Remove-Item "$_" -ErrorAction SilentlyContinue };
        $this.Paths = [System.Collections.Generic.List[string]]::new()
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

class VaultCache {
    VaultCache() {}
    [RecordMap[]] Read() {
        return $this.Read((xconvert)::ToSecurestring([ArgonCage]::Get_SessionConfig().CachedCredsPath))
    }
    [RecordMap[]] Read([securestring]$CachedCredsPath) {
        $FilePath = ''; $credspath = ''; $sc = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNullOrEmpty()][RecordMap]$sc = $sc
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
                $ca += [ArgonCage]::vault.Cache.Update((whoami), $_p, 'rwsu', $true)
            } else {
                Write-Host "[ArgonCage] FileNotFoundException: No such file.`n$(' '*12)File name: $FilePath" -f Yellow
            }
            return $ca
        }
        $tc = [IO.FILE]::ReadAllText($FilePath); if ([string]::IsNullOrWhiteSpace($tc.Trim())) { return $ca }
        $da = [byte[]](AesGCM)::Decrypt([Base85]::Decode($tc), $_p, (AesGCM)::GetDerivedBytes($_p), $null, 'Gzip', 1)
        $([System.Text.Encoding]::UTF8.GetString($da) | ConvertFrom-Json).ForEach({ $ca += [RecordMap]::new((xconvert)::ToHashTable($_)) })
        return $ca
    }
    [RecordMap[]] Update([string]$userName, [securestring]$password, [string]$TagName) {
        return $this.Update([pscredential]::new($userName, $password), $TagName, $false)
    }
    [RecordMap[]] Update([string]$userName, [securestring]$password, [string]$TagName, [bool]$Force) {
        return $this.Update([pscredential]::new($userName, $password), $TagName, $Force)
    }
    [RecordMap[]] Update([pscredential]$Credential, [string]$TagName, [bool]$Force) {
        $sessionConfig = [ArgonCage]::Tmp.vars.SessionConfig
        [ValidateNotNullOrEmpty()][RecordMap]$sessionConfig = $sessionConfig
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
                $results += [RecordMap]::new(@{
                        User  = $_Credential.UserName
                        Tag   = $_TagName
                        Token = (HKDF2)::GetToken($_Credential.Password)
                    }
                )
            } else {
                $results.Where({ $_.Tag -eq $_TagName }).Set('Token', (HKDF2)::GetToken($_Credential.Password))
            }
            if ($sessionConfig.SaveVaultCache) {
                $_p = (xconvert)::ToSecurestring((CryptoBase)::GetUniqueMachineId())
                Set-Content -Value $([Base85]::Encode((AesGCM)::Encrypt(
                            [System.Text.Encoding]::UTF8.GetBytes([string]($results | ConvertTo-Json)),
                            $_p, (AesGCM)::GetDerivedBytes($_p), $null, 'Gzip', 1
                        )
                    )
                ) -Path ($sessionConfig.CachedCredsPath) -Encoding utf8BOM
            }
        }
        return $results
    }
    [void] Clear() {
        [VaultCache] | Add-Member -Name Object -Force -MemberType ScriptProperty -Value { $null }.GetNewClosure()
        [ArgonCage]::Tmp.vars.SessionConfig.CachedCredsPath | Remove-Item -Force -ErrorAction Ignore
    }
    [string] ToString() {
        return [ArgonCage]::Get_SessionConfig().CachedCredsPath
    }
}

class vault {
    [ValidateNotNullOrEmpty()][string]$Name
    [ValidateNotNullOrEmpty()][uri]$Remote
    hidden [VaultCache]$Cache
    static hidden [ValidateNotNullOrEmpty()][string]$DataPath = [IO.Path]::Combine([ArgonCage]::DataPath, 'secrets')
    static hidden [bool]$UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
    vault([string]$Name) {
        if ([string]::IsNullOrWhiteSpace($Name)) { throw [System.ArgumentException]::new($Name) }
        $this.Name = $Name
        if ([string]::IsNullOrWhiteSpace([vault]::DataPath)) {
            [vault]::DataPath = [IO.Path]::Combine((CryptoBase)::Get_dataPath('ArgonCage', 'Data'), 'secrets')
        }
        $this.psobject.Properties.Add([psscriptproperty]::new('File', {
                    return [IO.FileInfo]::new([IO.Path]::Combine([vault]::DataPath, $this.Name))
                }, {
                    param($value)
                    if ($value -is [IO.FileInfo]) {
                        [vault]::DataPath = $value.Directory.FullName
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
        $this.psobject.Properties.Add([psscriptproperty]::new('Cache', {
                    if ($null -eq [VaultCache].Object) {
                        [VaultCache] | Add-Member -Name Object -Force -MemberType ScriptProperty -Value { return [VaultCache]::new() }.GetNewClosure() -SecondValue { throw [System.InvalidOperationException]::new("Cannot change Cache") }
                    }
                    return [VaultCache].Object
                }, { throw [System.InvalidOperationException]::new("Cannot set Cache") }
            )
        )
        if ($null -eq [ArgonCage]::Tmp.vars) { [ArgonCage]::SetTMPvariables() }else {
            $this.Remote = [vault]::get_secrets_RawUri($this.Name, [ArgonCage]::Tmp.vars.sessionConfig.Remote)
        }
    }
    static [vault] Create([string]$FilePath, [uri]$RemoteUri) {
        [ValidateNotNullOrEmpty()][string]$FileName = $FilePath
        [ValidateNotNullOrEmpty()][uri]$RemoteUri = $RemoteUri
        $__FilePath = (CryptoBase)::GetUnResolvedPath($FilePath);
        $result = [vault]::new([IO.Path]::GetFileName($__FilePath));
        $result.File = $(if ([IO.File]::Exists($__FilePath)) {
                Write-Host "    Found secrets file '$([IO.Path]::GetFileName($__FilePath))'" -f Green
                Get-Item $__FilePath
            } else {
                $result.File
            }
        )
        $result.Name = [IO.Path]::GetFileName($result.File.FullName); $result.Remote = $RemoteUri
        if (![IO.File]::Exists($result.File.FullName)) {
            $result.File = [vault]::FetchSecrets($result.Remote, $result.File.FullName)
        }
        return $result
    }
    [PsObject] GetSecrets() {
        if (![IO.File]::Exists($this.File.FullName)) {
            if ([string]::IsNullOrWhiteSpace($this.Remote.AbsoluteUri)) { $this.Set_RemoteUri() }
            $this.File = [vault]::FetchSecrets($this.Remote, $this.File.FullName)
        }
        return $this.GetSecrets($this.File)
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
        $da = [byte[]](AesGCM)::Decrypt([Base85]::Decode([IO.FILE]::ReadAllText($Path)), $Password, (AesGCM)::GetDerivedBytes($Password), $null, $Compression, 1)
        return $(ConvertFrom-Csv ([System.Text.Encoding]::UTF8.GetString($da).Split('" "'))) | Select-Object -Property @{ l = 'link'; e = { if ($_.link.Contains('"')) { $_.link.replace('"', '') } else { $_.link } } }, 'user', 'pass'
    }
    [void] EditSecrets() {
        if (![IO.File]::Exists($this.File.FullName)) {
            if ([string]::IsNullOrWhiteSpace($this.Remote.AbsoluteUri)) { $this.Set_RemoteUri() }
            $this.File = [vault]::FetchSecrets($this.Remote, $this.File.FullName)
        }
        $this.EditSecrets($this.File.FullName)
    }
    [void] EditSecrets([String]$Path) {
        $private:secrets = $null; $fswatcher = $null; $process = $null; $outFile = [IO.FileInfo][IO.Path]::GetTempFileName()
        try {
            Push-Stack "vault"; (NetworkManager)::BlockAllOutbound()
            if ([vault]::UseVerbose) { "[+] Edit secrets started .." | Write-Host -f Magenta }
            $this.GetSecrets($Path) | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
            Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo.FileName = 'nvim'
            $process.StartInfo.Arguments = $outFile.FullName
            $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
            $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
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
            if ([vault]::UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -f Green }
            if ($null -ne $secrets) { $this.UpdateSecrets($secrets, $Path) }
            if ([vault]::UseVerbosee) { "[+] Edit secrets completed." | Write-Host -f Magenta }
        }
    }
    [IO.FileInfo] FetchSecrets() {
        if ([string]::IsNullOrWhiteSpace($this.Remote.AbsoluteUri)) { $this.Set_RemoteUri() }
        return [vault]::FetchSecrets($this.Remote, $this.File.FullName)
    }
    static [IO.FileInfo] FetchSecrets([uri]$remote, [string]$OutFile) {
        if ([string]::IsNullOrWhiteSpace($remote.AbsoluteUri)) { throw [System.ArgumentException]::new("Invalid Argument: remote") }
        if ([vault]::UseVerbose) { "[+] Fetching secrets from gist ..." | Write-Host -f Magenta }
        Push-Stack "vault"; (NetworkManager)::DownloadOptions.ShowProgress = $true
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
    static [uri] get_secrets_RawUri() {
        if ($null -eq [ArgonCage]::Tmp) {
            [ArgonCage]::Tmp = [SessionTmp]::new()
            [ArgonCage]::SetTMPvariables()
        }
        return [vault]::get_secrets_RawUri([ArgonCage]::vault.Name, [ArgonCage]::Tmp.vars.sessionConfig.Remote)
    }
    static [uri] get_secrets_RawUri([string]$vaultName, [uri]$remote) {
        [ValidateNotNullOrEmpty()][uri]$remote = $remote
        [ValidateNotNullOrEmpty()][string]$vaultName = $vaultName
        $rem_gist = $null; $raw_uri = [string]::Empty -as [uri]
        if ([string]::IsNullOrWhiteSpace($remote)) { throw "Failed to get remote uri" }
        try {
            $rem_gist = [GitHub]::GetGist($remote)
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
        Push-Stack "vault"; if ([vault]::UseVerbose) { "[+] Updating secrets .." | Write-Host -f Green }
        if (![string]::IsNullOrWhiteSpace($Compression)) { (CryptoBase)::ValidateCompression($Compression) }
        [Base85]::Encode((AesGCM)::Encrypt([System.Text.Encoding]::UTF8.GetBytes([string]($InputObject | ConvertTo-Csv)), $Password, (AesGCM)::GetDerivedBytes($Password), $null, $Compression, 1)) | Out-File $outFile -Encoding utf8BOM
    }
    hidden [void] Set_RemoteUri() {
        if ([string]::IsNullOrWhiteSpace($this.Remote.AbsoluteUri)) {
            $this.Remote = [vault]::get_secrets_RawUri()
        } else {
            $this.Remote = [vault]::get_secrets_RawUri($this.Name, $this.Remote)
        }
    }
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
    [ValidateNotNullOrEmpty()][RecordMap] $Config
    [ValidateNotNullOrEmpty()][version] $version
    static hidden [ValidateNotNull()][vault] $vault
    static hidden [ValidateNotNull()][SessionTmp] $Tmp
    Static hidden [ValidateNotNull()][IO.DirectoryInfo] $DataPath = (CryptoBase)::Get_dataPath('ArgonCage', 'Data')
    static [System.Collections.ObjectModel.Collection[CliArt]] $banners = @()
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope = [EncryptionScope]::User

    ArgonCage() {
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        Push-Stack -class "ArgonCage"; $this.SetConfigs(); [ArgonCage]::SetTMPvariables($this.Config)
        # $this.SyncConfigs()
        $this.PsObject.properties.add([psscriptproperty]::new('IsOffline', [scriptblock]::Create({ return ((Test-Connection github.com -Count 1).status -ne "Success") })))
        [ArgonCage].psobject.Properties.Add([psscriptproperty]::new('Version', {
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
        $og_EncryptionScope = [ArgonCage]::EncryptionScope;
        try {
            $this::EncryptionScope = [EncryptionScope]::Machine
            Push-Stack -class "ArgonCage"; [void]$this.Config.Edit()
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
            $this.Config.Import($this.Config.Remote)
            $this.Config.Save();
        } finally {
            $this::EncryptionScope = $og_EncryptionScope;
        }
        if ($?) { Write-Host "[ArgonCage] Config Syncing" -NoNewline -f Blue; Write-Host " Completed." -f Green }
    }
    [void] ImportConfigs() {
        [void]$this.Config.Import($this.Config.File)
    }
    [void] ImportConfigs([uri]$raw_uri) {
        # $e = "GIST_CUD = {0}" -f ((AesGCM)::Decrypt("AfXkvWiCce7hAIvWyGeU4TNQyD6XLV8kFYyk87X4zqqhyzb7DNuWcj2lHb+2mRFdN/1aGUHEv601M56Iwo/SKhkWLus=", $(Read-Host -Prompt "pass" -AsSecureString), 1)); $e >> ./.env
        $this.Config.Import($raw_uri)
    }
    [bool] DeleteConfigs() {
        return [bool]$(
            try {
                $configFiles = ([GitHub]::GetTokenFile() | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ([ArgonCage]::DataPath | Get-ChildItem -File -Recurse).FullName
                $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose });
                $true
            } catch { $false }
        )
    }
    [void] SetConfigs() { $this.SetConfigs([string]::Empty, $false) }
    [void] SetConfigs([string]$ConfigFile) { $this.SetConfigs($ConfigFile, $true) }
    [void] SetConfigs([bool]$throwOnFailure) { $this.SetConfigs([string]::Empty, $throwOnFailure) }
    [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
        if ($null -eq $this.Config) { $this.Config = [RecordMap]::new([ArgonCage]::Get_default_Config()) }
        if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = [ArgonCage]::GetUnResolvedPath($ConfigFile) }
        if (![IO.File]::Exists($this.Config.File)) {
            if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
                throw [System.IO.FileNotFoundException]::new("Unable to find file '$($this.Config.File)'")
            }; [void](New-Item -ItemType File -Path $this.Config.File)
        }
        if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($this.Config.File).Trim())) {
            $og_EncryptionScope = [ArgonCage]::EncryptionScope; try {
                $this::EncryptionScope = [EncryptionScope]::Machine
                $this.Config.Save();
            } finally {
                $this::EncryptionScope = $og_EncryptionScope;
            }
        }
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
        $cache = [ArgonCage]::vault.Cache.Read().Where({ $_.Tag -eq $cacheTag })
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
        [FileMonitor]::Keys += $key = [System.Console]::ReadKey($true)
        Write-Host $("Pressed {0}{1}" -f $(if ($key.Modifiers -ne 'None') { $key.Modifiers.ToString() + '^' }), $key.Key) -f Green
        [System.Console]::TreatControlCAsInput = $originalTreatControlCAsInput
        return $key
    }
    static hidden [void] SetTMPvariables() {
        if ($null -eq [ArgonCage]::Tmp.vars.SessionConfig) {
            [ArgonCage]::SetTMPvariables([RecordMap]::new([ArgonCage]::Get_default_Config()))
        } else {
            [ArgonCage]::SetTMPvariables([ArgonCage]::Tmp.vars.SessionConfig)
        }
    }
    static hidden [void] SetTMPvariables([RecordMap]$Config) {
        # Sets default variables and stores them in $this::Tmp.vars
        # Makes it way easier to clean & manage variables without worying about scopes and not dealing with global variables.
        [ValidateNotNullOrEmpty()][RecordMap]$Config = $Config
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        [ArgonCage]::Tmp.vars.Set(@{
                Users         = @{}
                Host_Os       = (CryptoBase)::Get_Host_Os()
                ExitCode      = 0
                UseWhatIf     = [bool]$((Get-Variable WhatIfPreference -ValueOnly) -eq $true)
                SessionId     = [string]::Empty
                UseVerbose    = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
                OfflineMode   = $(Wait-Task -m "Testing Connection" -s { return $((NetworkManager)::Testconnection("github.com")) }).Output
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
            File            = [ArgonCage]::GetUnResolvedPath([IO.Path]::Combine([ArgonCage]::DataPath, $Config_FileName))
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
    static hidden [RecordMap] Get_SessionConfig() {
        if ($null -eq [ArgonCage]::Tmp) { [ArgonCage]::Tmp = [SessionTmp]::new() }
        if ($null -eq [ArgonCage]::Tmp.vars.SessionId) {
            Write-Verbose "Creating new session ..."; [ArgonCage]::SetTMPvariables()
        }
        $sc = [ArgonCage]::Tmp.vars.SessionConfig; [ValidateNotNullOrEmpty()][RecordMap]$sc = $sc
        return $sc
    }
    static hidden [void] Get_CachedCreds([RecordMap]$Config) {
        if ($null -eq [ArgonCage]::vault) { [ArgonCage]::vault = [vault]::new($Config.VaultFileName) }
        if ([IO.File]::Exists($Config.CachedCredsPath)) {
            [ArgonCage]::vault.Cache.Read((xconvert)::ToSecurestring($Config.CachedCredsPath))
        } else {
            [ArgonCage]::vault.Cache.Read()
        }
    }
    [version] SetVersion() {
        $this.version = [version]::New($script:localizedData.ModuleVersion)
        return $this.version
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