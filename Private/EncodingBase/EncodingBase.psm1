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

# .SYNOPSIS
#     Base85 encoding
# .DESCRIPTION
#     A binary-to-text encoding scheme that uses 85 printable ASCII characters to represent binary data
# .EXAMPLE
#     $b = [System.Text.Encoding]::UTF8.GetBytes("Hello world")
#     [Base85]::Encode($b)
#     [System.Text.Encoding]::UTF8.GetString([Base85]::Decode("87cURD]j7BEbo7"))
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
            Write-Debug "[Base85] Encoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
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
                foreach ($A85Char in $A85Chunk) {
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
            [String]$TimeLapse = "[Base85] Encoding completed in $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
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
            Write-Debug "[Base85] Decoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
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
            [String]$TimeLapse = "[Base85] Decoding completed after $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
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

function Base85 {
    [CmdletBinding()]
    param ()
    end {
        return [Base85]::New()
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")