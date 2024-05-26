function xconvert {
    [CmdletBinding()]
    param ()
    begin {
        enum EncryptionScope {
            User    # The encrypted data can be decrypted with the same user on any machine.
            Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
        }
        enum Compression {
            Gzip
            Deflate
            ZLib
            # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
        }

        # A Custom ObjectConverter
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
                    throw [System.InvalidOperationException]::new('$InputText.Trim().Length Should Be exactly 16. Ex: [xconvert]::ToGuid((CryptoBase)::GetRandomName(16))')
                }
                return [guid]::new([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($InputText)).Replace("-", "").ToLower().Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"))
            }
            static [SecureString] ToSecurestring([string]$String) {
                $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
                if (![string]::IsNullOrEmpty($String)) {
                    $Chars = $String.toCharArray()
                    foreach ($Char in $Chars) {
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
                return [xconvert]::FromPSObject($PSObject, $PSObject.PsObject.TypeNames[0])
            }
            static [System.Object] FromPSObject([PSCustomObject]$PSObject, [string]$typeName) {
                # /!\ not working as expected /!\
                $Type = [Type]::GetType($typeName, $false)
                if ($Type) {
                    $Obj = [Activator]::CreateInstance($Type)
                    $PSObject.PsObject.Properties | ForEach-Object {
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
                $p = [xconvert]::ToSecurestring((Get-UniqueMachineId))
                return (AesGCM)::Encrypt($Bytes, $p, (CryptoBase)::GetDerivedBytes($p))
            }
            static [byte[]] ToUnProtected([byte[]]$Bytes) {
                $p = [xconvert]::ToSecurestring((Get-UniqueMachineId))
                return (AesGCM)::Decrypt($Bytes, $p, (CryptoBase)::GetDerivedBytes($p))
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
                    $OutFile = (CryptoBase)::GetUnResolvedPath($OutFile)
                    try {
                        $resolved = (CryptoBase)::GetResolvedPath($OutFile);
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
                            foreach ($prop in $obj.PsObject.Properties) {
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
                $FilePath = (CryptoBase)::GetResolvedPath($FilePath); $Object = $null
                try {
                    if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
                    $Object = Import-Clixml -Path $FilePath
                } catch {
                    Write-Error $_
                }
                return $Object
            }
            [object] static ObjectFromFile([string]$FilePath, [string]$Type, [bool]$Decrypt) {
                $FilePath = (CryptoBase)::GetResolvedPath($FilePath); $Object = $null
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
    }
    end {
        return [xconvert]::New()
    }
}
Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")