enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}
enum CryptoAlgorithm {
    AesGCM # AES-GCM (Galois/Counter Mode). A strong encryption on its own that doesn't necessarily with its built-in authentication functions. Its a mode of operation for AES that provides both confidentiality and authenticity for the encrypted data. GCM provides faster encryption and decryption compared to CBC mode and is widely used for secure communication, especially in VPN and TLS/SSL apps.
    ChaCha20 # ChaCha20 + SHA256 in this case. I would prefer ChaCha20Poly1305 but the Poly1305 class is still not working/usable. But no wories, ChaCha20 is like the salsa of the cryptography world, it's got the moves to keep your data secure and grooving to its own beat! :) Get it? [ref] to the dance-like steps performed in the algorithm's mixing process? Nevermind ... Its a symmetric key encryption algorithm, based on salsa20 algorithm. ChaCha20 provides the encryption, while Poly1305 (or SHA256 in this case) provides the authentication. This combination provides both confidentiality and authenticity for the encrypted data.
    RsaAesHMAC # RSA + AES + HMAC: This combination uses RSA for key exchange, AES for encryption, and HMAC (hash-based message authentication code) for authentication. This provides a secure mechanism for exchanging keys and encrypting data, as well as a way to verify the authenticity of the data. ie: By combining RSA and AES, one can take advantage of both algorithms' strengths: RSA is used to securely exchange the AES key, while AES is be used for the actual encryption and decryption of the data. This way, RSA provides security for key exchange, and AES provides fast encryption and decryption for the data.
    RsaECDSA # RSA + ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
    RsaOAEP # RSA-OAEP (Optimal Asymmetric Encryption Padding)
}

enum RSAPadding {
    Pkcs1
    OaepSHA1
    OaepSHA256
    OaepSHA384
    OaepSHA512
}
enum CredentialPersistence {
    Session = 1
    LocalComputer = 2
    Enterprise = 3
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

class CryptoBase {
    [ValidateNotNull()][byte[]]hidden $_salt
    [ValidateNotNull()][byte[]]hidden $_bytes
    [ValidateNotNull()][securestring]hidden $_Password
    [ValidateNotNull()][CryptoAlgorithm]hidden $_Algorithm
    static [ValidateNotNull()][EncryptionScope] $EncryptionScope

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
        return [CryptoBase]::GetDerivedBytes((xconvert)::ToSecurestring([CryptoBase]::GetRandomName(16)), $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password) {
        return [CryptoBase]::GetDerivedBytes($password, 16)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [int]$Length) {
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        $pswd = (xconvert)::ToSecurestring($(switch ([CryptoBase]::EncryptionScope.ToString()) {
                    "Machine" {
                        [System.Text.Encoding]::UTF8.GetBytes((Get-UniqueMachineId))
                    }
                    Default {
                        [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==")
                    }
                }
            )
        )
        $s6lt = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $password, $([System.Text.Encoding]::UTF8.GetBytes(
                    ((xconvert)::ToString($password) + (Get-UniqueMachineId))
                )
            )
        ).GetBytes(16)
        return [CryptoBase]::GetDerivedBytes($pswd, $s6lt, $Length)
    }
    static [byte[]] GetDerivedBytes([securestring]$password, [byte[]]$salt, [int]$Length) {
        [ValidateNotNullOrEmpty()]$salt = $salt
        [ValidateNotNullOrEmpty()][securestring]$password = $password
        return [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, 1000).GetBytes($Length);
    }
    static [byte[]] GetKey() {
        return [CryptoBase]::GetKey(16);
    }
    static [byte[]] GetKey([int]$Length) {
        return [CryptoBase]::GetKey((xconvert)::ToSecurestring([CryptoBase]::GeneratePassword()), $Length)
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
        Write-Verbose "$(Show-Stack) [+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $Aes.Algo.$_) { $MissingProps += $_ } };
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
            if ([string]::IsNullOrWhiteSpace($Name)) { throw 'Name can not be null or space' }
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
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $((xconvert)::ToSecurestring([CryptoBase]::GeneratePassword()));
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
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Debug "Created $_" }
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
            return (xconvert)::ToSecurestring((Get-UniqueMachineId))
        } else {
            $pswd = [SecureString]::new(); Push-Stack -class "ArgonCage"
            Set-Variable -Name pswd -Scope Local -Visibility Private -Option Private -Value $(Read-Host -Prompt "$(Show-Stack) $Prompt" -AsSecureString);
            if ($ThrowOnFailure -and ($null -eq $pswd -or $([string]::IsNullOrWhiteSpace((xconvert)::ToString($pswd))))) {
                throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null or WhiteSpace.", $pswd, [System.ArgumentNullException]::new("Password"))
            }
            return $pswd;
        }
    }
    static [void] ValidateCompression([string]$Compression) {
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") };
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
#     $Passwd = (xconvert)::ToSecurestring('OKay_&~rVJ+T?NpJ(8TqL');
#     $shuffld = [Shuffl3r]::Combine([Shuffl3r]::Combine($_bytes, $Nonce2, $Passwd), $Nonce1, $Passwd);
#     ($b,$n1) = [Shuffl3r]::Split($shuffld, $Passwd, $Nonce1.Length);
#     ($b,$n2) = [Shuffl3r]::Split($b, $Passwd, $Nonce2.Length);
#     [System.text.Encoding]::UTF8.GetString($b) -eq '** _H4ck_z3_W0rld_ **' # should be $true
class Shuffl3r {
    Shuffl3r() {}
    static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
        return [Shuffl3r]::Combine($bytes, $Nonce, (xconvert)::ToString($Passwod))
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
        return [Shuffl3r]::Split($ShuffledBytes, (xconvert)::ToString($Passwod), [int]$NonceLength);
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

# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $bytes = GetbytesFromObj('Text_Message1'); $Password = (xconvert)::ToSecurestring('X-aP0jJ_:No=08TfdQ'); $salt = [CryptoBase]::GetRandomEntropy();
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
    AesGCM() { }
    static hidden [EncryptionScope] $Scope = [EncryptionScope]::User
    static [byte[]] Encrypt([byte[]]$bytes) {
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
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new((xconvert)::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = $bytes;
            $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$(Show-Stack) [+] Encryption [$i/$iterations] ... Done" -f Yellow
                # if ($Protect) { $_bytes = (xconvert)::ToProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Generate a random IV for each iteration:
                [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new((xconvert)::ToString($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
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
            $_bytes = (xconvert)::ToCompressed($_bytes, $Compression);
        }
        return $_bytes
    }
    static [void] Encrypt([IO.FileInfo]$File) {
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
        Write-Verbose "$(Show-Stack) Begin file encryption:"
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
        [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new((xconvert)::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
        [System.IntPtr]$th = [System.IntPtr]::new(0); Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
        try {
            $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { (xconvert)::ToDecompressed($bytes, $Compression) } else { $bytes }
            $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
            for ($i = 1; $i -lt $iterations + 1; $i++) {
                # Write-Host "$(Show-Stack) [+] Decryption [$i/$iterations] ... Done" -f Yellow
                # if ($UnProtect) { $_bytes = (xconvert)::ToUnProtected($_bytes, $Salt, [EncryptionScope]::User) }
                # Split the real encrypted bytes from nonce & tags then decrypt them:
                ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                $Decrypted = [byte[]]::new($b.Length);
                $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                $_bytes = $Decrypted;
            }
        } catch {
            if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
                Write-Host "$(Show-Stack) Wrong password" -f Yellow
            }
            throw $_
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
            Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
        }
        return $_bytes
    }
    static [void] Decrypt([IO.FileInfo]$File) {
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
        Write-Verbose "$(Show-Stack) Begin file decryption:"
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
        $dsalt = (CryptoBase)::GetDerivedBytes((xconvert)::ToSecurestring([System.Text.Encoding]::UTF8.GetString($bytes)))
        return [HKDF2]::Create($bytes, $dsalt)
    }
    static [HKDF2] Create([securestring]$secretKey) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((xconvert)::Tostring($secretKey))
        $dsalt = (CryptoBase)::GetDerivedBytes((xconvert)::ToSecurestring([System.Text.Encoding]::UTF8.GetString($bytes)))
        return [HKDF2]::Create($bytes, $dsalt)
    }
    static [HKDF2] Create([byte[]]$secretKey, [byte[]]$salt) {
        return [HKDF2]::Create([byte[]]$secretKey, [System.Security.Cryptography.HMACSHA256]::new(), [byte[]]$salt, 10000)
    }
    static [HKDF2] Create([securestring]$secretKey, [byte[]]$salt) {
        return [HKDF2]::Create([System.Text.Encoding]::UTF8.GetBytes((xconvert)::Tostring($secretKey)), $salt)
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
        return [HKDF2]::GetToken((xconvert)::ToSecurestring($secretKey))
    }
    static [string] GetToken([securestring]$secretKey) {
        return [HKDF2]::GetToken($secretKey, (CryptoBase)::GetDerivedBytes($secretKey))
    }
    static [string] GetToken([securestring]$secretKey, [int]$seconds) {
        return [HKDF2]::GetToken($secretKey, (CryptoBase)::GetDerivedBytes($secretKey), $seconds)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt) {
        return [HKDF2]::GetToken($secretKey, $salt, [timespan]::new(365 * 68, 0, 0, 0))
    }
    static [string] GetToken([securestring]$secretKey, [timespan]$expires) {
        return [HKDF2]::GetToken($secretKey, (CryptoBase)::GetDerivedBytes($secretKey), $expires.TotalSeconds)
    }
    static [string] GetToken([securestring]$secretKey, [datetime]$expires) {
        return [HKDF2]::GetToken($secretKey, ($expires - [datetime]::Now).TotalSeconds)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt, [int]$seconds) {
        $_mdhsbytes = [HKDF2]::new($secretKey, $salt).GetBytes(4)
        $_secretKey = (CryptoBase)::GetKey((xconvert)::ToSecurestring((xconvert)::ToHexString($_mdhsbytes)))
        $_token_str = (xconvert)::ToBase32String((Shuffl3r)::Combine([System.Text.Encoding]::UTF8.GetBytes([Datetime]::Now.AddSeconds($seconds).ToFileTime()), $_mdhsbytes, $_secretKey)).Replace("_", '')
        return (Shuffl3r)::Scramble($_token_str, $secretKey)
    }
    static [string] GetToken([securestring]$secretKey, [byte[]]$salt, [timespan]$expires) {
        if ($expires.TotalSeconds -gt [int]::MaxValue) {
            Throw [System.ArgumentException]::new("Token max timespan is $([Math]::Floor([timespan]::new(0, 0, 0, [int]::MaxValue).TotalDays/365)) years.", 'Expires')
        }
        return [HKDF2]::GetToken($secretKey, $salt, $expires.TotalSeconds)
    }
    static [bool] VerifyToken([string]$TokenSTR, [securestring]$secretKey) {
        return [HKDF2]::VerifyToken($TokenSTR, $secretKey, (CryptoBase)::GetDerivedBytes($secretKey))
    }
    static [bool] VerifyToken([string]$TokenSTR, [securestring]$secretKey, [byte[]]$salt) {
        $_calcdhash = [HKDF2]::new($secretKey, $salt).GetBytes(4)
        $_secretKey = (CryptoBase)::GetKey((xconvert)::ToSecurestring((xconvert)::ToHexString($_calcdhash)))
        $_Token_STR = (Shuffl3r)::UnScramble($TokenSTR.Trim(), $secretKey)
        ($fb, $mdh) = (Shuffl3r)::Split((xconvert)::FromBase32String(($_Token_STR + '_' * 4)), $_secretKey, 4)
        $ht = [DateTime]::FromFileTime([long]::Parse([System.Text.Encoding]::UTF8.GetString($fb)))
        $rs = ($ht - [Datetime]::Now).TotalSeconds
        $NotExpired = $rs -ge 0
        Write-Verbose $("[HKDF2] The token {0} on: {1}" -f $(if ($NotExpired) { "will expire" } else { "expired" }), [datetime]::Now.AddSeconds($rs))
        return $NotExpired -and [HKDF2]::TestEqualByteArrays($_calcdhash, $mdh)
    }
    static [securestring] Resolve([securestring]$Password, [string]$TokenSTR) {
        return [HKDF2]::Resolve($Password, $TokenSTR, (CryptoBase)::GetDerivedBytes($Password))
    }
    static [securestring] Resolve([securestring]$Password, [string]$TokenSTR, [byte[]]$salt) {
        $derivedKey = [securestring]::new(); [System.IntPtr]$handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        Add-Type -AssemblyName System.Runtime.InteropServices
        Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $((xconvert)::ToString($Password));
        Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
        [ValidateNotNullOrEmpty()][string] $TokenSTR = $TokenSTR
        [ValidateNotNullOrEmpty()][string] $Passw0rd = $Passw0rd
        if ([HKDF2]::VerifyToken($TokenSTR, $Password, $salt)) {
            try {
                if ([System.Environment]::UserInteractive) { (Get-Variable host).Value.UI.WriteDebugLine("  [i] Using Password, With token: $TokenSTR") }
                $derivedKey = (xconvert)::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, $salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)));
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
    static [byte[]] HashPassword([string]$Passw0rd) {
        return [HKDF2]::HashPassword((xconvert)::ToSecurestring($Passw0rd))
    }
    static [byte[]] HashPassword([securestring]$Password) {
        return [HKDF2]::HashPassword($Password, (CryptoBase)::getDerivedBytes($Password))
    }
    static [byte[]] HashPassword([securestring]$Password, [byte[]]$Salt) {
        return [HKDF2]::HashPassword($Password, 1000, $Salt, 20)
    }
    static [byte[]] HashPassword([securestring]$Password, [int]$Iterations, [byte[]]$Salt, [int]$HashSize) {
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes((xconvert)::ToString($Password))
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $passwordBytes, $Salt, $Iterations
        $hash = $pbkdf2.GetBytes($HashSize)
        return $hash
    }
    static [bool] VerifyPassword([securestring]$password, [byte[]]$hash) {
        return [HKDF2]::VerifyPassword($password, $hash, 1000, (CryptoBase)::GetDerivedBytes($password), 20)
    }
    static [bool] VerifyPassword([securestring]$Password, [byte[]]$Hash, [int]$Iterations, [byte[]]$Salt, [int]$HashSize) {
        $hashToVerify = [HKDF2]::HashPassword($Password, $Iterations, $Salt, $HashSize)
        return [System.Linq.Enumerable]::SequenceEqual($hashToVerify, $Hash)
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

function CryptoBase {
    [CmdletBinding()]
    param ()
    end {
        return [CryptoBase]::New()
    }
}
function Shuffl3r {
    [CmdletBinding()]
    param ()
    end {
        return [Shuffl3r]::New()
    }
}

function AesGCM {
    [CmdletBinding()]
    param ()
    end {
        return [AesGCM]::New()
    }
}

function HKDF2 {
    [CmdletBinding()]
    param ()
    end {
        return [HKDF2]::New()
    }
}

function Get-UniqueMachineId {
    [CmdletBinding()]
    param ()
    process {
        return [CryptoBase]::GetUniqueMachineId()
    }
}
Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")