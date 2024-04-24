# Usage

```Powershell
using namespace Konscious.Security.Cryptography

class Argon2idKDF {
    [int]$Iterations = 10
    [int]$MemorySize = 1024 * 64  # 64 MB
    [int]$Parallelism = [Math]::Max(1, [Environment]::ProcessorCount / 2)
    [int]$OutputLength = 32  # 256 bits

    [byte[]]DeriveKey([byte[]]$Password, [byte[]]$Salt, [int]$OutputLength) {
        $argon2 = new Argon2id($Parallelism, $MemorySize, $Iterations)
        return $argon2.DeriveBytes($Password, $Salt, $OutputLength)
    }

    [byte[]]DeriveKey([string]$Password, [byte[]]$Salt, [int]$OutputLength) {
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        return $this.DeriveKey($passwordBytes, $Salt, $OutputLength)
    }

    [string]DeriveHashedKey([byte[]]$Password, [byte[]]$Salt) {
        $derivedKey = $this.DeriveKey($Password, $Salt, $this.OutputLength)
        return [Convert]::ToBase64String($derivedKey)
    }

    [string]DeriveHashedKey([string]$Password, [byte[]]$Salt) {
        $derivedKey = $this.DeriveKey($Password, $Salt, $this.OutputLength)
        return [Convert]::ToBase64String($derivedKey)
    }
}
```

This class provides the following methods:

DeriveKey: Derives a cryptographic key of the specified length from the given password and salt
DeriveHashedKey: Derives a cryptographic key from the given password and salt, and returns it as a Base64-encoded string

You can adjust the parameters like Iterations, MemorySize, Parallelism, and OutputLength to meet your specific requirements.
To use this class, you can create an instance and call the appropriate method:

```PowerShell
$kdf = [Argon2idKDF]::new()

# Derive a 32-byte (256-bit) key from a password and salt
$password = "myPassword"
$salt = [byte[]](0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
$key = $kdf.DeriveKey($password, $salt, 32)

# Derive a hashed key (Base64-encoded)
$hashedKey = $kdf.DeriveHashedKey($password, $salt)
```