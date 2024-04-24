# Usage

Test libs only:

```Powershell
using namespace Konscious.Security.Cryptography

```

This class provides the following methods:

DeriveKey: Derives a cryptographic key of the specified length from the given password and salt
DeriveHashedKey: Derives a cryptographic key from the given password and salt, and returns it as a Base64-encoded string

You can adjust the parameters like Iterations, MemorySize, Parallelism, and OutputLength to meet your specific requirements.
To use this class, you can create an instance and call the appropriate method:
