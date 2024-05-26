# Module wiki

Managing sensitive information such as login credentials can be a daunting task. Traditional methods like storing passwords in spreadsheets or sticky notes are not only inconvenient but also pose significant security risks. Imagine having a personal, secure vault for all your secrets, accessible at your fingertips.
This is ArgonCage : A CLI tool using cutting-edge encryption for secure and efficient secret management.

**ArgonCage** is not limited to just passwords - from BitLocker logins to banking details, ArgonCage can encrypt and store all your secrets securely on your local system. Leveraging PowerShell's built-in security mechanisms and a 32-bit key for encryption, ArgonCage provides a reliable solution for managing secrets. Once connected to the vault, you can add, update, retrieve, and delete secrets with ease. Furthermore, ArgonCage allows you to **export** all your secrets and logins, making it a comprehensive tool for managing your day-to-day digital credentials.

## Installation

```powershell
PS /> Install-Module ArgonCage -Force
PS /> Import-Module ArgonCage -Force
```

### Module usage

Let's explore the cmdlets the module provides out of the box.

```powershell
PS /> Get-Command -Module ArgonCage

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Add-Secret                                       1.1.2      ArgonCage
....
```

Since we're using the module for first time we should register our credential. Then we should use the registered credential to connect the vault each time when we access it. You can run help on each cmdlet to know the parameters and functionality that it has to provide.

```powershell
PS /> Register-Vault
```

When you run the above cmdlet you will get a pop-up to enter the credential and recovery word. You should remember the recovery word to get the registered credential.
Once you've registered, connect to the vault.

```powershell
PS /> Connect-Vault

UserName                     Password Name          ConnectionFilePath
--------                     -------- ----          ------------------
testuser System.Security.SecureString ArgonCage C:\Users\testuser\.cos_testuser\connection.clixml
```

Once you've successfully connected to the vault you get a connection object. The connection file path is where the registered credential is saved. You can overwrite it using *Force* parameter in **Register-Vault** cmdlet. You can also remove the connection to the vault and re-register it. But to perform all these actions you should register first.

Now that we have connected to the vault, let's add a secret to it.

```powershell
PS /> Add-PSSecret -Name "testuser@gmail.com" -Value "mysecretvalue" -Metadata "My gmail user account"
```

**ArgonCage** validates the secret value before adding it to the vault and warns if it was hacked.

```powershell
PS /> Add-PSSecret -Name "testuser1@gmail.com" -Value "Password@123" -Metadata "My another gmail user account"

WARNING: Secret 'Password@123' was hacked 2448 time(s); Consider changing the secret value.
```

List all the stored secrets. Optionally, tab complete the names and get the secret value associated to it, either as an encrypted text or as a plain text.

```powershell
PS /> Get-Secret

Name                Value
----                -----
testuser1           76492d1116743f0423413b16050a5345MgB8ADMAKwBrADcAQQA3AEMASgBzAGoAbQBmAHQANABwAHgAMAB4ADQAVQAxAHcAPQA9AHwAZA...
testuser@gmail.com  76492d1116743f0423413b16050a5345MgB8AGQAUABNAFYAYwB6AEQANABVAGoAYgBIAG8AbwBuAFIAbwBEAFMAZwBlAFEAPQA9AHwAMA...
testuser1@gmail.com 76492d1116743f0423413b16050a5345MgB8AFAAeAA2AGcAcgB2AGIAbQBJAEIAbAA3AHEARQBlAHQATwB1AHAANwBNAHcAPQA9AHwANA...

PS /> Get-Secret -AsPlainText

Name                Value         Metadata
----                -----         --------
testuser1           Pass          My another gmail user account
testuser@gmail.com  mysecretvalue My gmail user account
testuser1@gmail.com Password@123  My another gmail user account
```

Get the key that is used to encrypt the credentials.

```powershell
PS /> Get-Key
UkbB4@swYJx\:qKDWyTInuMEg>1o53OV
```

You can rotate the key using *Force* parameter and save the secrets. This way you can use new key to encrypt the secrets which provides you an additional
security. To get the secrets you have to use the right key.

```powershell
PS /> Get-Key -Force
?x7GVMHZsiw:C0=XET@a]eoSzuYPU3Bd

PS /> Get-Secret -AsPlainText
WARNING: Cannot get the value as plain text; Use the right key to get the secret value as plain text.
```

For instance in the above example, you can't get the secrets because the key that was used to encrypt the secrets was different. You have use the same key to get the secrets as plain text. Once you have rotated the key, the old key will be archived so that you can still use it to get the secrets.

```powershell
PS /> Get-PSArchivedKey

DateModified          Key
------------          ---
10/08/2021 3:55:25 PM UkbB4@swYJx\:qKDWyTInuMEg>1o53OV
```

Now you can use the archived key to get the secrets.

```powershell
PS /> Get-Secret -AsPlainText -Key 'UkbB4@swYJx\:qKDWyTInuMEg>1o53OV'

Name                Value         Metadata
----                -----         --------
testuser1           Pass          My another gmail user account
testuser@gmail.com  mysecretvalue My gmail user account
testuser1@gmail.com Password@123  My another gmail user account
```

Update a secret value to the existing credential set. Tab complete the name parameter and update it's secret value easily.

```powershell
PS /> Update-Secret -Name testuser1 -Value "Thisisunhackablepassword" -Force
```

Remove the secret from the vault using it's Name.

```powershell
PS /> Remove-Secret -Name testuser1@gmail.com -Force
```

Import the registered credential using the recovery word.

```powershell
PS /> Import-Vault

cmdlet Import-Vault at command pipeline position 1
Supply values for the following parameters:
RecoveryWord: *****

UserName    Password
--------    --------
testuser Testuser
```

Explore the cmdlets and store the secrets locally & securely. Note that PowerShell uses Windows data protection API to encrypt the credentials. This means that only the user who saves the credential in the same machine can decrypt it.

### Running test

```PowerShell
build.ps1 -Task test
```

If you are just trying new changes in pwsh before commit, you can run:

```PowerShell
copy ./argoncage.psm1 ./module_tmp.ps1; . ./module_tmp.ps1; Remove-Item ./module_tmp.ps1
```
