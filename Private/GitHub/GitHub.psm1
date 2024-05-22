enum EncryptionScope {
    User    # The encrypted data can be decrypted with the same user on any machine.
    Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

class GitHub {
    static $webSession
    static [string] $UserName
    static hidden [bool] $IsInteractive = $false
    static hidden [EncryptionScope] $EncryptionScope = "Machine"
    static hidden [string] $TokenFile = (Get-GithubTokenFile)

    GitHub() {}
    static [PSObject] createSession() {
        return [Github]::createSession([Github]::UserName)
    }
    static [PSObject] createSession([string]$UserName) {
        [GitHub]::SetToken()
        return [GitHub]::createSession($UserName, (Get-GithubAPIToken))
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
    static [PsObject] GetUserInfo([string]$UserName) {
        Push-Stack 'GitHub'; if ([string]::IsNullOrWhiteSpace([GitHub]::userName)) { [GitHub]::createSession() }
        $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession ([GitHub]::webSession) -Method Get -Verbose:$false
        return $response
    }
    Static [string] GetGistContent([string]$FileName, [uri]$GistUri) {
        return (Get-GistInfo $GistUri).files.$FileName.content
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
    static [PsObject] UpdateGist($gist, [string]$NewContent) {
        return ''
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
        $cs = $null;
        $cs = Retry-Command -s { (CheckConnection -host "github.com" -msg "[Github] Testing Connection").Output }
        return $cs.Output
    }
}

class Gist {
    [uri] $Uri
    [string] $Id
    [string] $Owner
    [string] $Description
    [bool] $IsPublic
    [psobject[]] $Files = @()

    Gist() {}
    Gist([string]$Name) {
        # $this.AddFile([PSCustomObject]new($Name))
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
    [void] AddFile([psobject]$file) {
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

function Set-GitHubUsername ($Name) {
    [ValidateNotNullOrWhiteSpace()][string]$Name = $Name
    [GitHub]::UserName = $Name
}

function Get-GithubAPIToken {
    [CmdletBinding()]
    [OutputType([SecureString])]
    param ()

    begin {
        $sectoken = $null; $session_pass = (xconvert)::ToSecurestring('123');
        # todo: session pass should not be visible in code.
        # Fix: should be unique on each box. ex: (xconvert)::ToSecurestring((CryptoBase)::GetUniqueMachineId())
    }
    process {
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
                $session_pass = (CryptoBase)::GetPassword("[GitHub] Input password to use your token")
            } else {
                #Temporary_Workaround: Thisz a PAT from one of my GitHub a/cs. It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!
                $et = "kK1Dd8bEEbljDSUldb353Ff3cZAu+DEpXRu8KaBh1DWA5j3RPuDNIkriyZhyog/evFXz60wLJuZ80SmXyxnv29XOoGjLjs4y4QcOajIxM2APm0dl3Ej9JeKe30QEELriTFm1DRV7AYH7ol5O9sXfOuu593TeZawzYw=="
                [GitHub]::SetToken([system.Text.Encoding]::UTF8.GetString((AesGCM)::Decrypt([convert]::FromBase64String($et), $session_pass)), $session_pass)
            }
            $sectoken = (xconvert)::ToSecurestring([system.Text.Encoding]::UTF8.GetString(
                    (AesGCM)::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText((Get-GithubTokenFile))), $session_pass)
                )
            )
        } catch {
            throw $_
        }
    }

    end {
        return $sectoken
    }
}

function Get-GithubTokenFile() {
    if (![IO.File]::Exists([GitHub]::TokenFile)) {
        [GitHub]::TokenFile = [IO.Path]::Combine([GitHub]::Get_dataPath('Github', 'clicache'), "token");
    }
    return [GitHub]::TokenFile
}
function Get-GistInfo {
    # .SYNOPSIS
    #     Fetch all info about a gist
    [CmdletBinding(DefaultParameterSetName = 'ByUri')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ByUri', ValueFromPipeline = $true)]
        [uri]$uri,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ById')]
        [Alias('User')]
        [string]$UserName,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'ById')]
        [Alias('Id')]
        [string]$GistId
    )

    begin {
        $r = $null
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            Push-Stack 'GitHub';
            $t = Get-GithubAPIToken;
            if ($null -eq ([GitHub]::webSession)) {
                [GitHub]::webSession = $(if ($null -eq $t) {
                        [GitHub]::createSession($UserName)
                    } else {
                        [GitHub]::createSession($UserName, $t)
                    }
                )
            }
            if (!([GitHub]::IsConnected())) {
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
            $r = $(Retry-Command -s $FetchGistId -args @($GistId) -m "GitHub.FetchGist()  ").Output
        } else {
            $l = New-GistFile -GistUri ([uri]::new($Uri.AbsolutePath))
            $r = Get-GistInfo -UserName $l.Owner -Id $l.Id
        }
        $r = New-GistFile -GistInfo $r -Wrap
    }
    end {
        return $r
    }
}
function New-GistFile {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ByUri')]
        [ValidateNotNullOrEmpty()]
        [uri]$GistUri,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ByInfo')]
        [ValidateNotNullOrEmpty()]
        [PsObject]$GistInfo,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByInfo')]
        [switch]$Wrap
    )
    begin {
        $out = $null;
        function private:Set-StaticProp {
            param (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [System.Object]$Value
            )
            if ($null -ne $Value) {
                [PSCustomObject] | Add-Member -Name $Name -Force -MemberType ScriptProperty -Value {
                    return $Value
                }.GetNewClosure() -SecondValue {
                    throw [System.InvalidOperationException]::new("Cannot change $Name property")
                }
            } else {
                [PSCustomObject].PSObject.Properties.Remove($Name)
            }
        }

        function private:New-OutPutObject {
            param (
                [Parameter(Mandatory = $false)]
                [validateNotNullOrEmpty()]
                [string]$Name
            )
            return [PSCustomObject]@{
                Name      = $(if (![string]::IsNullOrWhiteSpace($Name)) { $Name } else { '' })
                language  = ''
                type      = ''
                owner     = ''
                raw_url   = ''
                IsPublic  = ''
                truncated = ''
                Id        = ''
                size      = ''
                files     = ''
                content   = ''
            }
        }
    }
    process {
        $PSCmdlet.ParameterSetName | Write-Verbose -Verbose
        if ($PSCmdlet.ParameterSetName -eq 'ByUri') {
            $ogs = $GistUri.AbsolutePath; $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
            $seg = $GistUri.Segments
            $res = $(if ($IsRawUri) {
                    Write-Verbose '$IsRawUri' -Verbose
                    $_name = $seg[-1]
                    $out = New-OutPutObject -Name $_name
                    $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                    $rtri = $rtri.Remove($rtri.Length - 1)
                    $info = [uri]::new($rtri) | Get-GistInfo
                    $file = $info.files."$_name"
                    Add-Member -InputObject $out -Name 'language' -MemberType NoteProperty -Value $file.language -Force
                    Add-Member -InputObject $out -Name 'IsPublic' -MemberType NoteProperty -Value $info.IsPublic -Force
                    Add-Member -InputObject $out -Name 'raw_url' -MemberType NoteProperty -Value $file.raw_url -Force
                    Add-Member -InputObject $out -Name 'owner' -MemberType NoteProperty -Value $info.owner.login -Force
                    Add-Member -InputObject $out -Name 'type' -MemberType NoteProperty -Value $file.type -Force
                    Add-Member -InputObject $out -Name 'size' -MemberType NoteProperty -Value $file.size -Force
                    Add-Member -InputObject $out -Name 'filename' -MemberType NoteProperty -Value $_name -Force
                    Add-Member -InputObject $out -Name 'filename' -MemberType NoteProperty -Value $file.language -Force
                    Add-Member -InputObject $out -Name 'Id' -MemberType NoteProperty -Value $seg[2].Replace('/', '') -Force
                    $out
                } else {
                    Write-Verbose '-not RawUri' -Verbose
                    Write-Verbose "($seg)" -Verbose
                    $out = New-OutPutObject
                    Add-Member -InputObject $out -Name 'owner' -MemberType NoteProperty -Value $seg[1].Split('/')[0] -Force
                    Add-Member -InputObject $out -Name 'IsPublic' -MemberType NoteProperty -Value ($null) -Force
                    Add-Member -InputObject $out -Name 'Id' -MemberType NoteProperty -Value $seg[-1] -Force
                    $out
                }
            )
            if (![string]::IsNullOrWhiteSpace($res.Owner)) {
                Write-Verbose 'Set-StaticProp UserName' -Verbose
                Set-StaticProp -Name 'UserName' -Value $res.Owner
            }
            $out = New-GistFile -GistInfo $res
            # $JobId = $(Start-Job -ScriptBlock {
            #         param ($GistInfo)
            #         return $GistInfo.ChildItems
            #     } -ArgumentList $res
            # ).Id
            # $out = Invoke-Command $(Get-WaitScript) -ArgumentList @('Get Gist items', $JobId)
        } elseif (!$wrap.IsPresent) {
            $out = $(if ($null -eq $GistInfo) { Write-Warning "Empty InputObject ⚠"; New-OutPutObject }else { $GistInfo })
            if ([string]::IsNullOrWhiteSpace($out.Owner)) {
                if (![string]::IsNullOrWhiteSpace([PSCustomObject].UserName)) {
                    $out.Owner = [PSCustomObject].UserName
                } else {
                    Write-Warning "Gist Owner was not set!"
                }
            }
            if ($null -eq ([PSCustomObject].ChildItems) -and ![string]::IsNullOrWhiteSpace($out.Id)) {
                Write-Verbose "GetGist ChildItems ..." -Verbose
                Set-StaticProp -Name 'ChildItems' -Value (Get-GistInfo -UserName $out.Owner -GistId $out.Id).files
            }
            if ($null -ne [PSCustomObject].ChildItems) {
                Write-Verbose '$null -ne [PSCustomObject].ChildItems ...' -Verbose
                [PsObject[]]$_files = @(); [string[]]$filenames = ([PSCustomObject].ChildItems | Get-Member -MemberType NoteProperty).Name
                try {
                    $filenames.Foreach({
                            $_Item = [PSCustomObject].ChildItems."$_"
                            Write-Verbose "New-OutPutObject for Filename $($_Item.filename)" -Verbose
                            $_Gist = New-OutPutObject -Name $_Item.filename
                            $_Gist.language = $_Item.language
                            $_Gist.Ispublic = $out.public
                            $_Gist.raw_url = $_Item.raw_url
                            $_Gist.type = $_Item.type
                            $_Gist.size = $_Item.size
                            $_Gist.content = $_Item.content
                            $_Gist.Owner = $out.Owner;
                            $_Gist.Id = $out.Id
                            $_files += $_Gist
                        }
                    )
                } finally {
                    # Set-StaticProp -Name 'ChildItems' -Value $null
                    $out.files = $_files
                    if ([string]::IsNullOrWhiteSpace($out.Name)) {
                        $out.Name = $filenames[0]
                    }
                }
            }
        } else {
            Write-Verbose "ByInfo Wrapppp ..." -Verbose
            $out = New-OutPutObject; ($out | Get-Member -MemberType NoteProperty).Name | ForEach-Object { $out.$_ = $GistInfo.$_ }
            $out.Ispublic = $GistInfo.public
            ('language', 'type', 'raw_url', 'truncated', 'content').ForEach({
                    if ($null -eq $out."$_") { $out.PSObject.Properties.Remove($_) }
                }
            )
        }
    }
    end {
        return $out
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")