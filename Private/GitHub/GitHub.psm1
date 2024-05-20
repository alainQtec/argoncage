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
        # $this.AddFile([GistFile]::new($Name))
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
            [GistFile]::ChildItems = (Get-GistInfo -UserName $this.Owner -GistId $this.Id).files
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
                $info = Get-GistInfo -uri ([uri]::new($rtri))
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
                #Fix: Temporary Workaround: Thisz a pat from one of my GitHub a/cs.It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!!
                $et = "+yDHse2ViCRxp7dBqhOa6Lju6Ww67ldUU2OaxG8w8aKqLsCmvsQB92Kv5YmYD7RFklr7Bc1dTeQlji38W3ha6RF9PneH1+7xd/8IFCkknVB6POZZANiSiaflmzq1dWxMIUzI6dzDBwNi6Xi0MSsRr6kjI+dqcQ5wZA=="
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
            $l = New-GistFile $Uri.AbsolutePath
            $r = Get-GistInfo -UserName $l.Owner -Id $l.Id
        }
        $r = [GistFile]::New($r)
    }
    end {
        return $r
    }
}
function New-GistFile {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri
    )
    begin {
        $res = $null; $GistUri = [uri]::new($Uri); $out = $null
    }
    process {
        $ogs = $GistUri.AbsolutePath; $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
        $seg = $GistUri.Segments
        $res = $(if ($IsRawUri) {
                $_name = $seg[-1]
                $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                $rtri = $rtri.Remove($rtri.Length - 1)
                $info = [uri]::new($rtri) | Get-GistInfo
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
                # $info = $GistUri | Get-GistInfo
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
        $out = [GistFile]::New($res)
        # $JobId = $(Start-Job -ScriptBlock {
        #         param ($GistInfo)
        #         return $GistInfo.ChildItems
        #     } -ArgumentList $res
        # ).Id
        # $out = Invoke-Command $(Get-WaitScript) -ArgumentList @('Get Gist items', $JobId)
    }
    end {
        return $out
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")