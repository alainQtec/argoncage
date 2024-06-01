class GitHub {
    static $webSession
    static [string] $UserName
    static hidden [bool] $IsInteractive = $false
    static hidden [ValidateSet('User', 'Machine')][string] $EncryptionScope = "Machine"
    static hidden [string] $TokenFile = (Get-GitHubTokenPath)

    GitHub() {}

    static [PsObject] GetUserInfo([string]$UserName) {
        Push-Stack 'GitHub'; if ($null -eq (Get-GitHubSession)) { New-GitHubSession | Out-Null }
        $response = Invoke-RestMethod -Uri "https://api.github.com/user/$UserName" -WebSession (Get-GitHubSession) -Method Get -Verbose:$false
        return $response
    }
    Static [string] GetGistContent([string]$FileName, [uri]$GistUri) {
        return (New-GistFile -GistUri $GistUri).files.$FileName.content
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
                return Invoke-RestMethod -Uri $UriObj -WebSession (Get-GitHubSession) -Method Post -Body $JSONBODY -Verbose:$false
            }
        )
        return $(Invoke-RetriableCommand -s $CreateGist -args @($url, ($body | ConvertTo-Json)) -m "CreateGist").Output
    }
    static [PsObject] UpdateGist($gist, [string]$NewContent) {
        return ''
    }
    static [PsObject] GetUserRepositories() {
        if ($null -eq (Get-GitHubSession)) { New-GitHubSession | Out-Null }
        $response = Invoke-RestMethod -Uri 'https://api.github.com/user/repos' -WebSession (Get-GitHubSession) -Method Get -Verbose:$false
        return $response
    }
    static [bool] ValidateBase64String([string]$base64) {
        return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
    }
    static [bool] IsConnected() {
        $cs = $null;
        $cs = Invoke-RetriableCommand -s { (CheckConnection -host "github.com" -msg "[Github] Testing Connection" -IsOnline).Output }
        return $cs.Output
    }
}

function ConvertTo-ParsedUri {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$text,
        [switch]$throwOnFailure
    )

    process {
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
}

function Get-GitHubToken {
    [CmdletBinding()]
    [OutputType([SecureString])]
    param ()

    begin {
        $sectoken = $null; $session_pass = (xconvert)::ToSecurestring('123');
        $stknPath = Get-GitHubTokenPath
        # todo: session pass should not be visible in code.
        # Fix: session pass should be unique on each box. as (Get-UniqueMachineId) is unique.
    }
    process {
        try {
            if ([GitHub]::IsInteractive) {
                if ([string]::IsNullOrWhiteSpace((Get-Content -Path $stknPath -ErrorAction Ignore))) {
                    Write-Host "[GitHub] You'll need to set your api token first. This is a One-Time Process :)" -f Green
                    Set-GitHubToken
                    Write-Host "[GitHub] Good, now let's use the api token :)" -f DarkGreen
                } elseif ([GitHub]::ValidateBase64String([IO.File]::ReadAllText($stknPath))) {
                    Write-Host "[GitHub] Encrypted token found in file: $stknPath" -f DarkGreen
                } else {
                    throw [System.Exception]::New("Unable to read token file!")
                }
                $session_pass = (CryptoBase)::GetPassword("[GitHub] Input password to use your token")
            } else {
                #Temporary_Workaround: Thisz a PAT from one of my GitHub a/cs. It Can only read/write gists. Will expire on 1/1/2025. DoNot Abuse this or I'll take it down!
                $et = "kK1Dd8bEEbljDSUldb353Ff3cZAu+DEpXRu8KaBh1DWA5j3RPuDNIkriyZhyog/evFXz60wLJuZ80SmXyxnv29XOoGjLjs4y4QcOajIxM2APm0dl3Ej9JeKe30QEELriTFm1DRV7AYH7ol5O9sXfOuu593TeZawzYw=="
                Set-GitHubToken -token $([system.Text.Encoding]::UTF8.GetString((AesGCM)::Decrypt([convert]::FromBase64String($et), $session_pass))) -password $session_pass
            }
            $sectoken = (xconvert)::ToSecurestring([system.Text.Encoding]::UTF8.GetString(
                    (AesGCM)::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText((Get-GitHubTokenPath))), $session_pass)
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

function Set-GitHubToken {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$token,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [securestring]$password
    )

    begin {
        $BoundParams = $PSCmdlet.MyInvocation.BoundParameters
        if (!$BoundParams.ContainsKey('token')) {
            $token = (xconvert)::Tostring((Read-Host -Prompt "[GitHub] Paste/write your api token" -AsSecureString))
        }
        if (!$BoundParams.ContainsKey('password')) {
            $password = Read-Host -Prompt "[GitHub] Paste/write a Password to encrypt the token" -AsSecureString
        }
    }

    process {
        $FilePath = Get-GitHubTokenPath; if (![IO.File]::Exists($FilePath)) {
            New-Item -Type File -Path $FilePath -Force | Out-Null
        }
        [IO.File]::WriteAllText($FilePath, [convert]::ToBase64String((AesGCM)::Encrypt([system.Text.Encoding]::UTF8.GetBytes($token), $password)), [System.Text.Encoding]::UTF8);
    }
}
function Get-GitHubTokenPath() {
    return [IO.Path]::Combine((Get-DataPath 'Github' 'clicache'), "token")
}

function Get-GitHubSession () {
    return [GitHub]::webSession
}

function New-GitHubSession () {
    [CmdletBinding()]
    [OutputType([Psobject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][Alias('u')]
        [string]$UserName,

        [Parameter(Mandatory = $true, Position = 1)]
        [AllowNull()][Alias('t')]
        [securestring]$token
    )
    process {
        if (!$PSCmdlet.MyInvocation.BoundParameters.ContainsKey('token') -or $null -eq $token) {
            Set-GitHubToken; $token = Get-GitHubToken
        }
        [ValidateNotNullOrEmpty()][string]$GithubToken = $GithubToken = (xconvert)::Tostring([securestring]$token)
        $encodedAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($UserName):$($GithubToken)"))
        $web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        [void]$web_session.Headers.Add('Authorization', "Basic $($encodedAuth)")
        [void]$web_session.Headers.Add('Accept', 'application/vnd.github.v3+json')
        [GitHub]::webSession = $web_session
        return $web_session
    }
}

function Set-GitHubUsername ($Name) {
    [ValidateNotNullOrWhiteSpace()][string]$Name = $Name
    [GitHub]::UserName = $Name
}

function New-GistObject {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [validateNotNullOrEmpty()]
        [string]$Name
    )
    process {
        $go = [PSCustomObject]@{
            Name      = $(if (![string]::IsNullOrWhiteSpace($Name)) { $Name } else { '' })
            language  = ''
            type      = ''
            owner     = ''
            raw_url   = ''
            IsPublic  = [bool]0
            truncated = ''
            Id        = ''
            size      = ''
            files     = [System.Management.Automation.PSDataCollection[psobject]]::new()
            content   = ''
        }
        $go.PsObject.Methods.Add(
            [psscriptmethod]::new('AddFile', {
                    $this.Files += $file
                }
            )
        )
        $go.PsObject.Methods.Add(
            [psscriptmethod]::new('Post', {
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
            )
        )
        $go.PsObject.Methods.Add([psscriptmethod]::new('ShowInfo', {
                    $info = "Gist ID: $($this.Id)"
                    $info += "`nDescription: $($this.Description)"
                    $info += "`nFiles:"
                    foreach ($file in $this.Files.Values) {
                        $info += "`n  - $($file.ShowFileInfo())"
                    }
                    return $info
                }
            )
        )
    }
    end {
        return $go
    }
}

function Get-GistChildItems {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ById')]
        [Alias('User')]
        [string]$UserName,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ByUri', ValueFromPipeline = $true)]
        [uri]$Uri,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'ById')]
        [Alias('Id')]
        [string]$GistId = '*'
    )
    begin {
        $result = $null
        $FetchGistId = [scriptblock]::Create({
                param (
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()][string]$Id
                )
                return Invoke-RestMethod -Uri "https://api.github.com/gists/$Id" -WebSession (Get-GitHubSession) -Method Get -Verbose:$false
            }
        )
    }
    process {
        ($UserName, $GistId) = $(if ($PSCmdlet.ParameterSetName -eq 'ByUri') {
                $ogs = $Uri.OriginalString; $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
                $seg = $Uri.Segments
                if ($IsRawUri) {
                    $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                    $rtri = $rtri.Remove($rtri.Length - 1)
                    $seg[1].Replace('/', ''), $seg[2].Replace('/', '')
                } else {
                    $seg[1].Split('/')[0], $seg[-1]
                }
            } else {
                $UserName, $GistId
            }
        )
        $t = Get-GitHubToken; if ($null -eq (Get-GitHubSession)) { New-GitHubSession -u $UserName -t $t }
        if ([string]::IsNullOrWhiteSpace($GistId) -or $GistId -eq '*') {
            $result = Get-Gists -UserName $UserName -SecureToken $t
        } else {
            $result = $(Invoke-RetriableCommand -s $FetchGistId -args @($GistId) -m "Get-GistChildItems > GitHub.FetchGist()  ").Output.files
        }
        [PsObject[]]$_files = @(); [string[]]$filenames = ($result | Get-Member -MemberType NoteProperty).Name
        $filenames.Foreach({
                $_Item = $result."$_"
                $_Gist = New-GistObject -Name $_Item.filename
                $_Gist.language = $_Item.language
                $_Gist.Ispublic = $result.public
                $_Gist.raw_url = $_Item.raw_url
                $_Gist.type = $_Item.type
                $_Gist.size = $_Item.size
                $_Gist.content = $_Item.content
                $_Gist.Owner = $result.Owner;
                $_Gist.Id = $result.Id
                $_files += $_Gist
            }
        )
        $result = $_files
    }
    end {
        return $result
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
    }
    process {
        if (!([GitHub]::IsConnected())) {
            throw [System.Net.NetworkInformation.PingException]::new("PingException, PLease check your connection!");
        }
        if ($PSCmdlet.ParameterSetName -eq 'ByUri') {
            $ogs = $GistUri.AbsolutePath; $IsRawUri = $ogs.Contains('/raw/') -and $ogs.Contains('gist.githubusercontent.com')
            $seg = $GistUri.Segments
            if ($IsRawUri) {
                $_name = $seg[-1]
                $out = New-GistObject -Name $_name
                $rtri = 'https://gist.github.com/{0}{1}' -f $seg[1], $seg[2]
                $rtri = $rtri.Remove($rtri.Length - 1)
                $info = New-GistFile -GistUri ([uri]::new($rtri))
                $file = $info.files."$_name"
                $out.language = $file.language
                $out.IsPublic = $info.IsPublic
                $out.raw_url = $file.raw_url
                $out.owner = $info.owner.login
                $out.type = $file.type
                $out.size = $file.size
                $out.Name = $_name
                $out.Id = $seg[2].Replace('/', '')
            } else {
                $out = New-GistObject; $out.owner = $seg[1].Split('/')[0]
                $out.IsPublic = $null
                $out.Id = $seg[-1]
            }
            if (![string]::IsNullOrWhiteSpace($out.Owner)) { Set-StaticProp -Name 'UserName' -Value $out.Owner }
            $out.files = (Get-GistChildItems -UserName $out.Owner -GistId $out.Id).Where({ ![string]::IsNullOrWhiteSpace($_.size.ToString()) })
            # $JobId = $(Start-Job -ScriptBlock {
            #         param ($GistInfo)
            #         return $GistInfo.ChildItems
            #     } -ArgumentList $res
            # ).Id
            # $out = Invoke-Command $(Get-WaitScript) -ArgumentList @('Get Gist items', $JobId)
        } elseif (!$wrap.IsPresent) {
            $out = $(if ($null -eq $GistInfo) { Write-Warning "Empty InputObject ⚠"; New-GistObject }else { $GistInfo })
            if ([string]::IsNullOrWhiteSpace($out.Owner)) {
                if (![string]::IsNullOrWhiteSpace([PSCustomObject].UserName)) {
                    $out.Owner = [PSCustomObject].UserName
                } else {
                    Write-Warning "Gist Owner was not set!"
                }
            }
            if ($null -eq ([PSCustomObject].ChildItems) -and ![string]::IsNullOrWhiteSpace($out.Id)) {
                Set-StaticProp -Name 'ChildItems' -Value $(Get-GistChildItems -User $out.Owner -Id $out.Id)
            }
            if ($null -ne [PSCustomObject].ChildItems) {
                $out.files = [PSCustomObject].ChildItems.Where({ ![string]::IsNullOrWhiteSpace($_.size.ToString()) })
            }
        } else {
            $out = New-GistObject; ($out | Get-Member -MemberType NoteProperty).Name | ForEach-Object { $out.$_ = $GistInfo.$_ }
            $out.Ispublic = $GistInfo.public
        }
        if ([string]::IsNullOrWhiteSpace($out.Name) -and $out.files) {
            $out.Name = $out.files.Name[0]
        }
    }
    end {
        return $out
    }
}

Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")