param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch]$Once,
    [switch]$StatusOnly,
    [switch]$Repair,
    [switch]$NoStatusHtml
)

$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch {
    # Older Windows builds may not expose every enum value. The default still works for the campus HTTP portal.
}

function New-SingleInstanceLock {
    param([string]$LockFilePath)

    $lockDirectory = Split-Path -Parent $LockFilePath
    if ($lockDirectory -and -not (Test-Path -LiteralPath $lockDirectory)) {
        New-Item -ItemType Directory -Path $lockDirectory | Out-Null
    }

    try {
        $stream = [System.IO.File]::Open(
            $LockFilePath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )

        $stream.SetLength(0)
        $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)), 1024, $true)
        $writer.WriteLine("pid=$PID")
        $writer.WriteLine("started=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $writer.WriteLine("script=$PSCommandPath")
        $writer.Flush()
        $stream.Flush()
        $stream.Position = 0

        return $stream
    } catch [System.IO.IOException] {
        Write-Host 'Another campus auto-login script is already running for this folder.'
        Write-Host 'Exit the existing PowerShell window with Ctrl+C, or end it in Task Manager / Process Manager.'
        Write-Host "Lock file: $LockFilePath"
        exit 2
    }
}

$script:InstanceLockStream = New-SingleInstanceLock -LockFilePath (Join-Path $PSScriptRoot '.auto-login.lock')
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:InstanceLockStream) {
        $script:InstanceLockStream.Dispose()
    }
} | Out-Null

if (-not ('SrunPortalCrypto' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class SrunPortalCrypto
{
    private const string SrunAlphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    public static string HmacMd5Hex(string message, string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key ?? "");
        byte[] messageBytes = Encoding.UTF8.GetBytes(message ?? "");
        using (HMACMD5 hmac = new HMACMD5(keyBytes))
        {
            return ToHex(hmac.ComputeHash(messageBytes));
        }
    }

    public static string Sha1Hex(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text ?? "");
        using (SHA1 sha1 = SHA1.Create())
        {
            return ToHex(sha1.ComputeHash(bytes));
        }
    }

    public static string SrunInfo(string json, string token)
    {
        return "{SRBX1}" + CustomBase64Encode(XEncodeToBytes(json ?? "", token ?? ""), SrunAlphabet);
    }

    private static string ToHex(byte[] bytes)
    {
        StringBuilder builder = new StringBuilder(bytes.Length * 2);
        for (int i = 0; i < bytes.Length; i++)
        {
            builder.Append(bytes[i].ToString("x2"));
        }
        return builder.ToString();
    }

    private static uint[] ToUInt32Array(string value, bool includeLength)
    {
        int length = value.Length;
        int arrayLength = (length + 3) / 4;
        uint[] result = new uint[arrayLength + (includeLength ? 1 : 0)];

        unchecked
        {
            for (int i = 0; i < length; i += 4)
            {
                uint item = 0;
                for (int j = 0; j < 4; j++)
                {
                    int index = i + j;
                    uint code = index < length ? (uint)value[index] : 0u;
                    item |= code << (8 * j);
                }
                result[i >> 2] = item;
            }
        }

        if (includeLength)
        {
            result[result.Length - 1] = (uint)length;
        }
        return result;
    }

    private static byte[] XEncodeToBytes(string message, string key)
    {
        if (message.Length == 0)
        {
            return new byte[0];
        }

        uint[] v = ToUInt32Array(message, true);
        uint[] k = ToUInt32Array(key, false);
        if (k.Length < 4)
        {
            Array.Resize(ref k, 4);
        }

        unchecked
        {
            uint n = (uint)(v.Length - 1);
            uint z = v[n];
            uint y = v[0];
            uint c = 0x86014019u | 0x183639A0u;
            uint d = 0;
            uint q = (uint)Math.Floor(6.0 + 52.0 / (n + 1));

            while (q-- > 0)
            {
                d += c;
                uint e = (d >> 2) & 3;
                uint p;

                for (p = 0; p < n; p++)
                {
                    y = v[p + 1];
                    uint m = (z >> 5) ^ (y << 2);
                    m += (y >> 3) ^ (z << 4) ^ (d ^ y);
                    m += k[(int)((p & 3) ^ e)] ^ z;
                    z = v[p] = v[p] + m;
                }

                y = v[0];
                uint last = (z >> 5) ^ (y << 2);
                last += (y >> 3) ^ (z << 4) ^ (d ^ y);
                last += k[(int)((p & 3) ^ e)] ^ z;
                z = v[n] = v[n] + last;
            }
        }

        byte[] output = new byte[v.Length * 4];
        for (int i = 0; i < v.Length; i++)
        {
            output[i * 4] = (byte)(v[i] & 0xff);
            output[i * 4 + 1] = (byte)((v[i] >> 8) & 0xff);
            output[i * 4 + 2] = (byte)((v[i] >> 16) & 0xff);
            output[i * 4 + 3] = (byte)((v[i] >> 24) & 0xff);
        }
        return output;
    }

    private static string CustomBase64Encode(byte[] bytes, string alphabet)
    {
        if (bytes.Length == 0)
        {
            return "";
        }

        StringBuilder result = new StringBuilder(((bytes.Length + 2) / 3) * 4);
        int fullLength = bytes.Length - (bytes.Length % 3);

        for (int i = 0; i < fullLength; i += 3)
        {
            int b10 = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            result.Append(alphabet[(b10 >> 18) & 63]);
            result.Append(alphabet[(b10 >> 12) & 63]);
            result.Append(alphabet[(b10 >> 6) & 63]);
            result.Append(alphabet[b10 & 63]);
        }

        int remain = bytes.Length - fullLength;
        if (remain == 1)
        {
            int b10 = bytes[fullLength] << 16;
            result.Append(alphabet[(b10 >> 18) & 63]);
            result.Append(alphabet[(b10 >> 12) & 63]);
            result.Append("==");
        }
        else if (remain == 2)
        {
            int b10 = (bytes[fullLength] << 16) | (bytes[fullLength + 1] << 8);
            result.Append(alphabet[(b10 >> 18) & 63]);
            result.Append(alphabet[(b10 >> 12) & 63]);
            result.Append(alphabet[(b10 >> 6) & 63]);
            result.Append('=');
        }

        return result.ToString();
    }
}
'@
}

function Get-UnixMilliseconds {
    return [int64](([DateTime]::UtcNow - [DateTime]'1970-01-01T00:00:00Z').TotalMilliseconds)
}

function Get-ConfigValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default
    )
    if ($Object -and $Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

function Get-ConfigArray {
    param(
        [object]$Object,
        [string]$Name,
        [object[]]$Default
    )
    $value = Get-ConfigValue -Object $Object -Name $Name -Default $Default
    if ($null -eq $value) {
        return @()
    }
    if ($value -is [System.Array]) {
        return @($value)
    }
    return @($value)
}

function Resolve-ConfigPath {
    param(
        [string]$Path,
        [string]$BasePath
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $BasePath $Path)
}

function Get-ObjectProperty {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )
    if ($Object -and $Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

function ConvertTo-JsonStringLiteral {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return 'null'
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')

    foreach ($char in $Value.ToCharArray()) {
        $code = [int][char]$char
        if ($code -eq 34) {
            [void]$builder.Append('\"')
        } elseif ($code -eq 92) {
            [void]$builder.Append('\\')
        } elseif ($code -eq 8) {
            [void]$builder.Append('\b')
        } elseif ($code -eq 12) {
            [void]$builder.Append('\f')
        } elseif ($code -eq 10) {
            [void]$builder.Append('\n')
        } elseif ($code -eq 13) {
            [void]$builder.Append('\r')
        } elseif ($code -eq 9) {
            [void]$builder.Append('\t')
        } elseif ($code -lt 32) {
            [void]$builder.Append('\u')
            [void]$builder.Append($code.ToString('x4'))
        } else {
            [void]$builder.Append($char)
        }
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-SrunInfoJson {
    param(
        [string]$Username,
        [string]$AuthText,
        [string]$Ip,
        [string]$AcId,
        [string]$EncVer
    )

    return ('{{"username":{0},"password":{1},"ip":{2},"acid":{3},"enc_ver":{4}}}' -f `
        (ConvertTo-JsonStringLiteral $Username),
        (ConvertTo-JsonStringLiteral $AuthText),
        (ConvertTo-JsonStringLiteral $Ip),
        (ConvertTo-JsonStringLiteral $AcId),
        (ConvertTo-JsonStringLiteral $EncVer))
}

function ConvertFrom-SecureStringPlainText {
    param([Security.SecureString]$SecureString)

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function New-QueryString {
    param([System.Collections.IDictionary]$Params)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Params.Keys) {
        $value = $Params[$key]
        if ($null -eq $value) {
            continue
        }
        $encodedKey = [Uri]::EscapeDataString([string]$key)
        $encodedValue = [Uri]::EscapeDataString([string]$value)
        $parts.Add(('{0}={1}' -f $encodedKey, $encodedValue))
    }
    return [string]::Join('&', $parts.ToArray())
}

function Invoke-HttpGet {
    param(
        [string]$Uri,
        [int]$TimeoutSec
    )

    $parameters = @{
        Uri = $Uri
        TimeoutSec = $TimeoutSec
        ErrorAction = 'Stop'
        Headers = @{
            'Accept' = '*/*'
            'User-Agent' = 'Mozilla/5.0 CampusAutoLogin/1.0'
        }
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $parameters['UseBasicParsing'] = $true
    }

    return Invoke-WebRequest @parameters
}

function ConvertFrom-Jsonp {
    param([string]$Text)

    $trimmed = ($Text -as [string]).Trim()
    if ($trimmed -match '(?s)^[\w\.\$]+\((.*)\)\s*;?\s*$') {
        $trimmed = $Matches[1]
    }
    return $trimmed | ConvertFrom-Json
}

function Invoke-PortalJsonp {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Params = ([ordered]@{})
    )

    $query = [ordered]@{}
    foreach ($key in $Params.Keys) {
        $query[$key] = $Params[$key]
    }

    $query['callback'] = 'jsonp' + (Get-UnixMilliseconds)
    $query['_'] = Get-UnixMilliseconds

    if (-not $Path.StartsWith('/')) {
        $Path = '/' + $Path
    }

    $uri = '{0}://{1}{2}?{3}' -f $script:PortalScheme, $script:PortalHost, $Path, (New-QueryString $query)
    $response = Invoke-HttpGet -Uri $uri -TimeoutSec $script:RequestTimeoutSeconds
    return ConvertFrom-Jsonp -Text ([string]$response.Content)
}

function Format-ByteCount {
    param([object]$Bytes)

    if ($null -eq $Bytes) {
        return ''
    }

    $value = [double]$Bytes
    $units = @('B', 'KB', 'MB', 'GB', 'TB')
    $index = 0
    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index += 1
    }
    return ('{0:n2} {1}' -f $value, $units[$index])
}

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpperInvariant(), $Message
    Write-Host $line
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    }
}

function Write-StatusFiles {
    param([System.Collections.IDictionary]$Status)

    $statusObject = [pscustomobject]$Status

    if ($script:StatusFilePath) {
        $statusObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:StatusFilePath -Encoding UTF8
    }

    if ($script:StatusHtmlPath -and -not $NoStatusHtml) {
        $rows = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Status.Keys) {
            $value = $Status[$key]
            if ($value -is [System.Array]) {
                $value = [string]::Join(', ', @($value))
            }
            $encodedKey = [System.Net.WebUtility]::HtmlEncode([string]$key)
            $encodedValue = [System.Net.WebUtility]::HtmlEncode([string]$value)
            $rows.Add("<tr><th>$encodedKey</th><td>$encodedValue</td></tr>")
        }

        $generated = [System.Net.WebUtility]::HtmlEncode((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
        $html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="10">
  <title>Campus Auto Login Status</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f8fafc; }
    main { max-width: 920px; margin: 0 auto; background: white; border: 1px solid #d9e2ec; border-radius: 8px; padding: 20px 24px; }
    h1 { font-size: 22px; margin: 0 0 16px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
    th { width: 220px; color: #475569; background: #f8fafc; }
    footer { margin-top: 14px; color: #64748b; font-size: 12px; }
  </style>
</head>
<body>
  <main>
    <h1>Campus Auto Login Status</h1>
    <table>
      $([string]::Join("`n      ", $rows.ToArray()))
    </table>
    <footer>Generated $generated. This page refreshes every 10 seconds.</footer>
  </main>
</body>
</html>
"@
        Set-Content -LiteralPath $script:StatusHtmlPath -Value $html -Encoding UTF8
    }
}

function Get-ClientIpForPortal {
    $configuredIp = Get-ConfigValue -Object $script:Config -Name 'LocalIp' -Default ''
    if (-not [string]::IsNullOrWhiteSpace($configuredIp)) {
        return [string]$configuredIp
    }

    $port = 80
    if ($script:PortalScheme -eq 'https') {
        $port = 443
    }

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($script:PortalHost, $port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(2000, $false) -and $client.Connected) {
            $ip = $client.Client.LocalEndPoint.Address.ToString()
            $client.Close()
            if ($ip -and $ip -notmatch '^169\.254\.') {
                return $ip
            }
        }
        $client.Close()
    } catch {
    }

    try {
        $configs = Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
            $_.IPv4DefaultGateway -and $_.IPv4Address
        }
        foreach ($config in $configs) {
            foreach ($address in $config.IPv4Address) {
                if ($address.IPAddress -and $address.IPAddress -notmatch '^169\.254\.') {
                    return $address.IPAddress
                }
            }
        }
    } catch {
    }

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $_.ToString() -notmatch '^169\.254\.'
        }
        if ($addresses) {
            return $addresses[0].ToString()
        }
    } catch {
    }

    return ''
}

function Get-RemoteProcessSnapshot {
    $processNames = Get-ConfigArray -Object $script:Config -Name 'RemoteProcessNames' -Default @()
    $running = New-Object System.Collections.Generic.List[string]

    foreach ($name in $processNames) {
        if ([string]::IsNullOrWhiteSpace([string]$name)) {
            continue
        }
        $cleanName = [System.IO.Path]::GetFileNameWithoutExtension([string]$name)
        $process = Get-Process -Name $cleanName -ErrorAction SilentlyContinue
        if ($process) {
            $running.Add($cleanName)
        }
    }

    return @($running.ToArray() | Sort-Object -Unique)
}

function Test-InternetAccess {
    $urls = Get-ConfigArray -Object $script:Config -Name 'InternetCheckUrls' -Default @()
    $results = New-Object System.Collections.Generic.List[string]

    foreach ($url in $urls) {
        if ([string]::IsNullOrWhiteSpace([string]$url)) {
            continue
        }

        try {
            $response = Invoke-HttpGet -Uri ([string]$url) -TimeoutSec $script:RequestTimeoutSeconds
            $statusCode = [int]$response.StatusCode
            $content = [string]$response.Content
            $finalUri = [string]$url

            if ($response.BaseResponse -and $response.BaseResponse.ResponseUri) {
                $finalUri = [string]$response.BaseResponse.ResponseUri
            }

            $looksLikePortal = $false
            if ($finalUri -match [regex]::Escape($script:PortalHost)) {
                $looksLikePortal = $true
            }
            if ($content -match 'srun_portal|login-account|rad_user_info|get_challenge') {
                $looksLikePortal = $true
            }

            $ok = $false
            if ($url -match 'connecttest\.txt') {
                $ok = ($statusCode -eq 200 -and $content -match 'Microsoft Connect Test')
            } elseif ($url -match 'generate_204') {
                $ok = ($statusCode -eq 204)
            } else {
                $ok = ($statusCode -ge 200 -and $statusCode -lt 400 -and -not $looksLikePortal)
            }

            $results.Add(('{0} => HTTP {1}' -f $url, $statusCode))
            if ($ok) {
                return [pscustomobject]@{
                    Online = $true
                    Detail = ('OK: {0}' -f $url)
                    Results = @($results.ToArray())
                }
            }
        } catch {
            $results.Add(('{0} => {1}' -f $url, $_.Exception.Message))
        }
    }

    return [pscustomobject]@{
        Online = $false
        Detail = 'No internet check URL succeeded'
        Results = @($results.ToArray())
    }
}

function Get-PortalStatus {
    try {
        $response = Invoke-PortalJsonp -Path '/cgi-bin/rad_user_info' -Params ([ordered]@{})
        $errorValue = [string](Get-ObjectProperty -Object $response -Name 'error' -Default '')

        if ($errorValue -eq 'ok') {
            return [pscustomobject]@{
                Reachable = $true
                Online = $true
                Username = [string](Get-ObjectProperty -Object $response -Name 'user_name' -Default '')
                Ip = [string](Get-ObjectProperty -Object $response -Name 'online_ip' -Default (Get-ObjectProperty -Object $response -Name 'user_ip' -Default ''))
                UsedBytes = Get-ObjectProperty -Object $response -Name 'sum_bytes' -Default $null
                RawError = $errorValue
                Detail = 'Portal reports online'
            }
        }

        return [pscustomobject]@{
            Reachable = $true
            Online = $false
            Username = ''
            Ip = ''
            UsedBytes = $null
            RawError = $errorValue
            Detail = ('Portal reports offline: {0}' -f $errorValue)
        }
    } catch {
        return [pscustomobject]@{
            Reachable = $false
            Online = $false
            Username = ''
            Ip = ''
            UsedBytes = $null
            RawError = ''
            Detail = ('Portal status failed: {0}' -f $_.Exception.Message)
        }
    }
}

function Import-CampusCredential {
    $credentialPath = Resolve-ConfigPath -Path (Get-ConfigValue -Object $script:Config -Name 'CredentialFile' -Default '.\credential.xml') -BasePath $script:ConfigBasePath
    if (-not (Test-Path -LiteralPath $credentialPath)) {
        throw "Credential file is missing. Run setup.ps1 first: $credentialPath"
    }

    $credential = Import-Clixml -LiteralPath $credentialPath
    if (-not ($credential -is [System.Management.Automation.PSCredential])) {
        throw "Credential file is not a PSCredential: $credentialPath"
    }
    return $credential
}

function Invoke-SrunLoginAttempt {
    param(
        [string]$Username,
        [string]$AuthText,
        [string]$InitialIp
    )

    $clientIp = [string]$InitialIp
    $challengeResponse = Invoke-PortalJsonp -Path '/cgi-bin/get_challenge' -Params ([ordered]@{
        username = $Username
        ip = $clientIp
    })

    $token = [string](Get-ObjectProperty -Object $challengeResponse -Name 'challenge' -Default '')
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Challenge token is empty'
    }

    $challengeIp = [string](Get-ObjectProperty -Object $challengeResponse -Name 'client_ip' -Default '')
    $challengeRefreshed = $false
    if (-not [string]::IsNullOrWhiteSpace($challengeIp) -and $clientIp -ne $challengeIp) {
        $clientIp = $challengeIp
        $challengeResponse = Invoke-PortalJsonp -Path '/cgi-bin/get_challenge' -Params ([ordered]@{
            username = $Username
            ip = $clientIp
        })
        $token = [string](Get-ObjectProperty -Object $challengeResponse -Name 'challenge' -Default '')
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw 'Challenge token is empty after IP refresh'
        }
        $challengeRefreshed = $true
    } elseif ([string]::IsNullOrWhiteSpace($clientIp)) {
        $clientIp = Get-ClientIpForPortal
    }

    $type = '1'
    $n = '200'
    $enc = 'srun_bx1'
    $acId = [string]$script:AcId
    $hmd5 = [SrunPortalCrypto]::HmacMd5Hex($AuthText, $token)
    $infoJson = New-SrunInfoJson -Username $Username -AuthText $AuthText -Ip $clientIp -AcId $acId -EncVer $enc
    $info = [SrunPortalCrypto]::SrunInfo($infoJson, $token)

    $checkString = $token + $Username
    $checkString += $token + $hmd5
    $checkString += $token + $acId
    $checkString += $token + $clientIp
    $checkString += $token + $n
    $checkString += $token + $type
    $checkString += $token + $info

    $checksum = [SrunPortalCrypto]::Sha1Hex($checkString)

    $loginResponse = Invoke-PortalJsonp -Path '/cgi-bin/srun_portal' -Params ([ordered]@{
        action = 'login'
        username = $Username
        password = ('{MD5}' + $hmd5)
        os = 'Windows 10'
        name = 'Windows'
        double_stack = '0'
        chksum = $checksum
        info = $info
        ac_id = $acId
        ip = $clientIp
        n = $n
        type = $type
    })

    $errorValue = [string](Get-ObjectProperty -Object $loginResponse -Name 'error' -Default '')
    $errorMessage = [string](Get-ObjectProperty -Object $loginResponse -Name 'error_msg' -Default '')
    $successMessage = [string](Get-ObjectProperty -Object $loginResponse -Name 'suc_msg' -Default '')
    $policyMessage = [string](Get-ObjectProperty -Object $loginResponse -Name 'ploy_msg' -Default '')
    $alreadyOnline = ($errorMessage -match 'AlreadyOnline|IpAlreadyOnline|IPHasBeenOnline|E2620|E6526') -or ($successMessage -match 'already_online')

    $treatAlreadyOnline = [bool](Get-ConfigValue -Object $script:Config -Name 'TreatPortalAlreadyOnlineAsSuccess' -Default $true)
    $success = ($errorValue -eq 'ok') -or ($successMessage -match 'login_ok|E0000') -or ($treatAlreadyOnline -and $alreadyOnline)

    return [pscustomobject]@{
        Success = $success
        ClientIp = $clientIp
        InitialIp = if ($InitialIp) { $InitialIp } else { '<empty>' }
        ChallengeIp = $challengeIp
        ChallengeRefreshed = $challengeRefreshed
        Error = $errorValue
        ErrorMessage = $errorMessage
        SuccessMessage = $successMessage
        PolicyMessage = $policyMessage
        Detail = if ($success) { 'Login request accepted' } else { 'Login request rejected' }
    }
}

function Invoke-SrunLogin {
    $credential = Import-CampusCredential
    $username = $credential.UserName
    $password = ConvertFrom-SecureStringPlainText -SecureString $credential.Password
    $configuredIp = Get-ConfigValue -Object $script:Config -Name 'LocalIp' -Default ''

    try {
        $ipCandidates = New-Object System.Collections.Generic.List[string]
        if (-not [string]::IsNullOrWhiteSpace([string]$configuredIp)) {
            $ipCandidates.Add([string]$configuredIp)
        }
        $ipCandidates.Add('')
        $detectedIp = Get-ClientIpForPortal
        if (-not [string]::IsNullOrWhiteSpace($detectedIp)) {
            $ipCandidates.Add($detectedIp)
        }

        $lastResult = $null
        foreach ($ipCandidate in @($ipCandidates.ToArray() | Select-Object -Unique)) {
            $lastResult = Invoke-SrunLoginAttempt -Username $username -AuthText $password -InitialIp $ipCandidate
            if ($lastResult.Success -or $lastResult.Error -ne 'challenge_expire_error') {
                return $lastResult
            }
            Write-Log -Level 'warn' -Message ('Portal rejected challenge for initial_ip={0}, client_ip={1}; retrying with a fresh challenge.' -f $lastResult.InitialIp, $lastResult.ClientIp)
            Start-Sleep -Seconds 1
        }

        return $lastResult
    } finally {
        $password = $null
    }
}

function Invoke-SrunLogout {
    $credential = Import-CampusCredential
    $username = $credential.UserName
    $portalStatus = Get-PortalStatus
    $clientIp = if ($portalStatus.Ip) { $portalStatus.Ip } else { Get-ClientIpForPortal }
    if ($portalStatus.Username) {
        $username = $portalStatus.Username
    }

    $logoutResponse = Invoke-PortalJsonp -Path '/cgi-bin/srun_portal' -Params ([ordered]@{
        action = 'logout'
        username = $username
        ip = $clientIp
        ac_id = [string]$script:AcId
    })

    $errorValue = [string](Get-ObjectProperty -Object $logoutResponse -Name 'error' -Default '')
    $errorMessage = [string](Get-ObjectProperty -Object $logoutResponse -Name 'error_msg' -Default '')
    $success = ($errorValue -eq 'ok') -or ($errorMessage -match 'not_online|not online|NotOnline')

    return [pscustomobject]@{
        Success = $success
        ClientIp = $clientIp
        Error = $errorValue
        ErrorMessage = $errorMessage
        Detail = if ($success) { 'Logout request accepted' } else { 'Logout request rejected' }
    }
}

function Invoke-CheckCycle {
    param([bool]$AllowLogin)

    $status = [ordered]@{
        CheckedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Computer = $env:COMPUTERNAME
        User = if ($env:USERNAME) { $env:USERNAME } elseif ($env:USER) { $env:USER } else { [Environment]::UserName }
        Internet = 'Unknown'
        InternetDetail = ''
        Portal = 'Unknown'
        PortalDetail = ''
        CampusUsername = ''
        ClientIp = ''
        UsedTraffic = ''
        RemoteProcesses = 'None'
        Action = 'None'
        LoginResult = ''
        Error = ''
        NextCheckSeconds = ''
    }

    try {
        $remoteProcesses = @(Get-RemoteProcessSnapshot)
        $status.RemoteProcesses = if ($remoteProcesses.Count -gt 0) { [string]::Join(', ', $remoteProcesses) } else { 'None' }
        $status.ClientIp = Get-ClientIpForPortal

        $internet = Test-InternetAccess
        $status.Internet = if ($internet.Online) { 'Online' } else { 'Offline' }
        $status.InternetDetail = $internet.Detail

        $portal = Get-PortalStatus
        $status.Portal = if ($portal.Online) { 'Online' } elseif ($portal.Reachable) { 'Offline' } else { 'Unreachable' }
        $status.PortalDetail = $portal.Detail
        $status.CampusUsername = $portal.Username
        if ($portal.Ip) {
            $status.ClientIp = $portal.Ip
        }
        $status.UsedTraffic = Format-ByteCount $portal.UsedBytes

        $loginWhenPortalOffline = [bool](Get-ConfigValue -Object $script:Config -Name 'LoginWhenPortalOffline' -Default $true)
        $repairWhenInternetOfflineAndPortalOnline = [bool](Get-ConfigValue -Object $script:Config -Name 'RepairWhenInternetOfflineAndPortalOnline' -Default $false)
        $loginReason = ''
        $logoutBeforeLogin = $false

        if ($Repair) {
            $loginReason = 'Manual repair requested'
            $logoutBeforeLogin = $portal.Online
        } elseif ($loginWhenPortalOffline -and $portal.Reachable -and -not $portal.Online) {
            $loginReason = 'Campus portal reports offline'
        } elseif (-not $internet.Online -and -not $portal.Online) {
            $loginReason = 'Internet checks failed and portal is not online'
        } elseif ($repairWhenInternetOfflineAndPortalOnline -and -not $internet.Online -and $portal.Online) {
            $loginReason = 'Portal is online but internet checks failed'
            $logoutBeforeLogin = $true
        }

        if ($loginReason) {
            if (-not $AllowLogin) {
                $status.Action = 'Login skipped'
                $status.LoginResult = 'StatusOnly or TestMode is enabled'
                Write-Log -Level 'info' -Message ("{0}; login skipped by mode." -f $loginReason)
            } else {
                $secondsSinceLogin = ([DateTime]::Now - $script:LastLoginAttempt).TotalSeconds
                if ($secondsSinceLogin -lt $script:MinSecondsBetweenLoginAttempts) {
                    $status.Action = 'Login delayed'
                    $status.LoginResult = ('Waiting {0:n0}s before another login attempt' -f ($script:MinSecondsBetweenLoginAttempts - $secondsSinceLogin))
                    Write-Log -Level 'warn' -Message $status.LoginResult
                } else {
                    $script:LastLoginAttempt = [DateTime]::Now
                    $status.Action = if ($logoutBeforeLogin) { 'Repair attempted' } else { 'Login attempted' }
                    Write-Log -Level 'warn' -Message ("{0}; attempting campus portal {1}." -f $loginReason, $(if ($logoutBeforeLogin) { 'repair' } else { 'login' }))

                    if ($logoutBeforeLogin) {
                        $logout = Invoke-SrunLogout
                        Write-Log -Level $(if ($logout.Success) { 'info' } else { 'warn' }) -Message ('Repair logout: {0}; error={1}; error_msg={2}' -f $logout.Detail, $logout.Error, $logout.ErrorMessage)
                        Start-Sleep -Seconds 2
                    }

                    $login = Invoke-SrunLogin
                    $status.LoginResult = ('{0}; initial_ip={1}; client_ip={2}; challenge_ip={3}; refreshed={4}; error={5}; error_msg={6}; suc_msg={7}; ploy_msg={8}' -f $login.Detail, $login.InitialIp, $login.ClientIp, $login.ChallengeIp, $login.ChallengeRefreshed, $login.Error, $login.ErrorMessage, $login.SuccessMessage, $login.PolicyMessage)
                    if ($login.ClientIp) {
                        $status.ClientIp = $login.ClientIp
                    }

                    if ($login.Success) {
                        Write-Log -Level 'info' -Message ('Campus portal login succeeded for {0}' -f (Import-CampusCredential).UserName)
                        Start-Sleep -Seconds 3
                        $internetAfter = Test-InternetAccess
                        $portalAfter = Get-PortalStatus
                        $status.Internet = if ($internetAfter.Online) { 'Online' } else { 'Offline' }
                        $status.InternetDetail = $internetAfter.Detail
                        $status.Portal = if ($portalAfter.Online) { 'Online' } elseif ($portalAfter.Reachable) { 'Offline' } else { 'Unreachable' }
                        $status.PortalDetail = $portalAfter.Detail
                        $status.CampusUsername = $portalAfter.Username
                        $status.UsedTraffic = Format-ByteCount $portalAfter.UsedBytes
                    } else {
                        Write-Log -Level 'error' -Message $status.LoginResult
                    }
                }
            }
        } elseif ($internet.Online) {
            $status.Action = 'No login needed'
            $status.LoginResult = 'Portal reports online and internet check succeeded'
            Write-Log -Level 'info' -Message 'Portal reports online and internet check succeeded.'
        } elseif ($portal.Online) {
            $status.Action = 'No login attempted'
            $status.LoginResult = 'Portal reports online, but internet check URLs failed'
            Write-Log -Level 'warn' -Message $status.LoginResult
        } else {
            $status.Action = 'No login attempted'
            $status.LoginResult = 'No matching condition'
        }
    } catch {
        $status.Error = $_.Exception.Message
        Write-Log -Level 'error' -Message $_.Exception.Message
    }

    Write-StatusFiles -Status $status
    return $status
}

$configExamplePath = Join-Path $PSScriptRoot 'config.example.json'
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    if (Test-Path -LiteralPath $configExamplePath) {
        Copy-Item -LiteralPath $configExamplePath -Destination $ConfigPath
        Write-Host "Created config.json from config.example.json. Run setup.ps1 to store your campus account."
    } else {
        throw "Config file not found: $ConfigPath"
    }
}

$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$script:ConfigBasePath = Split-Path -Parent $resolvedConfigPath
$script:Config = Get-Content -LiteralPath $resolvedConfigPath -Raw | ConvertFrom-Json

$script:PortalScheme = [string](Get-ConfigValue -Object $script:Config -Name 'PortalScheme' -Default 'http')
$script:PortalHost = [string](Get-ConfigValue -Object $script:Config -Name 'PortalHost' -Default '124.16.81.61')
$script:AcId = [string](Get-ConfigValue -Object $script:Config -Name 'AcId' -Default '1')
$script:RequestTimeoutSeconds = [int](Get-ConfigValue -Object $script:Config -Name 'RequestTimeoutSeconds' -Default 8)
$script:MinSecondsBetweenLoginAttempts = [int](Get-ConfigValue -Object $script:Config -Name 'MinSecondsBetweenLoginAttempts' -Default 60)
$script:LastLoginAttempt = [DateTime]::MinValue

$logDirectory = Resolve-ConfigPath -Path (Get-ConfigValue -Object $script:Config -Name 'LogDirectory' -Default '.\logs') -BasePath $script:ConfigBasePath
if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory | Out-Null
}
$script:LogFile = Join-Path $logDirectory ('auto-login-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))

$script:StatusFilePath = Resolve-ConfigPath -Path (Get-ConfigValue -Object $script:Config -Name 'StatusFile' -Default '.\status.json') -BasePath $script:ConfigBasePath
$script:StatusHtmlPath = Resolve-ConfigPath -Path (Get-ConfigValue -Object $script:Config -Name 'StatusHtml' -Default '.\status.html') -BasePath $script:ConfigBasePath

if ([bool](Get-ConfigValue -Object $script:Config -Name 'RunOnce' -Default $false)) {
    $Once = $true
}

$testMode = [bool](Get-ConfigValue -Object $script:Config -Name 'TestMode' -Default $false)
$allowLogin = (-not $StatusOnly) -and (-not $testMode)

Write-Log -Level 'info' -Message ('Starting campus auto-login. Portal={0}://{1}, ac_id={2}, once={3}, allowLogin={4}' -f $script:PortalScheme, $script:PortalHost, $script:AcId, [bool]$Once, $allowLogin)

if ([bool](Get-ConfigValue -Object $script:Config -Name 'OpenStatusOnStart' -Default $false) -and $script:StatusHtmlPath -and -not $NoStatusHtml) {
    $runningOnWindows = $env:OS -eq 'Windows_NT' -or $PSVersionTable.Platform -eq 'Win32NT'
    if ($runningOnWindows) {
        Start-Process -FilePath $script:StatusHtmlPath -ErrorAction SilentlyContinue
    } else {
        $xdgOpen = Get-Command xdg-open -ErrorAction SilentlyContinue
        if ($xdgOpen) {
            & xdg-open $script:StatusHtmlPath | Out-Null
        }
    }
}

do {
    $status = Invoke-CheckCycle -AllowLogin:$allowLogin

    if ($Once) {
        break
    }

    $remoteProcessText = [string]$status.RemoteProcesses
    $remoteCount = if ($remoteProcessText -and $remoteProcessText -ne 'None') { @($remoteProcessText.Split(',')).Count } else { 0 }
    $checkInterval = [int](Get-ConfigValue -Object $script:Config -Name 'CheckIntervalSeconds' -Default 30)
    $remoteInterval = [int](Get-ConfigValue -Object $script:Config -Name 'RemoteActiveCheckIntervalSeconds' -Default $checkInterval)
    $sleepSeconds = if ($remoteCount -gt 0 -and $remoteInterval -gt 0) { $remoteInterval } else { $checkInterval }
    if ($sleepSeconds -lt 3) {
        $sleepSeconds = 3
    }

    $status.NextCheckSeconds = $sleepSeconds
    Write-StatusFiles -Status $status
    Start-Sleep -Seconds $sleepSeconds
} while ($true)

if ($script:InstanceLockStream) {
    $script:InstanceLockStream.Dispose()
    $script:InstanceLockStream = $null
}
