$apiKeyVirusTotal="api_Key"
$apiKeyAbuse="api_Key"

Function Missatge-Informes{
    param(
        [String]$dolents,
        [String]$sospitos,
        [String]$ok,
        [String]$senseDeteccio,
        [String]$URL,
        [String] $tipus
    )
    Write-Host "------------------------------------"
    Write-Host "-     SCRIPT DESENVOLUPAT PER:     -"
    Write-Host "-     SCRIPT DESARROLLADO POR:     -"
    Write-Host "-        SCRIPT DEVLOPED BY:       -"
    Write-Host "------------------------------------"
    Write-Host "-            JORDI PARÉ            -"
    Write-Host "------------------------------------"
    Write-Host "VirusTotal report"
    Write-Host "$tipus categorized as malicious by $dolents antivirus"
    Write-Host "$tipus categorized as suspicious by $sospitos antivirus"
    Write-Host "$tipus categorized as good by $ok antivirus"
    Write-Host "$tipus not categorized by $senseDeteccio antivirus"
    Write-Host "Report URL: $URL"
}

Function Missatge-Abuse{
    param(
        [String] $pais,
        [String] $puntuacio,
        [String] $ultimReport,
        [String] $URL
    )
    Write-Host ""
    Write-Host "AbuseIP report"
    Write-Host "Country Name: " $pais
    Write-Host "Risk Score (0 is safe, 100 is very unsafe): "$puntuacio
    if($ultimReport){
        Write-Host "Last time report: "$ultimReport
    }
    else
    {
        Write-Host "Last time report: Any report"
    }
    
    Write-Host "Report URL: $URL"
}

Function Consulta-API{
    param(
        [String] $uri,
        [String] $url,
        [String] $tipus
    )
    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("x-apikey", "$apiKeyVirusTotal")
    $response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers

    $jsonObject = ConvertFrom-Json -InputObject $response
    $dolents = $jsonObject.data.attributes.last_analysis_stats.malicious
    $sospitosos = $jsonObject.data.attributes.last_analysis_stats.suspicious
    $senseDeteccio = $jsonObject.data.attributes.last_analysis_stats.undetected
    $ok = $jsonObject.data.attributes.last_analysis_stats.harmless

    if($tipus -eq "URL")
    {
        $idweb = $jsonObject.data.id
        $url = "https://www.virustotal.com/gui/url/$idweb"
        Missatge-Informes -dolents $dolents -sospitos $sospitosos -ok $ok -senseDeteccio $senseDeteccio -URL $url -tipus $tipus
    }
    else
    {
        Missatge-Informes -dolents $dolents -sospitos $sospitosos -ok $ok -senseDeteccio $senseDeteccio -URL $url -tipus $tipus
    }
}

Function Revisar-IP{
    param(
        [String] $ip
    )

    $uri = 'https://www.virustotal.com/api/v3/ip_addresses/'+$ip
    $url = "https://www.virustotal.com/gui/ip-address/$ip"
    $tipus = "IP"
    
    Consulta-API -uri $uri -url $url -tipus $tipus

    
    $headersAbuse = @{
        "Key" = "$apiKeyAbuse"
        "Accept" = "application/json"
    }

    $paramsAbuse = @{
        "ipAddress" = "$ip"
        "maxAgeInDays" = "90"
        "verbose" = "true"
    }

    $resposta = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method Get -Headers $headersAbuse -Body $paramsAbuse

    $abuseURL = "https://www.abuseipdb.com/check/$ip"

    Missatge-Abuse -pais $resposta.data.countryName -puntuacio $resposta.data.abuseConfidenceScore -ultimReport $resposta.data.lastReportedAt -URL $abuseURL
    
}


Function Revisar-Hash
{
    param(
        [String] $hash
    )
    $uri = 'https://www.virustotal.com/api/v3/files/'+$hash
    $url = "https://www.virustotal.com/gui/file/$hash"
    $tipus = "Hash"
    Consulta-API -uri $uri -url $url -tipus $tipus
}


Function Revisar-URL {
    param(
        [String] $URL 
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($URL)
    $base64 = [Convert]::ToBase64String($bytes)
    $urlSafeBase64 = $base64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $uri = 'https://www.virustotal.com/api/v3/urls/'+ $urlSafeBase64
    $url = "https://www.virustotal.com/gui/url/$idweb"
    $tipus = "URL"
    Consulta-API -uri $uri -url $url -tipus $tipus   
}

Function PedirRevisar-URL {
    param(
        [String] $URL 
    )
    $apiKey = "$apiKeyVirusTotal"
    $url = "$URL"
    $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method Post -Headers @{ "x-apikey" = $apiKey } -Body @{ "url" = $url } | ConvertTo-Json
    Write-Host "Petición enviada, espera al menos 30 segundos"
}

Function Revisar-Dominio {
    param(
        [String] $domini
    )
    $uri = "https://www.virustotal.com/api/v3/domains/"+$domini
    $tipus = "Domain"
    $url = "https://www.virustotal.com/gui/domain/$domini"
    Consulta-API -uri $uri -url $url -tipus $tipus
}


Function PedirRevisar-Dominio {
    param(
        [String] $URL 
    )

    $apiKey = "$apiKeyVirusTotal"
    $url = "$URL"
    $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$URL/analyse" -Method Post -Headers @{ "x-apikey" = $apiKey } -Body @{ "url" = $url } | ConvertTo-Json
    Write-Host "Petición enviada, espera al menos 30 segundos"
}


Function PedirRevisar-IP {
    param(
        [String] $IP 
    )

    $apiKey = "$apiKeyVirusTotal"
    $url = "$URL"
    $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP/analyse" -Method Post -Headers @{ "x-apikey" = $apiKey } -Body @{ "url" = $url } | ConvertTo-Json
    Write-Host "Petición enviada, espera al menos 30 segundos"
}


Function PedirRevisar-Hash {
    param(
        [String] $hash 
    )

    $apiKey = "$apiKeyVirusTotal"
    $url = "$URL"
    $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash/analyse" -Method Post -Headers @{ "x-apikey" = $apiKey } -Body @{ "url" = $url } | ConvertTo-Json
    Write-Host "Petición enviada, espera al menos 30 segundos"
}
