Invoke-WebRequest https://apps.garrettcountymd.gov/cron-monitor/jobHistory/start/68015c988ebd7db54d09ed20

#securely store the pfx password so this can be run as scheduled task
$inventoryDirectory = "\\file\PCICertificateInventory\Certificates\"
$pfxPasswordFilePath = "\\file\PCICertificateInventory\.pfx-pass-encrypted\$($env:computername)-$([Environment]::UserName).txt"
$cDrupalPasswordFilePath = "\\file\PCICertificateInventory\.pfx-pass-encrypted\$($env:computername)-$([Environment]::UserName)-c-drupal.txt"

$paBaseUrl = "https://pa-spare.garrettcounty.org/api/"
#PA Credentials
#how to generate encrypted credential files
#$Encrypted = ConvertTo-SecureString 'newpassword' -AsPlainText -Force
#$Encrypted  | ConvertFrom-SecureString | Out-File "pa-pw.txt"
$paEncryptedUsername = Get-Content "pa-un.txt" | ConvertTo-SecureString
$paUsername = ConvertFrom-SecureString -SecureString $paEncryptedUsername -AsPlainText

$paEncryptedPass = Get-Content "pa-pw.txt" | ConvertTo-SecureString
$paPass = ConvertFrom-SecureString -SecureString $paEncryptedPass -AsPlainText

$paBytes = [System.Text.Encoding]::ASCII.GetBytes($paUsername+':'+$paPass)
$paBase64 = [System.Convert]::ToBase64String($paBytes)
$paBasicAuthValue = "Basic $paBase64"
$paAuthHeader = 'Authorization: {0}' -f $paBasicAuthValue

function SaveCertToPaloAlto {
    param (
        [string]$baseUrl,
        [string]$authHeader
        [string]$pfxPassword,
        [System.IO.FileInfo]$certFile
    )
    
    $url = $baseUrl+"?type=import&category=keypair&passphrase="+$pfxPassword+"&format=pkcs12&certificate-name="+$certFile.BaseName
    $form = 'file=@"{0}"' -f $certFile.FullName

    Write-Host "--upload cert $($certFile.FullName)"
    
    #upload cert
    curl --location $url --header $authHeader --form $form
}

function CommitPaloAltoChanges {
    param (
        [string]$baseUrl,
        [string]$authHeader
    )
    Write-Host "commit changes"
        
    #commit
    curl --location $baseUrl+"?type=commit&action=partial&cmd=%3Ccommit%3E%3C%2Fcommit%3E" --header $authHeader 
}

if(-not(Test-Path $cDrupalPasswordFilePath)) {
    Write-Host "Please enter the password for c-drupal\lsv-pcicertinventory:"
    $cdrupalPassword = Read-Host -AsSecureString

    # Convert the secure string to an encrypted standard string
    $encryptedCDrupalPassword = ConvertFrom-SecureString $cdrupalPassword

    # Write the encrypted password to the file
    Set-Content -Path $cDrupalPasswordFilePath -Value $encryptedCDrupalPassword

    Write-Host "c-drupal\lsv-pcicertinventory password has been securely stored in $cDrupalPasswordFilePath."
}
$encryptedCDrupalPasswordString = Get-Content -Path $cDrupalPasswordFilePath
$secureCDrupalPassword = ConvertTo-SecureString -String $encryptedCDrupalPasswordString

$cDrupalCredential = New-Object System.Management.Automation.PsCredential("c-drupal\lsv-pcicertinventory", $secureCDrupalPassword)
New-PSDrive -Name "cdrupalcerts" -PSProvider "FileSystem" -Root "\\c-drupal\certs" -Credential $cDrupalCredential

if(-not(Test-Path $pfxPasswordFilePath)) {
    Write-Host "Please enter the PFX password:"
    $password = Read-Host -AsSecureString

    # Convert the secure string to an encrypted standard string
    $encryptedPassword = ConvertFrom-SecureString $password

    # Write the encrypted password to the file
    Set-Content -Path $pfxPasswordFilePath -Value $encryptedPassword

    Write-Host "PFX password has been securely stored in $pfxPasswordFilePath."
}

$encryptedPfxPasswordString = Get-Content -Path $pfxPasswordFilePath
$securePfxPassword = ConvertTo-SecureString -String $encryptedPfxPasswordString
$unsecurePfxPassword = [System.Net.NetworkCredential]::new("", $securePfxPassword).Password

#get certificates from web servers
$certsUpdatedOnPa = 0
$serverNames = @('c-web', 'c-drupal', 'c-web2')
foreach($serverName in $serverNames) {
    #create server name text file
    $severPfxFiles = Get-ChildItem -Path "\\$($serverName)\certs" -Filter "*.pfx"
    foreach($severPfxFile in $severPfxFiles) {
        Write-Host "Create server tag $($serverName) as $($severPfxFile.FullName)-server.txt"
        Set-Content -Path "$($severPfxFile.FullName)-server.txt" -Value $serverName
    }

    #copy certs to file
    $certFiles = Get-ChildItem -Path "\\$($serverName)\certs"
    foreach($certFile in $certFiles) {
        Write-Host "Move $($certFile.FullName) to inventory $($inventoryDirectory)"
        Move-Item -Path "$($certFile.FullName)" -Destination "$($inventoryDirectory)" -Force

        #save to pa
        SaveCertToPaloAlto -baseUrl $paBaseUrl -authHeader $paAuthHeader -pfxPassword $unsecurePfxPassword -certFile $certFile
        $certsUpdatedOnPa++
    }
}

if( $certsUpdatedOnPa -gt 0) {
    CommitPaloAltoChanges -baseUrl $paBaseUrl -authHeader $paAuthHeader
}

#create inventory from certificates
$pfxFiles = Get-ChildItem -Path "$($inventoryDirectory)" -Filter "*.pfx"
foreach($pfxFile in $pfxFiles) {
    $certDetail = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $pfxFile.FullName, $unsecurePfxPassword
    
    $server = ""
    if(Test-Path -Path "$($pfxFile.FullName)-server.txt") {
        $server = Get-Content -Path "$($pfxFile.FullName)-server.txt"
    }

    Write-Host "Inventory certificate $($pfxFile.Name) to SQL"
    $cert =  @{
        "File" = $pfxFile.Name
        "CertFriendlyName" = $certDetail.FriendlyName
        "Issuer" = $certDetail.IssuerName.Name.Replace("'", "''")
        "Expiration" = $certDetail.NotAfter
        "SignatureAlgorithm" = $certDetail.SignatureAlgorithm.FriendlyName
        "PrivateKeyExchangeAlgorithm" = $certDetail.PrivateKey.KeyExchangeAlgorithm
        "PrivateKeySignatureAlgorithm" = $certDetail.PrivateKey.SignatureAlgorithm
        "PrivateKeySize" = $certDetail.PrivateKey.KeySize
        "PublicKeyExchangeAlgorithm" = $certDetail.PublicKey.Key.KeyExchangeAlgorithm
        "PublicKeySignatureAlgorithm" = $certDetail.PublicKey.Key.SignatureAlgorithm
        "PublicKeySize" = $certDetail.PublicKey.Key.KeySize
        "CertDNSNames" = $certDetail.DnsNameList -join ", "
        "Server" = $server
    }

    Invoke-Sqlcmd -ServerInstance "c-sql-2019" -Database "PCICertificateInventory" -Encrypt "Optional" -Query "DELETE FROM certificates WHERE [File]='`$(File)';" -Variable $cert
    Invoke-Sqlcmd -ServerInstance "c-sql-2019" -Database "PCICertificateInventory" -Encrypt "Optional" -Query "INSERT INTO certificates ([File], [CertFriendlyName], [Expiration], [SignatureAlgorithm],[PrivateKeyExchangeAlgorithm],[PrivateKeySignatureAlgorithm],[PrivateKeySize],[PublicKeyExchangeAlgorithm],[PublicKeySignatureAlgorithm],[PublicKeySize],[CertDNSNames],[Server],[Issuer] ) VALUES ( '`$(File)', '`$(CertFriendlyName)','`$(Expiration)' ,'`$(SignatureAlgorithm)' ,'`$(PrivateKeyExchangeAlgorithm)' ,'`$(PrivateKeySignatureAlgorithm)' ,'`$(PrivateKeySize)' ,'`$(PublicKeyExchangeAlgorithm)' ,'`$(PublicKeySignatureAlgorithm)' ,'`$(PublicKeySize)' ,'`$(CertDNSNames)' ,'`$(Server)','`$(Issuer)');" -Variable $cert

}

Write-Host "Export full SQL inventory to CSV: \\file\PCICertificateInventory\inventory.csv"
Invoke-Sqlcmd -ServerInstance "c-sql-2019" -Database "PCICertificateInventory" -Encrypt "Optional" -Query "select * from certificates;" -Variable $cert | Export-Csv -Path "\\file\PCICertificateInventory\inventory.csv"


Invoke-WebRequest https://apps.garrettcountymd.gov/cron-monitor/jobHistory/end/68015c988ebd7db54d09ed20