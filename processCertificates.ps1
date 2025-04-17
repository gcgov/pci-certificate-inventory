net use \\c-drupal\certs /user:c-drupal\lsv-pcicertinventory /persistent:yes

#securely store the pfx password so this can be run as scheduled task
$inventoryDirectory = "\\file\PCICertificateInventory\Certificates\"
$pfxPasswordFilePath = "\\file\PCICertificateInventory\.pfx-pass-encrypted\$($env:computername)-$([Environment]::UserName).txt"

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
    }
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