Import-Module ACMESharp
Import-Module WebAdministration

### User inputs ###

# Prompt for the name of the website
$siteName = Read-Host 'Enter website name'
$siteName = $siteName.Trim()

# Prompt for the domain
$domain = Read-Host 'Enter domain'
$domain = $domain.Trim()

# Create the site physical path
$sitePath = "E:\htmldocs\" + $siteName

### Begin request and issuance of certificate ###

# Name of the certificate store we are working in (My = Personal, WebHosting = Web Hosting)
$certStoreName = "WebHosting"

# Path to the specified certificate store
$certStorePath = "Cert:\LocalMachine\" + $certStoreName

# Directory to save our certificates to, import from, and then delete
$workingDirectory = "C:\Temp\Certificates"

# Create an alias for LE for this domain
$dnsAlias = $domain + '.Dns.' + (Get-Date).ToFileTime().ToString()

# Create an alias for LE for this certificate
$certAlias = $domain + '.Cert.' + (Get-Date).ToFileTime().ToString()

# Create the name of our certificate once generated
$certName = $siteName + ".pfx"

# Create the export path to our certificate
$certPath = $workingDirectory + "\" + $certName

# Create our working directory if it doesn't already exist
if(!(Test-Path $workingDirectory -PathType Container)) { 
    New-Item -ItemType directory -Path $workingDirectory
}

# Initialize the ACME Vault if it doesn't exist and register
if (!(Get-ACMEVault))
{
    Initialize-ACMEVault
    New-ACMERegistration -Contacts mailto:cit.support@wsu.edu -AcceptTos
}

# Number of attempts to validate the domain
$validationAttempts = 0
$skip = $false
$movedApplication = $false

# Check the status of our challenge every 10 seconds until complete or exhausted attempts
do {
    if ($validationAttempts -gt 1) {
        Write-Host "Failed to validate domain: " $domain
        $skip = $true
        break
    }

    # Change $dnsAlias with every iteration so the alias is unique when creating the ACME identifier
    $dnsAlias = $dnsAlias + $validationAttempts

    try {
        # Create an ACME identifier associated with this domain
        New-ACMEIdentifier -Dns $domain -Alias $dnsAlias
    } catch {
        Get-ACMEIdentifier -IdentifierRef $dnsAlias
        Write-Host "Failed to create identifier, does one already exist (see above output of Get-ACMEIdentifier)."
        return
    }

    # If wwwroot exists within the site path, move site contents to temp folder, complete cert, and move them back
    try {
        if(Test-Path ($sitePath + "\wwwroot")) {
                
            Stop-Website -Name $siteName
            Stop-WebAppPool -Name $siteName
            Start-Sleep -Seconds 2

            $movedApplication = $true
            New-Item -Path $sitePath -Name "TempApplicationContainer" -ItemType "directory"

            Get-ChildItem -Path $sitePath -exclude "TempApplicationContainer" | ForEach-Object {
                $permissions = Get-Acl $_.FullName
                Move-Item $_.FullName ($sitePath + "\TempApplicationContainer")
                Set-Acl ($sitePath + "\TempApplicationContainer\" + $_.Name) $permissions
            }

            Start-WebAppPool -Name $siteName
            Start-Website -Name $siteName
            Start-Sleep -Seconds 2
        }
    } catch {

    }

    # Request a domain ownership challenge, in our case based on http (not dns).  This will create a directory in your website to be checked by LE
    Complete-ACMEChallenge $dnsAlias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = $siteName } -Force
        
    try {
        # Overwrite or create web.config to allow anonymous access to the acme-challege directory
        '<?xml version="1.0" encoding="UTF-8"?><configuration><system.web><authorization><allow users="?" /></authorization></system.web></configuration>' | Out-File -FilePath ($sitePath + "\.well-known\acme-challenge\web.config") -encoding "utf8"
    } catch {

    }
    
    # Tell LE to verify ownership
    Submit-ACMEChallenge $dnsAlias -ChallengeType http-01 -Force

    $validationAttempts = $validationAttempts + 1
    Start-Sleep -Seconds 10

    try {
        # Remove web.config so challenge files are accessible
        Remove-Item ($sitePath + "\.well-known\acme-challenge\web.config")
    } catch {

    }
} while (((Update-ACMEIdentifier $dnsAlias -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status -ne "valid")

# Put application back into root app folder if it was moved
try {
    # If wwwroot exists within the site path, move site contents to temp folder, complete cert, and move them back
    if($movedApplication) {
        Stop-Website -Name $siteName
        Stop-WebAppPool -Name $siteName
        Start-Sleep -Seconds 2

        Get-ChildItem -Path ($sitePath + "\TempApplicationContainer") | ForEach-Object {
            $permissions = Get-Acl $_.FullName
            Move-Item $_.FullName ($sitePath)
            Set-Acl ($sitePath + "\" + $_.Name) $permissions
        }

        Remove-Item ($sitePath + "\TempApplicationContainer") -Recurse

        Start-WebAppPool -Name $siteName
        Start-Website -Name $siteName
        Start-Sleep -Seconds 2
    }
} catch {

}

# Cleanup ACME check folder
try {
    Remove-Item ($sitePath + "\.well-known") -Recurse
} catch {

}

# Retrieve the overall status of the domain
$status = Update-ACMEIdentifier $dnsAlias

# If the domain status is not valid, take some action
if($status.Status -ne "valid") {
    Write-Host "Domain status is not valid."
    exit
}

# Generate a certificate request
New-ACMECertificate $dnsAlias -Generate -Alias $certAlias

# Submit our certificate request to LE
Submit-ACMECertificate $certAlias

# Ensures that intermediate certificates are installed
Update-ACMECertificate $certAlias

# Retrieves our issued certificate and saves it in PKCS#12 (PFX) format
Get-ACMECertificate $certAlias -ExportPkcs12 $certPath

# Save the Thumbprint from our new certificate
$newThumbprint = (Get-PfxCertificate -FilePath $certPath).Thumbprint

# Import our new certificate into our cert store
Import-PfxCertificate -FilePath $certPath -Exportable -CertStoreLocation $certStorePath

# Retrieve the site binding using the old certificate
$binding = Get-WebBinding -Protocol "https" -Name $siteName -HostHeader $domain

# Add the new certificate to the site binding
$binding.AddSslCertificate($newThumbprint, $certStoreName)

# Delete our PFX file from the working directory
Remove-Item -Path $certPath