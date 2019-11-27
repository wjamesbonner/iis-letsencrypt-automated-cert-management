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

### Create website, directory, app pool ###

# Create the physical path if it does not exist
if(!(Test-Path $sitePath -PathType Container)) { 
    New-Item -ItemType directory -Path $sitePath
}

# Create the app pool if it doesn't already exist
if (!(Test-Path IIS:\AppPools\$siteName -pathType container))
{
    $iisAppPoolDotNetVersion = "v4.0"
    $appPool = New-Item IIS:\AppPools\$siteName
    $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
}

# Create the website
if (!(Test-Path IIS:\Sites\$siteName -pathType container))
{
    # Create our website
    New-WebSite -Name $siteName -Port 80 -HostHeader $domain -PhysicalPath $sitePath -ApplicationPool $siteName
    
    # Create a https binding
    New-WebBinding -Name $siteName -IPAddress "*" -Port 443 -HostHeader $domain -Protocol "https" -SslFlags 1
}

# Set permissions on the site directory
if (Test-Path $sitePath -PathType Container) {

    # Retrieve the SID for the app pool identity
    $appPoolSid = (Get-ItemProperty IIS:\AppPools\$siteName).applicationPoolSid

    # Retrieve the security identifier for the SID
    $identifier = New-Object System.Security.Principal.SecurityIdentifier $appPoolSid

    # Translate the security identifier to a NT account
    $user = $identifier.Translate([System.Security.Principal.NTAccount])

    # Get the current ACL set on the site directory
    $acl = Get-Acl $sitePath

    # Create a read and execute access rule
    $ar = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")

    # Set the access rule on the ACL
    $acl.SetAccessRule($ar)

    # Set the updated ACL back onto the site directory
    Set-Acl $sitePath $acl
}

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

try {
    # Create an ACME identifier associated with this domain
    New-ACMEIdentifier -Dns $domain -Alias $dnsAlias
} catch {
    Get-ACMEIdentifier -IdentifierRef $dnsAlias
    Write-Host "Failed to create identifier, does one already exist (see above output of Get-ACMEIdentifier)."
    exit
}

# Request a domain ownership challenge, in our case based on http (not dns).  This will create a directory in your website to be checked by LE
Complete-ACMEChallenge $dnsAlias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = $siteName } -Force

# Remove web.config so challenge files are accessible
Remove-Item ($sitePath + "\.well-known\acme-challenge\web.config")

# Tell LE to verify ownership
Submit-ACMEChallenge $dnsAlias -ChallengeType http-01 -Force

# Check the status of our challenge every 10 seconds until complete
do {
    Start-Sleep -Seconds 10
} while (((Update-ACMEIdentifier $dnsAlias -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status -ne "valid")

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