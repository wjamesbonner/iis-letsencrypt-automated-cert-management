Import-Module ACMESharp
Import-Module WebAdministration

# Name of the certificate store we are installing to (My = Personal, WebHosting = Web Hosting)
$certStoreName = "WebHosting"

# Path to the certificate store
$certStorePath = "Cert:\LocalMachine\" + $certStoreName

# Directory to save our certificates to, import from, and then delete
$workingDirectory = "C:\Temp\Certificates"

# Proximity to expiration for replacement
$daysUntilExpiration = 32

# Computed expiration date
$expirationDate = (Get-Date).AddDays($daysUntilExpiration)

# Create our working directory if it doesn't already exist
if(!(Test-Path $workingDirectory -PathType Container)) { 
    New-Item -ItemType directory -Path $workingDirectory
}

# Create a collection of IIS websites
$sites = Get-Website | ? { $_.State -eq "Started" }

# Create a collection of just names from our IIS sites
$names = $sites | % { $_.Name }

# Create a collection of Thumbprints for certs associated with ssl bindings
$certs = Get-ChildItem IIS:SSLBindings | ? { $names -contains $_.Sites.Value } | % { $_.Thumbprint }

# Retrieve the certificates expiring within our specified threshold and used by our sites
$certs = Get-ChildItem $certStorePath | ? { $certs -contains $_.Thumbprint -and $_.NotAfter -lt $expirationDate }

# Loop over each certificate
$certs | ForEach-Object {
	$cert = $_


    ##### Build name, path, and misc variables #####

    # Track the current/old Thumbprint
    $oldThumbprint = $cert.Thumbprint

    # Split out the domain of our certificate subject
    $domain = $cert.Subject.Split('=')[1].Split(',')[0]

    # Retrieve the name of the site  from the SSL binding
    $siteName = Get-ChildItem IIS:SSLBindings | ? { $domain -eq $_.Host } | % { $_.Sites.Value }

    # Create the site physical path
    $sitePath = "E:\htmldocs\" + $siteName

    # Create an alias for LE for this domain
	$dnsAlias = $domain + '.Dns.' + (Get-Date).ToFileTime().ToString()

    # Create an alias for LE for this certificate
    $certAlias = $domain + '.Cert.' + (Get-Date).ToFileTime().ToString()

    # Create the name of our certificate once generated
    $certName = $siteName + ".pfx"

    # Create the export path to our certificate
    $certPath = $workingDirectory + "\" + $certName



    ##### Check if the domain on the cert resolves to an IP address on this server #####

    # Variable determining if there is an IP match
    $ipMatch = $false

    # Collection of IP's resolved by the domain name
    $dnsIps = @()

    # Populate our collection of IP addresses from the domain name on the cert
    try {
        [System.Net.Dns]::GetHostAddresses($domain) | foreach-object {
            if($_.IPAddressToString.Trim() -ne "") {
                $dnsIps = $dnsIps + $_.IPAddressToString
            }
        } 
    } catch {
        # Error condition
        # Most likely error is the DNS record no longer exists or resolves.
        return
    }

    # Collection of IP's across all local interfaces
    $hostIps = @()

    # Populate our collection of system IP's
    Get-NetIPAddress | % { $_.IpAddress } | foreach-object {
        if($_.Trim() -ne "") {
            $hostIps = $hostIps + $_
        }
    }

    # If hostIps contains any element of dnsIps set ipMatch to true
    $dnsIps | ? {$hostIps -contains $_ } | % { $ipMatch = $true }

    # If IP match is false, continue to next iteration
    if (!$ipMatch) {
        # Error condition
        Write-Host "System/DNS IP mismatch - impossible to complete domain validation for: " $domain
        return
    }
    
    ##### Check to make sure that the domain resolves to an IP address on the sites http web binding #####

    # Reset our IP match variable to false
    $ipMatch = $false

    # Get the bindings that match the site name, are http, match the domain on the cert, and then loop over the binding information field
    Get-WebBinding -Name $siteName -Protocol "http" | ? {$_.BindingInformation.Split(":")[2] -eq $domain} | % {$_.BindingInformation} | foreach-object {
        $ipAddress = $_.Split(':')[0]
        
        # If the ip address is a wildcard binding, then we are done
        if($ipAddress  -eq '*') {
            $ipMatch = $true
            return
        }

        # If the IP address is contained by the DNS IP records then we have a match
        $ipAddress | ? {$dnsIps -contains $_} | % { $ipMatch = $true }
    }

    if (!$ipMatch) {
        # Error condition
        Write-Host "Binding/Dns IP mismatch - impossible to complete domain validation for: " $domain
        return
    }



    ##### Begin generation and installation of new certificate #####
    
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
    $enabledAnonAccess = $false

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

        # If anon access is disabled, enable it
        try {
            $anonPerms = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -PSPath IIS:\ -Location $siteName
            if($anonPerms.Value -eq $false) {
                Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -Value $true -PSPath IIS:\ -Location $siteName
                $enabledAnonAccess = $true
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

    # If we changed anon access, put it back
    try {
        if($enabledAnonAccess -eq $true) {
            Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -Value $false -PSPath IIS:\ -Location $siteName
        }
    } catch {

    }

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

    # If we failed to validate we continue to the next iteration
    if ($skip) {
        return
    }

    # Retrieve the overall status of the domain
    $status = Update-ACMEIdentifier $dnsAlias

    # If the domain status is not valid, take some action
    if($status.Status -ne "valid") {
        #error condition
        Write-Host "Domain status is not valid: " $domain
        return
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

    # Set the friendly name to the certificates domain
    (Get-ChildItem -Path ($certStorePath + '\' + $newThumbprint)).FriendlyName = $domain
    
    # Retrieve the site binding using the old certificate
    $binding = Get-WebBinding -Protocol "https" -Name $siteName -HostHeader $domain

    # Add the new certificate to the site binding
    $binding.AddSslCertificate($newThumbprint, $certStoreName)

    # Delete the old certificate
    Get-ChildItem -Path ($certStorePath + "\" + $oldThumbprint)  | Remove-Item

    # Delete our PFX file from the working directory
    Remove-Item -Path $certPath
}