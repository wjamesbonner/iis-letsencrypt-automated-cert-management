# Automated SSL Certificate Management via Let's Encrypt
This is a sample set of powershell scripts for automating the creation of websites in IIS, the renewal of SSL certificates, and the streamlining and standardization of management activities such as adding bindings with certificates.  Certain assumptions are made about site and directory naming consistency and file locations.  Generally, sites that are created with the provided creation script will be able to be automatically managed via the certificate renewal script which can be run daily via a scheduled task.
