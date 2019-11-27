Install-Module -Name ACMESharp -AllowClobber
Install-Module -Name ACMESharp.Providers.IIS

Import-Module ACMESharp
Enable-ACMEExtensionModule -ModuleName ACMESharp.Providers.IIS

Get-ACMEExtensionModule | Select-Object -Expand Name