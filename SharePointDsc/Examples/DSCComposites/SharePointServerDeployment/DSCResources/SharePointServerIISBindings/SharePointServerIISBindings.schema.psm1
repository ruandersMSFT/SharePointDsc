Configuration SharePointServerIISBindings
{
    param
    (
        [Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$Node
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $CustomSharePointFoundation = 0    
    if ($Node.ServerRole -eq 'Custom')
    {
        $CustomSharePointFoundation = ($Node.CustomServiceInstances | 
            ? { $_.Name -eq 'Microsoft SharePoint Foundation Web Application' -and $_.Ensure -eq 'Present' } | 
            Measure-Object | 
            Select-Object Count).Count
	}

    if(
        ($Node.NodeName -ne '*') -and 
        (
            $Node.ServerRole -eq 'Application' -or 
            $Node.ServerRole -eq 'WebFrontEnd' -or 
            $CustomSharePointFoundation -eq 1
        )
    )
    {
        # Central Administration IIS Bindings (update site with SSL Certificate and IP Address Details)
        if ($Node.CentralAdministration -ne $null -and $Node.CentralAdministration.RunCentralAdmin -eq $true) 
        {
            $CentralAdminName = 'SharePoint Central Administration v4' # todo, variation for SP2013/2016
            $CentralAdminState = 'Started'
            $CentralAdminCertificateStoreName = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.CertificateStoreName
            $CentralAdminCertificateThumbprint = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.CertificateThumbprint
            $CentralAdminIPAddress = '*'
            $CentralAdminPort = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Port
            $CentralAdminProtocol = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Protocol

            if ($Node.CentralAdministration.IPAddress -ne $null)
            {
                $CentralAdminIPAddress = $Node.CentralAdministration.IPAddress
			}

            $CentralAdminCert = $ConfigurationData.NonNodeData.SharePoint.Certificates.Pfx | ? { $_.Thumbprint -eq $CentralAdminCertificateThumbprint -and $_.Ensure -eq 'Present' -and $_.Location -eq 'LocalMachine' -and $_.Store -eq $CentralAdminCertificateStoreName }
            if ($CentralAdminCert -eq $null)
            {
                throw [Exception] "Certificate with thumbprint '$($CentralAdminCertificateThumbprint)' must be defined in the Configuration Data PFX Certificates with Ensure = 'Present', Location = 'LocalMachine' and Store = '$($CentralAdminCertificateStoreName)' to utilize as the Central Administration SSL Certificate on Node '$($Node.NodeName)'."
			}

            xWebsite CentralAdmin {
                Name = $CentralAdminName
                State = $CentralAdminState
                BindingInfo = MSFT_xWebBindingInformation {
                    CertificateStoreName = $CentralAdminCertificateStoreName
                    CertificateThumbprint = $CentralAdminCertificateThumbprint
                    IPAddress = $CentralAdminIPAddress
                    Port = $CentralAdminPort
                    Protocol = $CentralAdminProtocol
                }
                Ensure = 'Present'
            }
        }

        # Web Application IIS Sites
        foreach($WebApplication in $ConfigurationData.NonNodeData.SharePoint.Farm.WebApplications)
        {
            $WebApplicationInternalName = $WebApplication.Name.Replace(' ', '')
            $WebApplicationCertificateStoreName = $WebApplication.Binding.Store
            $WebApplicationCertificateThumbprint = $WebApplication.Binding.Thumbprint
            $WebApplicationIPAddress = '*'
            $WebApplicationPort = $WebApplication.Binding.Port
            $WebApplicationProtocol = $WebApplication.Binding.Protocol
            $WebApplicationState = 'Started'

            # Get the IP for the binding
            $WebApplicationBinding = $Node.InternetInformationServer.Bindings | ? { $_.Name -eq $WebApplication.Name }
            if ($WebApplicationBinding -ne $null)
            {
                if ($WebApplicationBinding.IPAddress -ne $null)
                {
                    $WebApplicationIPAddress = $WebApplicationBinding.IPAddress
				}
			}

            $WebAppCert = $ConfigurationData.NonNodeData.SharePoint.Certificates.Pfx | ? { $_.Thumbprint -eq $WebApplicationCertificateThumbprint -and $_.Ensure -eq 'Present' -and $_.Location -eq 'LocalMachine' -and $_.Store -eq $WebApplication.Binding.Store }
            if ($WebAppCert -eq $null)
            {
                throw [Exception] "Certificate with thumbprint '$($WebApplicationCertificateThumbprint)' must be defined in the Configuration Data PFX Certificates with Ensure = 'Present', Location = 'LocalMachine' and Store = '$($WebApplication.Binding.Store)' to utilize as the SSL Certificate for Web Application '$($WebApplication.Name)' on Node '$($Node.NodeName)'."
			}

            #Set the binding for the web app
            if ($WebApplication.UseHostNamedSiteCollections) 
            { 
                xWebsite ($WebApplicationInternalName + "_IISBinding")
                {
                    Name = $WebApplication.Name
                    State = $WebApplicationState
                    BindingInfo = MSFT_xWebBindingInformation {
                        CertificateStoreName = $WebApplicationCertificateStoreName
                        CertificateThumbprint = $WebApplicationCertificateThumbprint
                        # HostName = $null  cannot pass as null/empty
                        IPAddress = $WebApplicationIPAddress
                        Port = $WebApplicationPort
                        Protocol = $WebApplicationProtocol
                    }
                    Ensure = 'Present'
                }
            }
            else
            {
                xWebsite ($Node.NodeName + $WebApplicationInternalName + "_IISBinding")
                {
                    Name = $WebApplication.Name
                    State = $WebApplicationState
                    BindingInfo = MSFT_xWebBindingInformation {
                        CertificateStoreName = $WebApplicationCertificateStoreName
                        CertificateThumbprint = $WebApplicationCertificateThumbprint
                        IPAddress = $WebApplicationIPAddress
                        HostName = [Uri]::new($WebApplication.Url).Host
                        Port = $WebApplicationPort
                        Protocol = $WebApplicationProtocol
                    }
                    Ensure = 'Present'
                }
            }
        }
    }
} 
