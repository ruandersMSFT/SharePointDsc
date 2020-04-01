# Issue 1)  KHLM\Software\Microsoft\Shared Tools\Web Server Extensions\12.0\WSS   CentralAdministrationURL

#************************************************************************************
# Title: SharePointServerDeployment
#
# Description: This configuration file is called by the 05_Build-InstallSharePoint.ps1 
#    script. This file should not be modified. Use the 05_Data-InstallSharePoint2019.psd1
#    file to modify the configuration. This configuration is to install and complete
#    initial configuration. The 05_Config-SharePoint2019.ps1 file should be used to 
#    configure additional web applications and site collections. The initial configuration 
#    accomplishes the following
#    steps:
#
#        1) Sets the Credential Security Support Provider for the server and client
#        2) Installs the IIS certificate into the certificate store
#        3) Copies the SharePoint Server install files from the pull server and unpacks
#           them.s
#        4) Add accounts to the local admin group and performance monitor group
#        5) Adds the registry entry to disable the IIS Loopback Check
#        6) Adds the registry entries to disable SSL 2.0 and 3.0
#        7) Disables IE Enhanced Security (for Admins)
#        8) Installs the IIS and IIS Management Tools features
#        9) Set the default IIS log settings
#        10) Remove default site and application pools from IIS
#        11) Sets the Windows Firewall settings for SharePoint
#        12) Set the SQL alias for the SharePoint farm
#        13) Setup Custom IIS HttpResponse Header
#        14) Installs the SharePoint prerequisites
#        15) Installs the SharePoint application
#        16) Install the latest SharePoint CU
#        17) Creates the SharePoint farm on the first application server
#        18) Add remaining servers into the farm
#        19) Performs basic farm configuration on the first application server
#        20) Configures services for custom nodes
#        21) Configures services on the first application server
#        22) Add the WOPI binding to Office Online Server
#        23) Configures and implements search and search topology
#        24) Runs the configuration wizard to ensure farm is completely updated
#
# Required Files:
#
#    05_Build-InstallSharePoint2019.ps1 - The script that will apply this configuration
#        to build the SharePoint Server farm.
#
#    05_Data-InstallSharePoint2019.psd1 - The DSC configuration data for the SharePoint
#        Server farm.
#
# Written By: Shaun Crist
# Created: 20180515
#
# Last Updated By:
# Last Update: 
# 
#************************************************************************************

Configuration SharePointServerDeployment
{
    param
    (
    )

    LocalConfigurationManager
    {
        ActionAfterReboot = 'ContinueConfiguration'
        RebootNodeIfNeeded = $true
		AllowModuleOverwrite = $True
        ConfigurationMode = 'ApplyAndAutoCorrect'
        RefreshMode = 'Push'
    }
	
	Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SQLServerDsc -ModuleVersion 13.4.0
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName xWebAdministration -ModuleVersion 3.1.1
    Import-DscResource -ModuleName CertificateDsc -ModuleVersion 4.7.0.0
    Import-DscResource -ModuleName SecurityPolicyDSC -ModuleVersion 2.10.0.0
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 8.0.0
    Import-DscResource -ModuleName xCredSSP -ModuleVersion 1.3.0.0
    Import-DscResource -ModuleName SharePointServerDeployment

    # SharePointVersion validation
    switch ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion)
    {
        '2013' { break }
        '2016' { break }
        '2019' { break }
        default { throw [Exception] "SharePointVersion must be 2013, 2016 or 2019." }
	}

    $objSetupAccountPw = $ConfigurationData.NonNodeData.SharePoint.Farm.ServiceAccounts.Setup.Password | ConvertTo-SecureString -AsPlainText -Force
    $SPSetupCredential = New-Object System.Management.Automation.PSCredential($ConfigurationData.NonNodeData.SharePoint.Farm.ServiceAccounts.Setup.Account, $objSetupAccountPw)

    $objFarmAccountPw = $ConfigurationData.NonNodeData.SharePoint.Farm.ServiceAccounts.Farm.Password | ConvertTo-SecureString -AsPlainText -Force
    $SPFarmCredential = New-Object System.Management.Automation.PSCredential($ConfigurationData.NonNodeData.SharePoint.Farm.ServiceAccounts.Farm.Account, $objFarmAccountPw)

    Node $AllNodes.NodeName
    {

        # Ensure Pfx Certificate(s) into Server Crtificate Store
        foreach($PfxCertificate in $ConfigurationData.NonNodeData.SharePoint.Certificates.Pfx)
        {

            #temp, code restructure, establish better way than plain text
            $objCertPw = $PfxCertificate.Password | ConvertTo-SecureString -AsPlainText -Force
            $objCertCredential = New-Object System.Management.Automation.PSCredential('Dummy', $objCertPw)

			# https://github.com/PowerShell/CertificateDsc/wiki/PfxImport
            PfxImport ("PfxImport_$($PfxCertificate.Thumbprint)")
            {
                Ensure = $PfxCertificate.Ensure
                Thumbprint = $PfxCertificate.Thumbprint
                Path = $PfxCertificate.Path
                Location = $PfxCertificate.Location
                Store = $PfxCertificate.Store
                Credential = $objCertCredential
                Exportable = $PfxCertificate.Exportable
                PsDscRunAsCredential = $SPSetupCredential
            }
        }
            
        # Ensure Cer Certificate(s) into Server Crtificate Store
        foreach($CerCertificate in $ConfigurationData.NonNodeData.SharePoint.Certificates.Cer)
        {
			# https://github.com/PowerShell/CertificateDsc/wiki/CertificateImport
            CertificateImport ("CertificateImport_$($CerCertificate.Thumbprint)") {
                Ensure = $CerCertificate.Ensure
                Thumbprint = $CerCertificate.Thumbprint
                Path = $CerCertificate.Path
                Location = $CerCertificate.Location
                Store = $CerCertificate.Store
                PsDscRunAsCredential = $SPSetupCredential
            }
        }
            
		# Windows Settings for SharePoint

        SharePointServerWindowsSettings SharePointWindowsSettings
        {
            Node = $Node
            PsDscRunAsCredential = $SPSetupCredential
        }

        SharePointServerEnforceTLS12 EnforeTLS12
        {
            Ensure = 'Present'
            PsDscRunAsCredential = $SPSetupCredential
		}

        # SQL Alias(es)
        foreach($SQLAlias in $ConfigurationData.NonNodeData.SharePoint.SQLAliases)
        {
            $SQLAliasLabel = "SQLAlias_$($SQLAlias.Name)"
            SQLAlias $SQLAliasLabel {
                Name = $SQLAlias.Name
                ServerName = $SQLAlias.ServerName
                Ensure = $SQLAlias.Ensure
                PsDscRunAsCredential = $SPSetupCredential
            }
        }

        # Deploy IIS

        SharePointServerIIS DeployIIS
        {
            CustomHeaders = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.CustomHeaders
            DisableLoopbackCheck = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.DisableLoopbackCheck
            LogFormat = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.LogFormat
			LogLocalTimeRollover = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.LogLocalTimeRollover
            LogPath = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.LogPath
            LogPeriod = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.LogPeriod
            Node = $Node
			RemoveIISDefaults = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.RemoveIISDefaults
            TraceLogPath = $ConfigurationData.NonNodeData.SharePoint.InternetInformationServer.TraceLogPath
            Ensure = 'Present'
            PsDscRunAsCredential = $SPSetupCredential
        }

		# Install SharePoint Prerequisites		
        SharePointServerInstall SPInstall
        { 
            Node = $Node
            PsDscRunAsCredential = $SPSetupCredential
	        DependsOn = '[SharePointServerIIS]DeployIIS'
        }

        $CreateOrJoinDependsOn = @('[SharePointServerInstall]SPInstall')

        if ($Node.NodeName -ne $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode)
        {
            # Get All Non Distribution (First) Node
            # Design intent sort by ServerRole then Node Name.  Given SharePoint MinRole Names, Application servers anticipated to be first, WebFrontEnds last
            $AllNodesNonDistribution = ($AllNodes | Where-Object { ($_.NodeName -ne $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) } | Sort-Object -Property ServerRole, NodeName).NodeName

            # Get the Index of the current node in that array
            $CurrentNodeIndex = $AllNodesNonDistribution.IndexOf($Node.NodeName)

            if ($CurrentNodeIndex -eq 0)
            {
                # First in the Array, must depend on Primary Distribution Node (cannot do N-1)
                $CreateOrJoinPredecessorNode = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
			}
            else
            {
                # If not Primary/Distribution Node, we can do N-1
                $CreateOrJoinPredecessorNode = $AllNodesNonDistribution[$CurrentNodeIndex - 1]
			}

            WaitForAll ('CreateOrJoinFarmPredecessor_' + $CreateOrJoinPredecessorNode)
            {
                NodeName = $CreateOrJoinPredecessorNode
                ResourceName = '[PendingReboot]RebootAfterCreateJoin::[SharePointServerCreateOrJoinFarm]SPCreateOrJoinFarm'
                RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
                RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
                PsDscRunAsCredential = $SPSetupCredential
            }

            $CreateOrJoinDependsOn = '[WaitForAll]CreateOrJoinFarmPredecessor_' + $CreateOrJoinPredecessorNode
		}

		# Create or Join SharePoint Farm
        SharePointServerCreateOrJoinFarm SPCreateOrJoinFarm
        {
            Node = $Node
            CreateOnNodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
            SPFarmCredential = $SPFarmCredential
            PsDscRunAsCredential = $SPSetupCredential
			DependsOn = $CreateOrJoinDependsOn
        }

        WaitForAll CreateOrJoinFarm
        {
            NodeName = ($AllNodes).NodeName
            ResourceName = '[PendingReboot]RebootAfterMinRoleServiceInstances::[SharePointServerCreateOrJoinFarm]SPCreateOrJoinFarm'
            RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
            RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
			DependsOn = "[SharePointServerCreateOrJoinFarm]SPCreateOrJoinFarm"
            PsDscRunAsCredential = $SPSetupCredential
        }

		SharePointServerFarmConfiguration DeployFarmConfig
        {
            Node = $Node
            SPFarmCredential = $SPFarmCredential
			PsDscRunAsCredential = $SPSetupCredential
			DependsOn = "[WaitForAll]CreateOrJoinFarm"
		}
            
        WaitForAll FarmConfiguration
        {
            NodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
            ResourceName = '[PendingReboot]RebootAfterNodeConfiguration::[SharePointServerFarmConfiguration]DeployFarmConfig'
            RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
            RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
            PsDscRunAsCredential = $SPSetupCredential
        }

        SharePointServerSearchTopology DeploySearchToplogy
        {
            Node = $Node
            DeployOnNodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
        	PsDscRunAsCredential = $SPSetupCredential
			DependsOn = "[WaitForAll]FarmConfiguration"
		}

         <#       
		SharePointServerDistributedCache DistributedCache {
			Node = $Node
			PsDscRunAsCredential = $SPSetupCredential
		}
        #>

        SPConfigWizard RunConfigWizard
        {
            IsSingleInstance = "Yes"
            DatabaseUpgradeDays = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationWizard.DatabaseUpgradeDays
            DatabaseUpgradeTime = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationWizard.DatabaseUpgradeTime
            PsDscRunAsCredential = $SPSetupCredential
        }

        SharePointServerIISBindings IISBindings 
        {
            Node = $Node
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPConfigWizard]RunConfigWizard"
		}

         <#       

        if ($Node.ServerRole -eq 'Custom') {

            #**********************************************************
            # Custom - Distributed cache
            #**********************************************************
			    $AllDCacheNodes = $AllNodes | Where-Object { ($_.ServerRole -eq 'Custom') -and ($_.ServiceRoles.DistributedCache -eq $true) }

            if ($Node.ServiceRoles.DistributedCache -eq $true) {
                $CurrentDcacheNode = [Array]::IndexOf($AllDCacheNodes, $Node)

                #Wait for service account to be managed

                if ($Node.NodeName -ne $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) {
                    # Node is not the first app server so won't have the dependency for the service account
                    WaitForAll WaitForServiceAccount {
                        ResourceName = '[SPManagedAccount]ServicePoolManagedAccount'
                        NodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
                        RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
                        RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
                        PsDscRunAsCredential = $SPSetupCredential
                        DependsOn = '[SPServiceInstance]ClaimsToWindowsTokenService' 
                    }

                    $DCacheWaitFor = '[WaitForAll]WaitForServiceAccount'
                } else {
                    $DCacheWaitFor = '[SPManagedAccount]ServicePoolManagedAccount'
                }

                if ($CurrentDcacheNode -eq 0) {
                    # The first distributed cache node doesn't wait on anything
                    SPDistributedCacheService EnableDistributedCache {
                        Name = 'AppFabricCachingService'
                        Ensure = 'Present'
                        CacheSizeInMB = $ConfigurationData.NonNodeData.SharePoint.Farm.DCache.CacheSizeInMB
                        ServiceAccount = $SPSvcAppCredential.UserName
                        CreateFirewallRules = $true
                        ServerProvisionOrder = $AllDCacheNodes.NodeName
                        PsDscRunAsCredential = $SPSetupCredential
                        DependsOn = @('[SPServiceInstance]ClaimsToWindowsTokenService',$DCacheWaitFor)
                    }
                } else {
                    # All other distributed cache nodes depend on the node previous to it
                    $previousDCacheNode = $AllDCacheNodes[$CurrentDcacheNode - 1]
                    WaitForAll WaitForDCache {
                        ResourceName = '[SPDistributedCacheService]EnableDistributedCache'
                        NodeName = $previousDCacheNode.NodeName
                        RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
                        RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
                        PsDscRunAsCredential = $SPSetupCredential
                        DependsOn = '[SPServiceInstance]ClaimsToWindowsTokenService'
                    }

                    SPDistributedCacheService EnableDistributedCache {
                        Name = 'AppFabricCachingService'
                        Ensure = 'Present'
                        CacheSizeInMB = $ConfigurationData.NonNodeData.SharePoint.Farm.DCache.CacheSizeInMB
                        ServiceAccount = $SPSvcAppCredential.UserName
                        CreateFirewallRules  = $true
                        ServerProvisionOrder = $AllDCacheNodes.NodeName
                        PsDscRunAsCredential = $SPSetupCredential
                        DependsOn = '[WaitForAll]WaitForDCache'
                    }
                }
            }
        }

<#
        # Update bindings on other nodes
        # Only Application, Web Front End, and Custom servers get bindings
        WaitForAll WaitForWebAppsOnCA {
            ResourceName = '[SPSite]$internalSiteName'
            NodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
            RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
            RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
            PsDscRunAsCredential = $SPSetupCredential
        }

        # Run the configuration wizard on the CA host first
        if ($Node.NodeName -eq $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) {
            SPConfigWizard RunConfigWizOnCAServer {
                IsSingleInstance = 'Yes'
                PsDscRunAsCredential = $SPSetupCredential
                DependsOn = '[WaitForAll]??'
            }
        } else {
            # Wait until the CA host completes before running wizard on other systems
            WaitForAll WaitConfigWizOnCAServer {
                ResourceName = '[SPConfigWizard]RunConfigWizOnCAServer'
                NodeName = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode
                RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
                RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
                PsDscRunAsCredential = $SPSetupCredential
            }

            SPConfigWizard RunConfigWizNonCAServers {
            IsSingleInstance = 'Yes'
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = '[WaitForAll]WaitConfigWizOnCAServer'
            }
        }
		#>
#>

    }
}