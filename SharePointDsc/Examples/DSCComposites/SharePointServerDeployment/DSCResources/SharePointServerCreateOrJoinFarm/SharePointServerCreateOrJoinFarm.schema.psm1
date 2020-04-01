Configuration SharePointServerCreateOrJoinFarm
{
    param
    (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [System.Collections.Hashtable]$Node,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String]$CreateOnNodeName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]$SPFarmCredential

    )

    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName xWebAdministration -ModuleVersion 3.1.1

    if ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion -ne '2013' -and $ConfigurationData.NonNodeData.SharePoint.Farm.DeveloperDashboard -eq 'OnDemand')
    {
     throw [Exception] "DeveloperDashboard can only be set to 'OnDemand' in SharePoint 2013."
	}

	$objPassPhrase = $ConfigurationData.NonNodeData.SharePoint.Farm.PassPhrase | ConvertTo-SecureString -AsPlainText -Force
    $SPPassPhraseCred =  New-Object System.Management.Automation.PSCredential('PassPhrase', $objPassPhrase)

    #region Basic farm configuration
    
	# https://github.com/PowerShell/SharePointDsc/wiki/SPFarm
    if ($Node.NodeName -eq $CreateOnNodeName) {
            
        $LocalNodeSPFarmWaitCondition = "[SPFarm]SPFarmCreate"
        
        # Create the SharePoint Farm (first server / new farm)
        SPFarm SPFarmCreate {
			AdminContentDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.ContentDatabase
			CentralAdministrationAuth = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.AuthenticationMode
			CentralAdministrationPort = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Port
            CentralAdministrationUrl = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Url
			DatabaseServer = $ConfigurationData.NonNodeData.SharePoint.Farm.DatabaseServer
			DeveloperDashboard = $ConfigurationData.NonNodeData.SharePoint.Farm.DeveloperDashboard
			FarmAccount = $SPFarmCredential
			FarmConfigDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationDatabase
			Passphrase = $SPPassPhraseCred
			RunCentralAdmin = $Node.CentralAdministration -ne $null -and $Node.CentralAdministration.RunCentralAdmin -eq $true
			ServerRole = $Node.ServerRole
			Ensure = 'Present'
			IsSingleInstance = 'Yes'
        }

    } else {

		$LocalNodeSPFarmWaitCondition = "[SPFarm]SPFarmJoin"

        WaitForAll WaitForFarmToExist {
            ResourceName = '[PendingReboot]RebootAfterCreateJoin::[SharePointServerCreateOrJoinFarm]SPCreateOrJoinFarm'
            NodeName = $CreateOnNodeName
            RetryIntervalSec = $ConfigurationData.NonNodeData.WaitRetryIntSec
            RetryCount = $ConfigurationData.NonNodeData.WaitRetryCount
        }

		# Join the server to an existing Farm
        SPFarm SPFarmJoin {
            AdminContentDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.ContentDatabase
			CentralAdministrationAuth = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.AuthenticationMode
			CentralAdministrationPort = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Port
            CentralAdministrationUrl = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Url
            DatabaseServer = $ConfigurationData.NonNodeData.SharePoint.Farm.DatabaseServer
			DeveloperDashboard = $ConfigurationData.NonNodeData.SharePoint.Farm.DeveloperDashboard
            FarmAccount = $SPFarmCredential
            FarmConfigDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationDatabase
            Passphrase = $SPPassPhraseCred
			RunCentralAdmin = $Node.CentralAdministration -ne $null -and $Node.CentralAdministration.RunCentralAdmin -eq $true
            ServerRole = $Node.ServerRole
            Ensure = 'Present'
			IsSingleInstance = 'Yes'
            DependsOn = '[WaitForAll]WaitForFarmToExist'
        }
    }

	# Reboot after Create or Join
    PendingReboot RebootAfterCreateJoin {
        Name = 'RebootAfterCreateJoin'
		SkipCcmClientSDK = $true
        DependsOn = $LocalNodeSPFarmWaitCondition
    }

    $FinalCreateJoinRebootDependsOn = '[PendingReboot]RebootAfterCreateJoin'
	if ($Node.ServerRole -ne 'Custom') 
	{
        $FinalCreateJoinRebootDependsOn = '[SPMinRoleCompliance]MinRoleCompliance'

		# Min Role Compliance Check
		# https://github.com/PowerShell/SharePointDsc/wiki/SPMinRoleCompliance
		SPMinRoleCompliance MinRoleCompliance
		{
			IsSingleInstance     = "Yes"
			State                = $ConfigurationData.NonNodeData.SharePoint.Farm.MinRoleComplianceState
			DependsOn = '[PendingReboot]RebootAfterCreateJoin'
		}
	}
	else
	{
		if ($Node.CustomServiceInstances -ne $null)
		{
			foreach($CustomServiceInstance in $Node.CustomServiceInstances) {
				$CustomServiceInstanceNameNoSpace = $CustomServiceInstance.Name.Replace(" ", "")

				SPServiceInstance $CustomServiceInstanceNameNoSpace {  
					Name = $CustomServiceInstance.Name
					Ensure = $CustomServiceInstance.Ensure
					DependsOn = $FinalCreateJoinRebootDependsOn
				}

                # Change next Depends On usage to this Service Instance
                $FinalCreateJoinRebootDependsOn = "[SPServiceInstance]$($CustomServiceInstanceNameNoSpace)"
			}
		}
    }

    # Reboot after MinRole / ServiceActivation
    PendingReboot RebootAfterMinRoleServiceInstances {
        Name = 'RebootAfterMinRoleServiceInstances'
		SkipCcmClientSDK = $true
        DependsOn = $FinalCreateJoinRebootDependsOn
    }
} 
