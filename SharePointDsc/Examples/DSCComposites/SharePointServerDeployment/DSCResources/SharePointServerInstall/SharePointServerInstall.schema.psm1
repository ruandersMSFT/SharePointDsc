Configuration SharePointServerInstall
{
param
(
[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[System.Collections.Hashtable]$Node
)

    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 8.0.0
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
	Import-DscResource -ModuleName SharePointServerDeployment

    # SharePoint Binaries /  Installation Files
    SharePointServerBinaries DeploySharePointBinaries
	{
        SharePointBinarySourceArchive = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.SPZipPath
        SharePointBinaryPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.SPInstallPath
        SharePointPreRequisitesSourcePath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.PreRequisitesSourcePath
        SharePointPreRequisitesTargetPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.PreRequisitesTargetPath
        Ensure = 'Present'
    }

	if ($ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OnlineMode -eq $true)
	{
	    SPInstallPrereqs InstallPrerequisites
		{
			IsSingleInstance = 'Yes'
			InstallerPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.PrereqInstallerPath
			OnlineMode = $true
			Ensure = 'Present'
			DependsOn = '[SharePointServerBinaries]DeploySharePointBinaries'
		}
	}
	else 
	{
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall -eq $null)
		{
			throw [Exception] "OfflineInstall configuration must be provided when OnlineMode is false"
		}

		# SharePoint 2013 / 2016 / 2019 Offline variations
		switch ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion)
		{
			'2013' 
			{ 
				SPInstallPrereqs InstallPrerequisites
				{
					IsSingleInstance = 'Yes'
					InstallerPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.PrereqInstallerPath 

					SXSPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SXSPath
					SQLNCli = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SQLNCliInstallPath
					#PowerShell = 
					#NETFX = 
					#IDFX = 
					Sync = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SyncInstallPath
					AppFabric = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.AppFabricInstallPath
					IDFX11 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.IDFX11InstallPath
					MSIPCClient = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSIPCClientInstallPath
					#WCFDataServices = 
					#KB2671763 = 
					WCFDataServices56 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.WCFDataServices56InstallPath


					OnlineMode = $false
					Ensure = 'Present'
					DependsOn = '[SharePointServerBinaries]DeploySharePointBinaries'
				}
				break 
			}
			'2016' 
			{ 
				SPInstallPrereqs InstallPrerequisites
				{
					IsSingleInstance = 'Yes'
					InstallerPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.PrereqInstallerPath 
					SXSPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SXSPath
					SQLNCli = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SQLNCliInstallPath
					Sync = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SyncInstallPath
					AppFabric = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.AppFabricInstallPath
					IDFX11 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.IDFX11InstallPath
					MSIPCClient = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSIPCClientInstallPath
					WCFDataServices56 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.WCFDataServices56InstallPath
					MSVCRT11 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSVCRT11InstallPath
					#MSVCRT141 = 
					KB3092423 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.KB3092423InstallPath
					#ODBC = 
					#DotNetFx = 

					OnlineMode = $false
					Ensure = 'Present'
					DependsOn = '[SharePointServerBinaries]DeploySharePointBinaries'
				}
				break 
			}
			'2019' 
			{ 
				SPInstallPrereqs InstallPrerequisites
				{
					IsSingleInstance = 'Yes'
					InstallerPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.PrereqInstallerPath 
					SXSPath = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SXSPath
					SQLNCli = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SQLNCliInstallPath
					Sync = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.SyncInstallPath
					AppFabric = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.AppFabricInstallPath
					IDFX11 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.IDFX11InstallPath
					MSIPCClient = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSIPCClientInstallPath
					KB3092423 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.KB3092423InstallPath
					WCFDataServices56 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.WCFDataServices56InstallPath
					DotNet472 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.DotNet472InstallPath
					MSVCRT11 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSVCRT11InstallPath
					MSVCRT141 = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.OfflineInstall.MSVCRT14InstallPath
					OnlineMode = $false
					Ensure = 'Present'
					DependsOn = '[SharePointServerBinaries]DeploySharePointBinaries'
				}
				break 
			}
			default { throw [Exception] "SharePointVersion must be 2013, 2016 or 2019." }
		}
	}

	# Reboot after prerequisite install
    PendingReboot AfterPrereqInstall
	{
        Name = 'AfterPrereqInstall'
		SkipCcmClientSDK = $true
        DependsOn = '[SPInstallPrereqs]InstallPrerequisites'
    }

    SPInstall InstallSharePoint
	{
        Ensure = 'Present'
        IsSingleInstance = 'Yes'
        ProductKey = $ConfigurationData.NonNodeData.SharePoint.Farm.SharePointProductKey
        BinaryDir = $ConfigurationData.NonNodeData.SharePoint.Farm.Installation.SPInstallPath
        DependsOn = '[PendingReboot]AfterPrereqInstall'
    }

    # Reboot after installing SharePoint
    PendingReboot AfterSPInstall
	{
        Name = 'AfterSPInstall'
		SkipCcmClientSDK = $true
        DependsOn = '[SPInstall]InstallSharePoint'
    }

} 
