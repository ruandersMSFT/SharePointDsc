Configuration SharePointServerFarmConfiguration
{
    param
    (
    	[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$Node,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]$SPFarmCredential
	)

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SharePointServerDeployment

	# Apply farm wide configuration and logical components only on the first server
	if ($Node.NodeName -eq $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) 
	{
		# Trusted Root Authority
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.TrustedRootAuthorities -ne $null)
		{
			foreach ($TrustedRootAuthority in $ConfigurationData.NonNodeData.SharePoint.Farm.TrustedRootAuthorities)
			{
				$TrustedRootAuthorityName = $TrustedRootAuthority.Name.Replace(' ', '')

	            $TrustedRootAuthorityCertificate = $ConfigurationData.NonNodeData.SharePoint.Certificates.Cer | ? { $_.Thumbprint -eq $TrustedRootAuthority.CertificateThumbprint -and $_.Ensure -eq 'Present' -and $_.Location -eq 'LocalMachine' -and $_.Store -eq 'My' }
				if ($TrustedRootAuthorityCertificate -eq $null)
				{
					throw [Exception] "Certificate with thumbprint '$($TrustedRootAuthority.CertificateThumbprint)' must be defined in the Configuration Data CER Certificates with Ensure = 'Present', Location = 'LocalMachine' and Store = 'My' to utilize in Trusted Root Authority '$($TrustedRootAuthority.Name)'."
				}

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPTrustedRootAuthority
				SPTrustedRootAuthority $TrustedRootAuthorityName
				{
					Name                  = $TrustedRootAuthority.Name
					CertificateThumbprint = $TrustedRootAuthority.CertificateThumbprint
					Ensure                = $TrustedRootAuthority.Ensure
				}
			}
		}

		# SharePoint Authentication Realm
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.AuthenticationRealm -ne $null)
		{
			if ($ConfigurationData.NonNodeData.SharePoint.Farm.AuthenticationRealm -ceq $ConfigurationData.NonNodeData.SharePoint.Farm.AuthenticationRealm.ToLower())
			{
				# https://github.com/dsccommunity/SharePointDsc/wiki/SPAuthenticationRealm
				SPAuthenticationRealm AuthenticationRealm
				{
					IsSingleInstance = "Yes"
					AuthenticationRealm = $ConfigurationData.NonNodeData.SharePoint.Farm.AuthenticationRealm
				}
			}
			else
			{
				throw "AuthenticationRealm must be lower cased."
			}
		}
		
		# SharePoint Log Level
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.LogLevels -ne $null)
		{
			foreach ($LogLevel in $ConfigurationData.NonNodeData.SharePoint.Farm.LogLevels)
			{
				$LogLevelName = $LogLevel.Name.Replace(' ', '_')

				$LogLevelSettings = @()

				if ($LogLevel.Settings -ne $null)
				{
					foreach ($Setting in $LogLevel.Settings)
					{
						$LogLevelItem = MSFT_SPLogLevelItem 
						{
							Area = $Setting.Area
							Name = $Setting.Name
							TraceLevel = $Setting.TraceLevel
							EventLevel = $Setting.EventLevel
						}

						$LogLevelSettings += $LogLevelItem
					}
				}

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPLogLevel
				SPLogLevel $LogLevelName
				{
					Name = $LogLevel.Name
					SPLogLevelSetting = $LogLevelSettings
				}
			}
		}

		# SharePoint Farm Administrators
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.Administrators -eq $null)
		{
			throw "Administrators must be defined within the Farm configuration."
		}
		else 
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPFarmAdministrators
			SPFarmAdministrators LocalFarmAdmins
			{
				IsSingleInstance     = "Yes"
				Members              = $ConfigurationData.NonNodeData.SharePoint.Farm.Administrators.Members
				MembersToInclude     = $ConfigurationData.NonNodeData.SharePoint.Farm.Administrators.MembersToInclude
				MembersToExclude     = $ConfigurationData.NonNodeData.SharePoint.Farm.Administrators.MembersToExclude
			}
		}

		# Managed Account(s)
		foreach($SPManagedAccount in $ConfigurationData.NonNodeData.SharePoint.Farm.ManagedAccounts)
		{
			$SPManagedAccountLabel = "SPManagedAccount_$($SPManagedAccount.Name)"

			$ManagedAccountPassword = $SPManagedAccount.Password | ConvertTo-SecureString -AsPlainText -Force
			$ManagedAccountCredential = New-Object System.Management.Automation.PSCredential($SPManagedAccount.Account, $ManagedAccountPassword)

			# https://github.com/PowerShell/SharePointDsc/wiki/SPManagedAccount
			SPManagedAccount $SPManagedAccountLabel
			{
				AccountName = $ManagedAccountCredential.UserName
				Account = $ManagedAccountCredential
			}
		}

		# Service App Pool(s)
		foreach($SPServiceAppPool in $ConfigurationData.NonNodeData.SharePoint.Farm.ServiceAppPools)
		{
			if ($SPServiceAppPool.ServiceAccount.Contains('$'))
			{
				# https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/plan-for-administrative-and-service-accounts
				# Important: Do not use service account names that contain the symbol $ with the exception of using a Group Managed Service Account for SQL Server.
				throw [Exception] "Service Account '$($SPServiceAppPool.ServiceAccount)' for Service App Pool '$($SPServiceAppPool.Name)' cannot contain $.  https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/plan-for-administrative-and-service-accounts"
			}

			$AppPoolName = "AppPool_" + $SPServiceAppPool.Name.Replace(' ', '_')

			# https://github.com/PowerShell/SharePointDsc/wiki/SPServiceAppPool
			SPServiceAppPool $AppPoolName
			{
				Name = $SPServiceAppPool.Name
				ServiceAccount = $SPServiceAppPool.ServiceAccount
			}
		}

		# Security Token Service Config
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig -ne $null)
		{
			# https://github.com/dsccommunity/SharePointDsc/wiki/SPSecurityTokenServiceConfig
			SPSecurityTokenServiceConfig SecurityTokenService
            {
                IsSingleInstance = "Yes"
                Name = $ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig.Name
                NameIdentifier = $ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig.NameIdentifier
                UseSessionCookies = $ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig.UseSessionCookies
                AllowOAuthOverHttp = $ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig.AllowOAuthOverHttp
                AllowMetadataOverHttp = $ConfigurationData.NonNodeData.SharePoint.Farm.SecurityTokenServiceConfig.AllowMetadataOverHttp
				Ensure = 'Present' # Document as Absent not supported
            }
		}

		# Health Analyzer Rule state
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.HealthAnalyzerRuleStates -ne $null)
		{
			foreach ($HealthAnalyzerRuleState in $ConfigurationData.NonNodeData.SharePoint.Farm.HealthAnalyzerRuleStates)
			{
				$HealthAnalyzerRuleStateName = "HealthAnalyzerRuleState_" + $HealthAnalyzerRuleState.Name.Replace(' ', '_')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPHealthAnalyzerRuleState
				SPHealthAnalyzerRuleState $HealthAnalyzerRuleStateName
				{
					Name = $HealthAnalyzerRuleState.Name
					Enabled = $HealthAnalyzerRuleState.Enabled
					RuleScope = $HealthAnalyzerRuleState.RuleScope
					Schedule = $HealthAnalyzerRuleState.Schedule
					FixAutomatically = $HealthAnalyzerRuleState.FixAutomatically
				}
			}
		}

		# Diagnostic Logging Settings
		# https://github.com/PowerShell/SharePointDsc/wiki/SPDiagnosticLoggingSettings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings -ne $null)
		{
			SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
			{
				IsSingleInstance = 'Yes'
				LogPath = $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.LogPath
				LogSpaceInGB = $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.LogSpaceInGB
				AppAnalyticsAutomaticUploadEnabled = $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.AppAnalyticsAutomaticUploadEnabled
				CustomerExperienceImprovementProgramEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.CustomerExperienceImprovementProgramEnabled
				DaysToKeepLogs = $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.DaysToKeepLogs
				DownloadErrorReportingUpdatesEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.DownloadErrorReportingUpdatesEnabled
				ErrorReportingAutomaticUploadEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.ErrorReportingAutomaticUploadEnabled
				ErrorReportingEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.ErrorReportingEnabled
				EventLogFloodProtectionEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.EventLogFloodProtectionEnabled
				EventLogFloodProtectionNotifyInterval =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.EventLogFloodProtectionNotifyInterval
				EventLogFloodProtectionQuietPeriod =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.EventLogFloodProtectionQuietPeriod
				EventLogFloodProtectionThreshold =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.EventLogFloodProtectionThreshold
				EventLogFloodProtectionTriggerPeriod =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.EventLogFloodProtectionTriggerPeriod
				LogCutInterval =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.LogCutInterval
				LogMaxDiskSpaceUsageEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.LogMaxDiskSpaceUsageEnabled
				ScriptErrorReportingDelay =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.ScriptErrorReportingDelay
				ScriptErrorReportingEnabled =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.ScriptErrorReportingEnabled
				ScriptErrorReportingRequireAuth =  $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticLoggingSettings.ScriptErrorReportingRequireAuth
			}
		}

		# Diagnostic Providers
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticProviders -ne $null)
		{
			foreach ($DiagnosticProvider in $ConfigurationData.NonNodeData.SharePoint.Farm.DiagnosticProviders)
			{
				$DiagnosticProviderName = "DiagnosticProvider_" + $DiagnosticProvider.Name.Replace(' ', '')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPDiagnosticsProvider
				SPDiagnosticsProvider $DiagnosticProviderName
				{
					Name = $DiagnosticProvider.Name
					MaxTotalSizeInBytes = $DiagnosticProvider.MaxTotalSizeInBytes
					Retention = $DiagnosticProvider.Retention
					Enabled = $DiagnosticProvider.Enabled
					Ensure = $DiagnosticProvider.Ensure
				}
			}
		}

		# Usage Application
		# https://github.com/PowerShell/SharePointDsc/wiki/SPUsageApplication
		SPUsageApplication UsageApplication
		{
			Name = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.Name
			DatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.DatabaseName
			DatabaseServer = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.DatabaseServer
			UsageLogCutTime = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.UsageLogCutTime
			UsageLogLocation = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.UsageLogLocation
			UsageLogMaxFileSizeKB = $ConfigurationData.NonNodeData.SharePoint.Farm.UsageApplication.UsageLogMaxFileSizeKB
		}

		# https://github.com/PowerShell/SharePointDsc/wiki/SPStateServiceApp
		SPStateServiceApp StateServiceApp
		{
			Name = $ConfigurationData.NonNodeData.SharePoint.Farm.StateServiceApplication.Name
			DatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.StateServiceApplication.DatabaseName
			DatabaseServer = $ConfigurationData.NonNodeData.SharePoint.Farm.StateServiceApplication.DatabaseServer
		}

		# Secure Store Service Application(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.SecureStoreServices -ne $null)
		{
			foreach($SecureStoreServiceApplication in $ConfigurationData.NonNodeData.SharePoint.Farm.SecureStoreServices) 
			{
				$SecureStoreServiceApplicationNameNoSpaces = $SecureStoreServiceApplication.Name.Replace(' ', '')
		
				# https://github.com/PowerShell/SharePointDsc/wiki/SPSecureStoreServiceApp
				SPSecureStoreServiceApp $SecureStoreServiceApplicationNameNoSpaces
				{
					Name = $SecureStoreServiceApplication.Name
					ApplicationPool = $SecureStoreServiceApplication.ApplicationPool
					AuditingEnabled = $SecureStoreServiceApplication.AuditingEnabled
					AuditlogMaxSize = $SecureStoreServiceApplication.AuditLogMaxSize
					DatabaseName = $SecureStoreServiceApplication.DatabaseName
					DatabaseServer = $SecureStoreServiceApplication.DatabaseServer
					Ensure = $SecureStoreServiceApplication.Ensure
				}

				if ($SecureStoreServiceApplication.Ensure -eq 'Present')
				{
					$PublishServiceApplicationEnsure = 'Absent'
					if ($SecureStoreServiceApplication.PublishService -ne $null -and $SecureStoreServiceApplication.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($SecureStoreServiceApplicationNameNoSpaces + '_PublishServiceApplication')
					{
						Name = $SecureStoreServiceApplication.Name
						Ensure = $PublishServiceApplicationEnsure
					}
				}
			}
		}

		# Managed Meta Data Service Application
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.ManagedMetaDataServices -ne $null)
		{
			$DefaultColumnTermSetService = $null
			$DefaultKeywordTermSetService = $null
			foreach($ManagedMetaDataService in $ConfigurationData.NonNodeData.SharePoint.Farm.ManagedMetaDataServices) 
			{
				$ManagedMetaDataServiceNoSpaces = $ManagedMetaDataService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPManagedMetaDataServiceApp
				SPManagedMetaDataServiceApp $ManagedMetaDataServiceNoSpaces
				{
					Name = $ManagedMetaDataService.Name
					ProxyName = $ManagedMetaDataService.ProxyName
					ApplicationPool = $ManagedMetaDataService.ApplicationPool
					ContentTypePushdownEnabled = $ManagedMetaDataService.ContentTypePushdownEnabled
					ContentTypeSyndicationEnabled = $ManagedMetaDataService.ContentTypeSyndicationEnabled
					DatabaseName = $ManagedMetaDataService.DatabaseName
					DatabaseServer = $ManagedMetaDataService.DatabaseServer
					TermStoreAdministrators = $ManagedMetaDataService.TermStoreAdministrators
					Ensure = $ManagedMetaDataService.Ensure
				}

				if ($ManagedMetaDataService.Ensure -eq 'Present')
				{
					if ($ManagedMetaDataService.IsDefaultColumnTermSetService -eq $true)
					{
						if ($DefaultColumnTermSetService -ne $null)
						{
							throw [Exception] "Only one Managed Metadata Service can be set as the Default Column Term Set."
						}

						$DefaultColumnTermSetService = $ManagedMetaDataService
					}

					if ($ManagedMetaDataService.IsDefaultKeywordTermSetService -eq $true)
					{
						if ($DefaultKeywordTermSetService -ne $null)
						{
							throw [Exception] "Only one Managed Metadata Service can be set as the Default Keyword Term Set."
						}

						$DefaultKeywordTermSetService = $ManagedMetaDataService
					}

					$PublishServiceApplicationEnsure = 'Absent'
					if ($ManagedMetaDataService.PublishService -ne $null -and $ManagedMetaDataService.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($ManagedMetaDataServiceNoSpaces + '_PublishServiceApplication')
					{
						Name = $ManagedMetaDataService.Name
						Ensure = $PublishServiceApplicationEnsure
					}
				}
			}
			
			if ($DefaultColumnTermSetService -eq $null)
			{
				throw [Exception] "One Managed Metadata Service must be set as the Default Column Term Set (IsDefaultColumnTermSetService = `$true)."
			}

			if ($DefaultKeywordTermSetService -eq $null)
			{
				throw [Exception] "One Managed Metadata Service must be set as the Default Keyword Term Set (IsDefaultKeywordTermSetService = `$true)."
			}

			if ($DefaultColumnTermSetService.ProxyName -eq $null)
			{
				$DefaultSiteCollectionProxyName = $DefaultColumnTermSetService.Name
			}
			else
			{
				$DefaultSiteCollectionProxyName = $DefaultColumnTermSetService.ProxyName
			}

			if ($DefaultKeywordTermSetService.ProxyName -eq $null)
			{
				$DefaultKeywordProxyName = $DefaultKeywordTermSetService.Name
			}
			else
			{
				$DefaultKeywordProxyName = $DefaultKeywordTermSetService.ProxyName
			}
			
			<#

			Needs to have SPServiceAppProxyGroup implemented first, as of SharePoint DSC 4.0.0

			# https://github.com/dsccommunity/SharePointDsc/wiki/SPManagedMetaDataServiceAppDefault
			SPManagedMetaDataServiceAppDefault ManagedMetadataServiceAppDefault
			{
				DefaultKeywordProxyName = $DefaultKeywordProxyName
				DefaultSiteCollectionProxyName = $DefaultSiteCollectionProxyName
				ServiceAppProxyGroup = 'Proxy Group 1'
			}
			#>
		}

		# Access Service Application(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.AccessServices -ne $null)
		{
			foreach($AccessService in $ConfigurationData.NonNodeData.SharePoint.Farm.AccessServices)
			{
				$AccessServiceNoSpaces = $AccessService.Name.Replace(' ', '')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPAccessServiceApp
				SPAccessServiceApp $AccessServiceNoSpaces
				{
					Name = $AccessService.Name
					ApplicationPool = $AccessService.ApplicationPool 
					DatabaseServer = $AccessService.DatabaseServer
					Ensure = $AccessService.Ensure
				}
			}
		}

		# App management Service Application
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.AppManagementServices -ne $null)
		{
			foreach($AppManagementService in $ConfigurationData.NonNodeData.SharePoint.Farm.AppManagementServices) 
			{
				$AppManagementServiceNoSpaces = $AppManagementService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPAppManagementServiceApp
				SPAppManagementServiceApp $AppManagementServiceNoSpaces
				{
					Name = $AppManagementService.Name
					ApplicationPool = $AppManagementService.ApplicationPool
					DatabaseName = $AppManagementService.DatabaseName
					DatabaseServer = $AppManagementService.DatabaseServer
					Ensure = $AppManagementService.Ensure
				}
			}
		}

		# BCS Service Application
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.BusinessDataConnectivityServices -ne $null)
		{
			foreach($BusinessDataConnectivityService in $ConfigurationData.NonNodeData.SharePoint.Farm.BusinessDataConnectivityServices) 
			{
				$BusinessDataConnectivityServiceNoSpaces = $BusinessDataConnectivityService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPBCSServiceApp
				SPBCSServiceApp $BusinessDataConnectivityServiceNoSpaces
				{
					Name = $BusinessDataConnectivityService.Name
					ApplicationPool = $BusinessDataConnectivityService.ApplicationPool
					DatabaseName = $BusinessDataConnectivityService.DatabaseName
					DatabaseServer = $BusinessDataConnectivityService.DatabaseServer
					Ensure = $BusinessDataConnectivityService.Ensure
				}

				if ($BusinessDataConnectivityService.Ensure -eq 'Present')
				{
					$PublishServiceApplicationEnsure = 'Absent'
					if ($BusinessDataConnectivityService.PublishService -ne $null -and $BusinessDataConnectivityService.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($BusinessDataConnectivityServiceNoSpaces + '_PublishServiceApplication')
					{
						Name = $BusinessDataConnectivityService.Name
						Ensure = $PublishServiceApplicationEnsure
					}
				}
			}
		}

		# Excel Service Application
	    if ($ConfigurationData.NonNodeData.SharePoint.Farm.ExcelServices -ne $null)
		{
			if ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion -ne '2013')
			{
				throw [Exception] "Excel Services are only available in SharePoint 2013 and cannot be created in SharePoint $($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion) (ExcelServices cannot be specified in the Configuration Data File)."
			}

			foreach($ExcelService in $ConfigurationData.NonNodeData.SharePoint.Farm.ExcelServices)
			{
				$ExcelServiceNoSpaces = $ExcelService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPExcelServiceApp
				SPExcelServiceApp $ExcelServiceNoSpaces
				{
					Name = $ExcelService.Name
					ApplicationPool = $ExcelService.ApplicationPool
					CachingOfUnusedFilesEnable = $ExcelService.CachingOfUnusedFilesEnable
					CrossDomainAccessAllowed = $ExcelService.CrossDomainAccessAllowed
					EncryptedUserConnectionRequired = $ExcelService.EncryptedUserConnectionRequired
					ExternalDataConnectionLifetime = $ExcelService.ExternalDataConnectionLifetime
					FileAccessMethod = $ExcelService.FileAccessMethod
					LoadBalancingScheme = $ExcelService.LoadBalancingScheme
					MemoryCacheThreshold = $ExcelService.MemoryCacheThreshold
					PrivateBytesMax = $ExcelService.PrivateBytesMax
					SessionsPerUserMax = $ExcelService.SessionsPerUserMax
					SiteCollectionAnonymousSessionsMax = $ExcelService.SiteCollectionAnonymousSessionsMax
					TerminateProcessOnAccessViolation = $ExcelService.TerminateProcessOnAccessViolation
					ThrottleAccessViolationsPerSiteCollection = $ExcelService.ThrottleAccessViolationsPerSiteCollection
					TrustedFileLocations = $ExcelService.TrustedFileLocations
					UnattendedAccountApplicationId = $ExcelService.UnattendedAccountApplicationId
					UnusedObjectAgeMax = $ExcelService.UnusedObjectAgeMax
					WorkbookCache = $ExcelService.WorkbookCache
					WorkbookCacheSizeMax = $ExcelService.WorkbookCacheSizeMax
					Ensure = $ExcelService.Ensure
				}
			}
		}

		# Machine Translation Service App(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.MachineTranslationServiceApps -ne $null)
		{
			foreach($MachineTranslationServiceApp in $ConfigurationData.NonNodeData.SharePoint.Farm.MachineTranslationServiceApps)
			{
				$MachineTranslationServiceAppName = $MachineTranslationServiceApp.Name.Replace(' ', '')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPMachineTranslationServiceApp
				SPMachineTranslationServiceApp $MachineTranslationServiceAppName
				{
					Name = $MachineTranslationServiceApp.Name
					ApplicationPool = $MachineTranslationServiceApp.ApplicationPool
					DatabaseServer = $MachineTranslationServiceApp.DatabaseServer
					DatabaseName = $MachineTranslationServiceApp.DatabaseName
					ProxyName = $MachineTranslationServiceApp.ProxyName
					Ensure = $MachineTranslationServiceApp.Ensure
				}

				if ($MachineTranslationServiceApp.Ensure -eq 'Present')
				{
					$PublishServiceApplicationEnsure = 'Absent'
					if ($MachineTranslationServiceApp.PublishService -ne $null -and $MachineTranslationServiceApp.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($MachineTranslationServiceAppName + '_PublishServiceApplication')
					{
						Name = $MachineTranslationServiceApp.Name
						Ensure = $PublishServiceApplicationEnsure
					}
				}
			}
		}

		# Performance Point Service App(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.PerformancePointServiceApps -ne $null)
		{
			foreach($PerformancePointServiceApp in $ConfigurationData.NonNodeData.SharePoint.Farm.PerformancePointServiceApps)
			{
				$PerformancePointServiceAppName = $PerformancePointServiceApp.Name.Replace(' ', '')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPPerformancePointServiceApp
				SPPerformancePointServiceApp $PerformancePointServiceAppName
				{
					Name = $PerformancePointServiceApp.Name
					ApplicationPool = $PerformancePointServiceApp.ApplicationPool
					DatabaseServer = $PerformancePointServiceApp.DatabaseServer
					DatabaseName = $PerformancePointServiceApp.DatabaseName
					ProxyName = $PerformancePointServiceApp.ProxyName
					Ensure = $PerformancePointServiceApp.Ensure
				}
			}
		}

		# PowerPoint Automation Service App(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.PowerPointAutomationServiceApps -ne $null)
		{
			foreach($PowerPointAutomationServiceApp in $ConfigurationData.NonNodeData.SharePoint.Farm.PowerPointAutomationServiceApps)
			{
				$PowerPointAutomationServiceAppName = $PowerPointAutomationServiceApp.Name.Replace(' ', '')

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPPowerPointAutomationServiceApp
				SPPowerPointAutomationServiceApp $PowerPointAutomationServiceAppName
				{
					Name = $PowerPointAutomationServiceApp.Name
					ApplicationPool = $PowerPointAutomationServiceApp.ApplicationPool
					CacheExpirationPeriodInSeconds = $PowerPointAutomationServiceApp.CacheExpirationPeriodInSeconds
					MaximumConversionsPerWorker = $PowerPointAutomationServiceApp.MaximumConversionsPerWorker
					WorkerKeepAliveTimeoutInSeconds = $PowerPointAutomationServiceApp.WorkerKeepAliveTimeoutInSeconds
					WorkerProcessCount = $PowerPointAutomationServiceApp.WorkerProcessCount
					WorkerTimeoutInSeconds = $PowerPointAutomationServiceApp.WorkerTimeoutInSeconds
					ProxyName = $PowerPointAutomationServiceApp.ProxyName
					Ensure = $PowerPointAutomationServiceApp.Ensure
				}
			}
		}

		# Project Server Service Application(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.ProjectServerServices -ne $null)
		{
			# todo add exception in Project Server Key not present

			foreach($ProjectServerService in $ConfigurationData.NonNodeData.SharePoint.Farm.ProjectServerServices) 
			{
				$ProjectServerServiceNoSpaces = $ProjectServerService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPProjectServerServiceApp
				SPProjectServerServiceApp $ProjectServerServiceNoSpaces
				{
					Name = $ProjectServerService.Name
					ApplicationPool = $ProjectServerService.ApplicationPool
					Ensure = $ProjectServerService.Ensure
				}

			}

			if ($ConfigurationData.NonNodeData.SharePoint.Farm.ProjectServerProductKey -ne $null)
			{
				# https://github.com/PowerShell/SharePointDsc/wiki/SPProjectServerLicense
				SPProjectServerLicense ProjectServerLicenseKey {
					IsSingleInstance     = "Yes"
					ProductKey = $ConfigurationData.NonNodeData.SharePoint.Farm.ProjectServerProductKey
				}
			}
		}

		# Subscription Settings Service Application
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.SubscriptionSettingsServices -ne $null)
		{
			foreach($SubscriptionSettingsService in $ConfigurationData.NonNodeData.SharePoint.Farm.SubscriptionSettingsServices)
			{
				$SubscriptionSettingsServiceNoSpaces = $SubscriptionSettingsService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPSubscriptionSettingsServiceApp
				SPSubscriptionSettingsServiceApp $SubscriptionSettingsServiceNoSpaces
				{
					Name = $SubscriptionSettingsService.Name
					ApplicationPool = $SubscriptionSettingsService.ApplicationPool
					DatabaseName = $SubscriptionSettingsService.DatabaseName
					DatabaseServer = $SubscriptionSettingsService.DatabaseServer
					Ensure = $SubscriptionSettingsService.Ensure
				}
			}
		}
		
		# Visio Service Application(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.VisioGraphicsServices -ne $null)
		{
			foreach($VisioGraphicsService in $ConfigurationData.NonNodeData.SharePoint.Farm.VisioGraphicsServices) 
			{
				$VisioGraphicsServiceNoSpaces = $VisioGraphicsService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPVisioServiceApp
				SPVisioServiceApp $VisioGraphicsServiceNoSpaces
				{
					Name = $VisioGraphicsService.Name
					ApplicationPool = $VisioGraphicsService.ApplicationPool
					Ensure = $VisioGraphicsService.Ensure
				}
			}
		}

		# Word Automation Service Applications(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.WordAutomationServices -ne $null)
		{
			foreach($WordAutomationService in $ConfigurationData.NonNodeData.SharePoint.Farm.WordAutomationServices) 
			{
				$WordAutomationServiceNoSpaces = $WordAutomationService.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPWordAutomationServiceApp
				SPWordAutomationServiceApp $WordAutomationServiceNoSpaces {
					Name = $WordAutomationService.Name
					ApplicationPool = $WordAutomationService.ApplicationPool
					DatabaseName = $WordAutomationService.DatabaseName
					DatabaseServer = $WordAutomationService.DatabaseServer
					SupportedFileFormats = $WordAutomationService.SupportedFileFormats
					DisableEmbeddedFonts = $WordAutomationService.DisableEmbeddedFonts
					MaximumMemoryUsage = $WordAutomationService.MaximumMemoryUsage
					RecycleThreshold = $WordAutomationService.RecycleThreshold
					DisableBinaryFileScan = $WordAutomationService.DisableBinaryFileScan
					ConversionProcesses = $WordAutomationService.ConversionProcesses
					JobConversionFrequency = $WordAutomationService.JobConversionFrequency
					NumberOfConversionsPerProcess = $WordAutomationService.NumberOfConversionsPerProcess
					TimeBeforeConversionIsMonitored = $WordAutomationService.TimeBeforeConversionIsMonitored
					MaximumConversionAttempts = $WordAutomationService.MaximumConversionAttempts
					MaximumSyncConversionRequests = $WordAutomationService.MaximumSyncConversionRequests
					KeepAliveTimeout = $WordAutomationService.KeepAliveTimeout
					MaximumConversionTime = $WordAutomationService.MaximumConversionTime
					Ensure = $WordAutomationService.Ensure
				} 
			}
		}
	
		# App Domain
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.AppDomain -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPAppDomain
			SPAppDomain FarmAppDomain
			{
				AppDomain = $ConfigurationData.NonNodeData.SharePoint.Farm.AppDomain.AppDomain
				Prefix = $ConfigurationData.NonNodeData.SharePoint.Farm.AppDomain.Prefix
			}
		}

		# Trusted Identity Token Issuer(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.TrustedIdentityTokenIssuers -ne $null)
		{
			foreach($SPTrustedIdentityTokenIssuer in $ConfigurationData.NonNodeData.SharePoint.Farm.TrustedIdentityTokenIssuers) 
			{
				$SPTrustedIdentityTokenIssuerLabel = "SPTrustedIdentityTokenIssuer_$($SPTrustedIdentityTokenIssuer.Name)"

				$ClaimsMappings = @()

				foreach ($ClaimMapping in $SPTrustedIdentityTokenIssuer.ClaimMappings)
				{
					$ClaimsMappings += MSFT_SPClaimTypeMapping {
						Name = $ClaimMapping.Name
						IncomingClaimType = $ClaimMapping.IncomingClaimType
						LocalClaimType = $ClaimMapping.LocalClaimType
					}
				}

				# https://github.com/PowerShell/SharePointDsc/wiki/SPTrustedIdentityTokenIssuer
				SPTrustedIdentityTokenIssuer $SPTrustedIdentityTokenIssuerLabel
				{
					Name = $SPTrustedIdentityTokenIssuer.Name
					Description = $SPTrustedIdentityTokenIssuer.Description
					Realm = $SPTrustedIdentityTokenIssuer.Realm
					SignInUrl = $SPTrustedIdentityTokenIssuer.SignInUrl
					IdentifierClaim = $SPTrustedIdentityTokenIssuer.IdentifierClaim
					ClaimsMappings = $ClaimsMappings
					SigningCertificateThumbPrint = $SPTrustedIdentityTokenIssuer.SigningCertificateThumbPrint
					ClaimProviderName = $SPTrustedIdentityTokenIssuer.ClaimProviderName
					ProviderSignOutUri = $SPTrustedIdentityTokenIssuer.ProviderSignOutUri
					UseWReplyParameter = $SPTrustedIdentityTokenIssuer.UseWReplyParameter
					Ensure = $SPTrustedIdentityTokenIssuer.Ensure
				}

				if ($SPTrustedIdentityTokenIssuer.Ensure.ToLower() -eq "present") # We can only ensure Provider Realms if the Provider is Present
				{
					$SPTrustedIdentityTokenIssuerProviderRealmsLabel = "SPTrustedIdentityTokenIssuerProviderRealms_$($SPTrustedIdentityTokenIssuer.Name)"

					$ProviderRealms = @()

					foreach ($ProviderRealm in $SPTrustedIdentityTokenIssuer.Realms)
					{
						$ProviderRealms += MSFT_SPProviderRealm {
							RealmUrl = $ProviderRealm.RealmUrl
							RealmUrn = $ProviderRealm.RealmUrn
						}
					}

					# https://github.com/PowerShell/SharePointDsc/wiki/SPTrustedIdentityTokenIssuerProviderRealms
					SPTrustedIdentityTokenIssuerProviderRealms $SPTrustedIdentityTokenIssuerProviderRealmsLabel
					{
						IssuerName = $SPTrustedIdentityTokenIssuer.Name
						ProviderRealms = $ProviderRealms
						Ensure = "Present"
					}
				}
			}
		}

		# Trusted Security Token Issuer(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.TrustedSecurityTokenIssuers -ne $null)
		{
			foreach($SPTrustedSecurityTokenIssuer in $ConfigurationData.NonNodeData.SharePoint.Farm.TrustedSecurityTokenIssuers) 
			{
				$SPTrustedSecurityTokenIssuerLabel = "SPTrustedSecurityTokenIssuer_$($SPTrustedSecurityTokenIssuerLabel.Name)"

				# https://github.com/PowerShell/SharePointDsc/wiki/SPTrustedSecurityTokenIssuer
				SPTrustedSecurityTokenIssuer  $SPTrustedSecurityTokenIssuerLabel
				{
					Name = $SPTrustedSecurityTokenIssuer.Name
					Description = $SPTrustedSecurityTokenIssuer.Description
					RegisteredIssuerNameIdentifier = $SPTrustedSecurityTokenIssuer.RegisteredIssuerNameIdentifier
					IsTrustBroker = $SPTrustedSecurityTokenIssuer.IsTrustBroker
					SigningCertificateThumbprint = $SPTrustedSecurityTokenIssuer.SigningCertificateThumbprint
					Ensure = $SPTrustedSecurityTokenIssuer.Ensure
				}
			}
		}

		# Quota Templates
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.QuotaTemplates -ne $null)
		{
			foreach($QuotaTemplate in $ConfigurationData.NonNodeData.SharePoint.Farm.QuotaTemplates) 
			{
				# https://github.com/PowerShell/SharePointDsc/wiki/SPQuotaTemplate
				SPQuotaTemplate $QuotaTemplate.Name
				{
					Name = $QuotaTemplate.Name
					StorageMaxInMB = $QuotaTemplate.StorageMaxInMB
					StorageWarningInMB = $QuotaTemplate.StorageWarningInMB
					MaximumUsagePointsSolutions = $QuotaTemplate.MaximumUsagePointsSolutions
					WarningUsagePointsSolutions = $QuotaTemplate.WarningUsagePointsSolutions
					Ensure = $QuotaTemplate.Ensure
				}
			}
		}

		# Incoming Email Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPIncomingEmailSettings
			SPIncomingEmailSettings IncomingEmailSettings
			{
				DLsRequireAuthenticatedSenders = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.DLsRequireAuthenticatedSenders
				DistributionGroupsEnabled = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.DistributionGroupsEnabled
				DropFolder = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.DropFolder
				IsSingleInstance     = "Yes"
				RemoteDirectoryManagementURL = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.RemoteDirectoryManagementURL
				ServerAddress = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.ServerAddress
				ServerDisplayAddress = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.ServerDisplayAddress
				UseAutomaticSettings = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.UseAutomaticSettings
				UseDirectoryManagementService = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.UseDirectoryManagementService
				Ensure = $ConfigurationData.NonNodeData.SharePoint.Farm.IncomingEmailSettings.Ensure
			}
		}

		# Outgoing Email Settings (Farm Wide, configured using Central Administration Url)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.OutgoingEmailSettings -ne $null -and $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Url -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPOutgoingEmailSettings
			SPOutgoingEmailSettings FarmWideOutgoingEmailSettings
			{
				WebAppUrl = "$($ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Url):$($ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdministration.Port)"
				SMTPServer = $ConfigurationData.NonNodeData.SharePoint.Farm.OutgoingEmailSettings.SMTPServer
				FromAddress = $ConfigurationData.NonNodeData.SharePoint.Farm.OutgoingEmailSettings.FromAddress
				ReplyToAddress = $ConfigurationData.NonNodeData.SharePoint.Farm.OutgoingEmailSettings.ReplyToAddress
				CharacterSet = $ConfigurationData.NonNodeData.SharePoint.Farm.OutgoingEmailSettings.CharacterSet
			}
		}
		# Office Online Server (OOS) Bindings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.OfficeOnlineServerBindings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPOfficeOnlineServerBinding
			SPOfficeOnlineServerBinding OfficeOnlineServerBindings
			{
				Zone = $ConfigurationData.NonNodeData.SharePoint.Farm.OfficeOnlineServerBindings.Zone
				DnsName = $ConfigurationData.NonNodeData.SharePoint.Farm.OfficeOnlineServerBindings.DnsName
				Ensure = $ConfigurationData.NonNodeData.SharePoint.Farm.OfficeOnlineServerBindings.Ensure
			}
		}

		# Anti Virus Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPAntivirusSettings
			SPAntivirusSettings AntiVirusSettings
			{
				IsSingleInstance = "Yes"
				ScanOnDownload = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.ScanOnDownload
				ScanOnUpload = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.ScanOnUpload
				AllowDownloadInfected = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.AllowDownloadInfected
				AttemptToClean = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.AttemptToClean
				NumberOfThreads = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.NumberOfThreads
				TimeoutDuration = $ConfigurationData.NonNodeData.SharePoint.Farm.AntiVirusSettings.TimeoutDuration
			}
		}

		# IRM Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.IrmSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPIrmSettings
			SPIrmSettings IrmSettings
			{
				IsSingleInstance = "Yes"
				RMSserver = $ConfigurationData.NonNodeData.SharePoint.Farm.IrmSettings.RMSserver
				Ensure = 'Present'
			}
		}
		else
		{
			SPIrmSettings IrmSettings
			{
				IsSingleInstance = "Yes"
				Ensure = 'Absent'
			}
		}

		# Password Change Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.PasswordChangeSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPPasswordChangeSettings
			SPPasswordChangeSettings PasswordChangeSettings
			{
				IsSingleInstance = "Yes"
				MailAddress = $ConfigurationData.NonNodeData.SharePoint.Farm.PasswordChangeSettings.MailAddress
				DaysBeforeExpiry = $ConfigurationData.NonNodeData.SharePoint.Farm.PasswordChangeSettings.DaysBeforeExpiry
				PasswordChangeWaitTimeSeconds = $ConfigurationData.NonNodeData.SharePoint.Farm.PasswordChangeSettings.PasswordChangeWaitTimeSeconds
				NumberOfRetries = $ConfigurationData.NonNodeData.SharePoint.Farm.PasswordChangeSettings.NumberOfRetries
			}
		}

		# Distributed Cache Client Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPDistributedCacheClientSettings
			SPDistributedCacheClientSettings DistributedCacheClientSettings
			{
				IsSingleInstance            = "Yes"
				DLTCMaxConnectionsToServer  = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DLTCMaxConnectionsToServer
				DLTCRequestTimeout          = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DLTCRequestTimeout
				DLTCChannelOpenTimeOut      = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DLTCChannelOpenTimeOut
				DVSCMaxConnectionsToServer  = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DVSCMaxConnectionsToServer
				DVSCRequestTimeout          = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DVSCRequestTimeout
				DVSCChannelOpenTimeOut      = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DVSCChannelOpenTimeOut
				DACMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DACMaxConnectionsToServer
				DACRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DACRequestTimeout
				DACChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DACChannelOpenTimeOut
				DAFMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFMaxConnectionsToServer
				DAFRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFRequestTimeout
				DAFChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFChannelOpenTimeOut
				DAFCMaxConnectionsToServer  = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFCMaxConnectionsToServer
				DAFCRequestTimeout          = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFCRequestTimeout
				DAFCChannelOpenTimeOut      = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DAFCChannelOpenTimeOut
				DBCMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DBCMaxConnectionsToServer
				DBCRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DBCRequestTimeout
				DBCChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DBCChannelOpenTimeOut
				DDCMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DDCMaxConnectionsToServer
				DDCRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DDCRequestTimeout
				DDCChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DDCChannelOpenTimeOut
				DSCMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSCMaxConnectionsToServer
				DSCRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSCRequestTimeout
				DSCChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSCChannelOpenTimeOut
				DTCMaxConnectionsToServer   = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DTCMaxConnectionsToServer
				DTCRequestTimeout           = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DTCRequestTimeout
				DTCChannelOpenTimeOut       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DTCChannelOpenTimeOut
				DSTACMaxConnectionsToServer = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSTACMaxConnectionsToServer
				DSTACRequestTimeout         = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSTACRequestTimeout
				DSTACChannelOpenTimeOut     = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheClientSettings.DSTACChannelOpenTimeOut
			}
		}

		# Farm Property Bag Items
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.PropertyBag -ne $null)
		{
			foreach($PropertyBagItem in $ConfigurationData.NonNodeData.SharePoint.Farm.PropertyBag) 
			{
				$PropertyBagItemKeyNoSpace = $PropertyBagItem.Key.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPFarmPropertyBag
				SPFarmPropertyBag ('FarmPropertyBag_' + $PropertyBagItemKeyNoSpace)
				{
					Key = $PropertyBagItem.Key
					Value = $PropertyBagItem.Value
					Ensure = $PropertyBagItem.Ensure
				}
			}
		}

		# Remote Farm Trust(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.RemoteFarmTrusts -ne $null)
		{
			foreach($RemoteFarmTrust in $ConfigurationData.NonNodeData.SharePoint.Farm.RemoteFarmTrusts) 
			{
				# https://github.com/PowerShell/SharePointDsc/wiki/SPRemoteFarmTrust
				SPRemoteFarmTrust ('RemoteFarmTrust_' + $RemoteFarmTrust.Name)
				{
					Name = $RemoteFarmTrust.Name
					RemoteWebAppUrl = $RemoteFarmTrust.RemoteWebAppUrl
					LocalWebAppUrl = $RemoteFarmTrust.LocalWebAppUrl
					Ensure = $RemoteFarmTrust.Ensure
				}
			}
		}

		# Deploy Farm Solutions
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.FarmSolutions -ne $null)
		{
			foreach($FarmSolution in $ConfigurationData.NonNodeData.SharePoint.Farm.FarmSolutions) 
			{
				$FarmSolutionNameNoSpaces = $FarmSolution.Name.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPFarmSolution
				SPFarmSolution ("FarmSolution_" + $FarmSolutionNameNoSpaces)
				{
					Name = $FarmSolution.Name
					LiteralPath = $FarmSolution.LiteralPath
					SolutionLevel = $FarmSolution.SolutionLevel
					Version = $FarmSolution.Version
					WebAppUrls = $FarmSolution.WebAppUrls
					Ensure = $FarmSolution.Ensure
				}
			}
		}

		# Create Web Application(s)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.WebApplications -ne $null)
		{
			foreach($WebApplication in $ConfigurationData.NonNodeData.SharePoint.Farm.WebApplications)
			{
				$WebApplicationNameNoSpaces = $WebApplication.Name.Replace(' ', '')

				SharePointServerWebApplication ("WebAppliation_" + $WebApplicationNameNoSpaces)
				{
					WebApplication = $WebApplication
				}
			}
		}

		# Timer Job State (Farm Level)
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.TimerJobStates -ne $null)
		{
			foreach($TimerJobState in $ConfigurationData.NonNodeData.SharePoint.Farm.TimerJobStates) 
			{
				$TimerJobStateName = "TimerJobState_Farm_" + $TimerJobState.TypeName

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPTimerJobState
				SPTimerJobState $TimerJobStateName
				{
					Enabled = $TimerJobState.Enabled
					Schedule = $TimerJobState.Schedule
					TypeName = $TimerJobState.TypeName
					WebAppUrl = 'N/A'
				}
			}
		}

		# InfoPath Forms Service Config
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig -ne $null)
		{
			# https://github.com/dsccommunity/SharePointDsc/wiki/SPInfoPathFormsServiceConfig
			SPInfoPathFormsServiceConfig InfoPathFormsServiceConfig
			{
				IsSingleInstance = 'Yes'
				AllowUserFormBrowserEnabling = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.AllowUserFormBrowserEnabling
				AllowUserFormBrowserRendering = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.AllowUserFormBrowserRendering
				MaxDataConnectionTimeout = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.MaxDataConnectionTimeout
				DefaultDataConnectionTimeout = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.DefaultDataConnectionTimeout
				MaxDataConnectionResponseSize = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.MaxDataConnectionResponseSize
				RequireSslForDataConnections = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.RequireSslForDataConnections
				AllowEmbeddedSqlForDataConnections = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.AllowEmbeddedSqlForDataConnections
				AllowUdcAuthenticationForDataConnections = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.AllowUdcAuthenticationForDataConnections
				AllowUserFormCrossDomainDataConnections = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.AllowUserFormCrossDomainDataConnections
				MaxPostbacksPerSession = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.MaxPostbacksPerSession
				MaxUserActionsPerPostback = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.MaxUserActionsPerPostback
				ActiveSessionsTimeout = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.ActiveSessionsTimeout
				MaxSizeOfUserFormState = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.MaxSizeOfUserFormState
				Ensure = $ConfigurationData.NonNodeData.SharePoint.Farm.InfoPathFormsServiceConfig.Ensure
			}
		}

		# Search Service Settings
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.SearchServiceSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchServiceSettings
			SPSearchServiceSettings SearchServiceSettings
			{
				IsSingleInstance = "Yes"
				PerformanceLevel = $ConfigurationData.NonNodeData.SharePoint.Farm.SearchServiceSettings.PerformanceLevel
				ContactEmail = $ConfigurationData.NonNodeData.SharePoint.Farm.SearchServiceSettings.ContactEmail
				WindowsServiceAccount = $ConfigurationData.NonNodeData.SharePoint.Farm.SearchServiceSettings.WindowsServiceAccount
			}
		}
	}

	# User Profile Service Application(s) are provisioned after Web Applications, 
	# as the My Site Host URL needs to exist

	# User Profile Service Application
	if ($ConfigurationData.NonNodeData.SharePoint.Farm.UserProfileServices -ne $null)
	{
		foreach($UserProfileService in $ConfigurationData.NonNodeData.SharePoint.Farm.UserProfileServices) 
		{
			# Seek My Site Host Site Collections
			foreach($WebApplication in $ConfigurationData.NonNodeData.SharePoint.Farm.WebApplications)
			{
				foreach ($ContentDatabase in $WebApplication.ContentDatabases)
				{
					$SiteCollection = $ContentDatabase.SiteCollections | ? { $_.Url -eq $UserProfileService.MySiteHostLocation }

					if ($SiteCollection -ne $null)
					{
						break
					}
				}
			}
			# My Site Host Site Collection Tests
			if ($SiteCollection -eq $null)
			{
				throw [Exception] "Unable to locate My Site Host Site Collection '$($UserProfileService.MySiteHostLocation)' for User Profile Service '$($UserProfileService.Name)'."
			}
			else
			{
				if ($SiteCollection.Template -ne 'SPSMSITEHOST#0')
				{
					throw [Exception] "The My Site Host Site Collection '$($UserProfileService.MySiteHostLocation)' for User Profile Service '$($UserProfileService.Name)' must use Site Template 'SPSMSITEHOST#0' (currently '$($SiteCollection.Template)')."
				}
			}

			# My Site Host Web Application Tests
			if ($WebApplication -eq $null)
			{
				throw [Exception] "Web Application Context for the My Site Host Site Collection '$($UserProfileService.MySiteHostLocation)' for User Profile Service '$($UserProfileService.Name)' to evaluate Managed Path Configuration."
			}
			else
			{
				$WebAppManagedPath = $WebApplication.ManagedPaths | ? { $_.RelativeUrl -eq $UserProfileService.MySiteManagedPath}
				if ($WebAppManagedPath -eq $null)
				{
					throw [Exception] "The My Site Managed Path '$($UserProfileService.MySiteManagedPath)' for User Profile Service '$($UserProfileService.Name)' was not found on the My Site Host Web Application '$($WebApplication.WebAppUrl)'."
				}
				else
				{
					if ($WebAppManagedPath.Explicit -eq $null -or $WebAppManagedPath.Explicit -eq $true)
					{
						throw [Exception] "The My Site Managed Path '$($UserProfileService.MySiteManagedPath)' for User Profile Service '$($UserProfileService.Name)' in My Site Host Web Application '$($WebApplication.WebAppUrl)' must be defined as a wildcard inclusion Managed Path (Explicit = `$false)."
					}
				}
			}
			
			$UserProfileServiceNoSpaces = $UserProfileService.Name.Replace(' ', '')

			if ($Node.NodeName -eq $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) 
			{
				# https://github.com/PowerShell/SharePointDsc/wiki/SPUserProfileServiceApp
				SPUserProfileServiceApp $UserProfileServiceNoSpaces 
				{
					Name = $UserProfileService.Name
					ProxyName = $UserProfileService.ProxyName
					ApplicationPool = $UserProfileService.ApplicationPool
					MySiteHostLocation = $UserProfileService.MySiteHostLocation
					MySiteManagedPath = $UserProfileService.MySiteManagedPath
					ProfileDBName = $UserProfileService.ProfileDBName
					ProfileDBServer = $UserProfileService.ProfileDBServer
					SocialDBName = $UserProfileService.SocialDBName
					SocialDBServer = $UserProfileService.SocialDBServer
					SyncDBName = $UserProfileService.SyncDBName
					SyncDBServer = $UserProfileService.SyncDBServer
					EnableNetBIOS = $UserProfileService.EnableNetBIOS
					NoILMUsed = $UserProfileService.NoILMUsed
					SiteNamingConflictResolution = $UserProfileService.SiteNamingConflictResolution
					Ensure = $UserProfileService.Ensure
				}

				if ($UserProfileService.Ensure -eq 'Present')
				{
					$PublishServiceApplicationEnsure = 'Absent'
					if ($UserProfileService.PublishService -ne $null -and $UserProfileService.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($UserProfileServiceNoSpaces + '_PublishServiceApplication')
					{
						Name = $UserProfileService.Name
						Ensure = $PublishServiceApplicationEnsure
					}

					if ($UserProfileService.Permissions -ne $null)
					{
						if ($UserProfileService.ProxyName -ne $null)
						{
							$UserProfileServiceProxyName = $UserProfileService.ProxyName
						}
						else
						{
							$UserProfileServiceProxyName = $UserProfileService.Name + ' Proxy'
						}

						# https://github.com/dsccommunity/SharePointDsc/wiki/SPUserProfileServiceAppPermissions
						SPUserProfileServiceAppPermissions ($UserProfileServiceNoSpaces + '_UPAPermissions')
						{
							ProxyName = $UserProfileServiceProxyName
							CreatePersonalSite = $UserProfileService.Permissions.CreatePersonalSite
							FollowAndEditProfile = $UserProfileService.Permissions.FollowAndEditProfile
							UseTagsAndNotes= $UserProfileService.Permissions.UseTagsAndNotes
						}
					}
				}
			}
			# User Profile Sync Service
			if ($UserProfileService.SyncServiceNodes -ne $null)
			{
				# Only SharePoint 2013 is supported to deploy the user profile sync service via DSC, as 2016/2019 do not use the FIM based sync service. 
				if ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion -ne '2013')
				{
					throw [Exception] "User Profile Synchronization Service is only available in SharePoint 2013 and cannot be created in SharePoint $($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion) (SyncServiceNodes cannot be specified in the Configuration Data File)."
				}

				if ($ConfigurationData.NonNodeData.SharePoint.Farm.SharePointVersion -ne '2013')
				{
					throw [Exception] "Only SharePoint 2013 is supported to deploy the user profile sync service via DSC, as 2016/2019 do not use the FIM based sync service (SyncServiceNodes must be `$null)"
				}

				$UserProfileSyncServiceEnsure = 'Absent'
				if ($UserProfileService.SyncServiceNodes.Contains($ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode))
				{
					$UserProfileSyncServiceEnsure = 'Present'
				}

				# https://github.com/dsccommunity/SharePointDsc/wiki/SPUserProfileSyncService
				# This call is type SPECIFIC (thus outside $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode)
				SPUserProfileSyncService UserProfileSyncService
				{
					UserProfileServiceAppName = $UserProfileService.Name
					Ensure                    = $UserProfileSyncServiceEnsure
					RunOnlyWhenWriteable      = $true
				}
			}

			if ($Node.NodeName -eq $ConfigurationData.NonNodeData.SharePoint.Farm.DistributionNode) 
			{
				if ($UserProfileService.Connections -ne $null)
				{
					foreach ($UserProfileServiceConnection in $UserProfileService.Connections)
					{
						$UserProfileServiceConnectionNoSpaces = $UserProfileServiceNoSpaces + '_Connection_' + $UserProfileServiceConnection.Name.Replace(' ', '_')

						$objConnectionAccountPassword = $UserProfileServiceConnection.ConnectionCredentials.Password | ConvertTo-SecureString -AsPlainText -Force
						$objConnectionCredential = New-Object System.Management.Automation.PSCredential($UserProfileServiceConnection.ConnectionCredentials.Account, $objConnectionAccountPassword)
    
						# https://github.com/dsccommunity/SharePointDsc/wiki/SPUserProfileSyncConnection
						SPUserProfileSyncConnection $UserProfileServiceConnectionNoSpaces
						{
							Name = $UserProfileServiceConnection.Name
							UserProfileService = $UserProfileService.Name
							Forest = $UserProfileServiceConnection.Forest
							ConnectionCredentials = $objConnectionCredential
							Server = $UserProfileServiceConnection.Server
							UseSSL = $UserProfileServiceConnection.UseSSL
							IncludedOUs = $UserProfileServiceConnection.IncludedOUs
							ExcludedOUs = $UserProfileServiceConnection.ExcludedOUs
							Force = $UserProfileServiceConnection.Force
							ConnectionType = $UserProfileServiceConnection.ConnectionType
							Ensure = $UserProfileServiceConnection.Ensure
						}
					}
				}

				if ($UserProfileService.Sections -ne $null)
				{
					foreach ($UserProfileServiceSection in $UserProfileService.Sections)
					{
						$UserProfileServiceSectionNoSpaces = $UserProfileServiceNoSpaces + '_Section_' + $UserProfileServiceSection.Name.Replace(' ', '_')

						# https://github.com/dsccommunity/SharePointDsc/wiki/SPUserProfileSection
						SPUserProfileSection $UserProfileServiceSectionNoSpaces
						{
							Name = $UserProfileServiceSection.Name
							DisplayName = $UserProfileServiceSection.DisplayName
							DisplayOrder = $UserProfileServiceSection.DisplayOrder
							UserProfileService = $UserProfileService.Name
							Ensure = $UserProfileServiceSection.Ensure
						}
					}
				}

				if ($UserProfileService.Properties -ne $null)
				{
					foreach ($UserProfileServiceProperty in $UserProfileService.Properties)
					{
						$UserProfileServicePropertyNoSpaces = $UserProfileServiceNoSpaces + '_Property_' + $UserProfileServiceProperty.Name.Replace(' ', '_')

						$UserProfileServicePropertyMapping = $null
						if ($UserProfileServiceProperty.PropertyMappings -ne $null)
						{
							$UserProfileServicePropertyMapping = MSFT_SPUserProfilePropertyMapping {
									ConnectionName = $UserProfileServiceProperty.PropertyMappings.ConnectionName
									PropertyName   = $UserProfileServiceProperty.PropertyMappings.PropertyName
									Direction      = $UserProfileServiceProperty.PropertyMappings.Direction
								}
						}

						# https://github.com/dsccommunity/SharePointDsc/wiki/SPUserProfileProperty
						SPUserProfileProperty $UserProfileServicePropertyNoSpaces
						{
							Name = $UserProfileServiceProperty.Name
							UserProfileService = $UserProfileService.Name
							DisplayName = $UserProfileServiceProperty.DisplayName
							Type = $UserProfileServiceProperty.Type
							Description = $UserProfileServiceProperty.Description #implementation isn't using it yet
							PolicySetting = $UserProfileServiceProperty.PolicySetting
							PrivacySetting = $UserProfileServiceProperty.PrivacySetting
							PropertyMappings = $UserProfileServicePropertyMapping
							Length               = $UserProfileServiceProperty.Length
							DisplayOrder         = $UserProfileServiceProperty.DisplayOrder
							IsEventLog           = $UserProfileServiceProperty.IsEventLog
							IsVisibleOnEditor    = $UserProfileServiceProperty.IsVisibleOnEditor
							IsVisibleOnViewer    = $UserProfileServiceProperty.IsVisibleOnViewer
							IsUserEditable       = $UserProfileServiceProperty.IsUserEditable
							IsAlias              = $UserProfileServiceProperty.IsAlias
							IsSearchable         = $UserProfileServiceProperty.IsSearchable
							IsReplicable         = $UserProfileServiceProperty.IsReplicable
							TermStore            = $UserProfileServiceProperty.TermStore
							TermGroup            = $UserProfileServiceProperty.TermGroup
							TermSet              = $UserProfileServiceProperty.TermSet
							UserOverridePrivacy = $UserProfileServiceProperty.UserOverridePrivacy
							Ensure = $UserProfileServiceProperty.Ensure
						}
					}
				}
			}
		}
	}

	# Reboot after Node Configuration
    PendingReboot RebootAfterNodeConfiguration {
        Name = 'RebootAfterNodeConfiguration'
		SkipCcmClientSDK = $true
    }
}