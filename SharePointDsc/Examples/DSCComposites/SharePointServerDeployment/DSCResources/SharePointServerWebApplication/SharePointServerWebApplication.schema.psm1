Configuration SharePointServerWebApplication
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$WebApplication
    )

    Import-DscResource -ModuleName SharePointServerDeployment
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0

    $WebApplicationNameNoSpaces = $WebApplication.Name.Replace(' ', '')

	#Validate Web application
	
	if ($WebApplication.ContentDatabases -eq $null -or $WebApplication.ContentDatabases.Count -eq 0)
	{
		throw "Web Application '$($WebApplication.Name)' must have at least one Content Database."
	}
                
	# https://docs.microsoft.com/en-us/SharePoint/administration/host-named-site-collection-architecture-and-deployment#deployment-and-configuration-for-host-named-site-collections
	# A root site collection is a requirement for any Web application. It is also necessary for crawling content. This site collection must have the same URL as the Web application. 
	# Currently, SharePoint prevents the creation of a host-named site collection with the same URL as a Web application. Therefore, the root site collection is created as a path-based site collection.
	$RootSiteCollection = $null
	foreach ($ContentDatabase in $WebApplication.ContentDatabases)
	{
		foreach ($SiteCollection in $ContentDatabase.SiteCollections)
		{
			if ($SiteCollection.Url -ceq $WebApplication.WebAppUrl) # Case Sensitive, match
			{
				if ($SiteCollection.HostNamedSiteCollection -ne $null -and $SiteCollection.HostNamedSiteCollection -eq $true)
				{
					throw "Root Site Collection '$($SiteCollection.Url)' must be a path-based site collection (HostNamedSiteCollection cannot be true)."
				}

				$RootSiteCollection = $SiteCollection
			}
			elseif ($SiteCollection.Url -eq $WebApplication.WebAppUrl) # Match by Url, but not Case Sensitive match
			{
				throw "Root Site Collection Url '$($SiteCollection.Url)' must match Web Application Url with case sensitivity '$($WebApplication.WebAppUrl)'."
			}
		}
	}

	if ($RootSiteCollection -eq $null)
	{
		throw "Web Application '$($WebApplication.Name)' must have a root site collection with the same URL (case sensitive) as the Web Application ('$($WebApplication.WebAppUrl)')."
	}

    #Create the Web Application

    $HostHeader = $null
    if ($WebApplication.UseHostNamedSiteCollections -eq $false) {
        # NOTE: When using Host Header Site Collections, do not use the HostHeader parameter in SPWebApplication. 
        # This will set the specified host header on your IIS site and prevent the site from listening for the URL of the Host Header Site Collection. 
        $HostHeader = [Uri]::new($WebApplication.WebAppUrl).Host
    }    

    $ApplicationPoolAccountManaged = $ConfigurationData.NonNodeData.SharePoint.Farm.ManagedAccounts | ? { $_.Account -eq $WebApplication.ApplicationPoolAccount }
    if ($ApplicationPoolAccountManaged -eq $null)
    {
        throw [Exception] "Managed Account must exists for account '$($WebApplication.ApplicationPoolAccount)' to run the Application Pool '$($WebApplication.ApplicationPool)' for Web Application '$($WebApplication.Name)'."
	}

	# https://github.com/PowerShell/SharePointDsc/wiki/SPWebApplication
    SPWebApplication $WebApplicationNameNoSpaces 
	{
        Name = $WebApplication.Name
        ApplicationPool = $WebApplication.ApplicationPool
        ApplicationPoolAccount = $WebApplication.ApplicationPoolAccount
        AllowAnonymous = $WebApplication.AllowAnonymous
        DatabaseName = $WebApplication.ContentDatabases[0].Name
        DatabaseServer = $WebApplication.ContentDatabases[0].DatabaseServer
        WebAppUrl = $WebApplication.WebAppUrl
        HostHeader = $HostHeader
        Port = $WebApplication.Port
        Path = $WebApplication.Path
		Ensure = $WebApplication.Ensure
    }
 
	if ($WebApplication.Ensure -eq 'Present') 
	{
		if ($WebApplication.Permissions -ne $null)
		{
			if ($WebApplication.Permissions.AllPermissions -eq $true)
			{
				if ($WebApplication.Permissions.ListPermissions -ne $null -or $WebApplication.Permissions.SitePermissions -ne $null -or $WebApplication.Permissions.PersonalPermissions -ne $null)
				{
					throw [Exception] "ListPermissions, SitePermissions and PersonalPermissions cannot be specified when AllPermissions is True for Web Application '$($WebApplication.Name)' Permissions."
				}
			}
			elseif ($WebApplication.Permissions.AllPermissions -eq $false)
			{
				if ($WebApplication.Permissions.ListPermissions -eq $null -or $WebApplication.Permissions.SitePermissions -eq $null -or $WebApplication.Permissions.PersonalPermissions -eq $null)
				{
					throw [Exception] "ListPermissions, SitePermissions and PersonalPermissions must all be specified when AllPermissions is False for Web Application '$($WebApplication.Name)' Permissions."
				}
			}
			else
			{
				throw [Exception] "AllPermissions is must be set to True or False for Web Application '$($WebApplication.Name)' Permissions."
			}

			if ($WebApplication.Permissions.AllPermissions -eq $true)
			{
				# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebAppPermissions
				SPWebAppPermissions ($WebApplicationNameNoSpaces + '_WebApplicationPermissions')
				{
					WebAppUrl = $WebApplication.WebAppUrl
					AllPermissions = $true
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
			else
			{
				# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebAppPermissions
				SPWebAppPermissions ($WebApplicationNameNoSpaces + '_WebApplicationPermissions')
				{
					WebAppUrl = $WebApplication.WebAppUrl
					ListPermissions = $WebApplication.Permissions.ListPermissions
					SitePermissions = $WebApplication.Permissions.SitePermissions
					PersonalPermissions = $WebApplication.Permissions.PersonalPermissions
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}

		if ($WebApplication.Policy -ne $null)
		{
			if ($WebApplication.Policy.Members -eq $null -and $WebApplication.Policy.MembersToInclude -eq $null -and $WebApplication.Policy.MembersToExclude -eq $null)
			{
				throw [Exception] "Members, or both MembersToInclude and MembersToExclude, must be specified for Web Application '$($WebApplication.Name)' Policy."
			}
			elseif ($WebApplication.Policy.Members -ne $null -and $WebApplication.Policy.MembersToInclude -ne $null -and $WebApplication.Policy.MembersToExclude -ne $null)
			{
				throw [Exception] "Only Members, or both MembersToInclude and MembersToExclude, can be specified for Web Application '$($WebApplication.Name)' Policy."
			}
			elseif ($WebApplication.Policy.Members -eq $null -and ($WebApplication.Policy.MembersToInclude -eq $null -or $WebApplication.Policy.MembersToExclude -eq $null))
			{
				throw [Exception] "Both MembersToInclude and MembersToExclude should be specified for Web Application '$($WebApplication.Name)' Policy."
			}
			elseif ($WebApplication.Policy.Members -ne $null -and ($WebApplication.Policy.MembersToInclude -ne $null -or $WebApplication.Policy.MembersToExclude -ne $null))
			{
				throw [Exception] "MembersToInclude or MembersToExclude cannot be specified when using Members Web Application '$($WebApplication.Name)' Policy."
			}

			$WebApplicationPolicyMembers = $null
			$WebApplicationPolicyMembersToInclude = $null
			$WebApplicationPolicyMembersToExclude = $null
			if ($WebApplication.Policy.Members -ne $null)
			{
				$WebApplicationPolicyMembers = @()
				
				foreach ($Member in $WebApplication.Policy.Members)
				{
					$WebApplicationPolicyMembers += MSFT_SPWebPolicyPermissions
					{
						ActAsSystemAccount = $Member.ActAsSystemAccount
						PermissionLevel = $Member.PermissionLevel
						IdentityType = $Member.IdentityType
						Username = $Member.Username
					}
				}
			}

			if ($WebApplication.Policy.MembersToInclude -ne $null)
			{
				$WebApplicationPolicyMembersToInclude = @()

				foreach ($MemberToInclude in $WebApplication.Policy.MembersToInclude)
				{
					$WebApplicationPolicyMembersToInclude += MSFT_SPWebPolicyPermissions
					{
						ActAsSystemAccount = $MemberToInclude.ActAsSystemAccount
						PermissionLevel = $MemberToInclude.PermissionLevel
						IdentityType = $MemberToInclude.IdentityType
						Username = $MemberToInclude.Username
					}
				}
			}

			if ($WebApplication.Policy.MembersToExclude -ne $null)
			{
				$WebApplicationPolicyMembersToExclude = @()
				
				foreach ($MemberToExclude in $WebApplication.Policy.MembersToExclude)
				{
					$WebApplicationPolicyMembersToExclude += MSFT_SPWebPolicyPermissions
					{
						Username = $MemberToExclude.Username
					}
				}
			}

			# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebAppPolicy
			SPWebAppPolicy ($WebApplicationNameNoSpaces + '_WebApplicationPolicy')
            {
                WebAppUrl = $WebApplication.WebAppUrl
				SetCacheAccountsPolicy = $WebApplication.Policy.SetCacheAccountsPolicy
                Members = $WebApplicationPolicyMembers
				MembersToInclude = $WebApplicationPolicyMembersToInclude
                MembersToExclude = $WebApplicationPolicyMembersToExclude
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}

		if ($WebApplication.Zones -eq $null)
		{
			throw "Zones must be defined for Web Application '$($WebApplication.WebAppUrl)'."
		}

		#  Let's ensure we have the Default zone defined
		$DefaultZone = $WebApplication.Zones | ? { $_.Name -eq 'Default' }
		if ($DefaultZone -eq $null)
		{
			throw "The Default Zone of Web Application '$($WebApplication.WebAppUrl)' must be defined."
		}

		$DefaultZone = $null
		$IntranetZone = $null
		$InternetZone = $null
		$ExtranetZone = $null
		$CustomZone = $null
		foreach ($Zone in $WebApplication.Zones)
		{
			switch ($Zone.Name)
			{
				'Default' {
					if ($DefaultZone -ne $null) {
						throw [Exception] "Default Zone already exists in Web Application '$($WebApplication.WebAppUrl)'."
					}

					$DefaultZone = $Zone
					break
				}
				'Intranet' {
					if ($IntranetZone -ne $null) {
						throw [Exception] "Intranet Zone already exists in Web Application '$($WebApplication.WebAppUrl)'."
					}

					$IntranetZone = $Zone
					break
				}
				'Internet' {
					if ($InternetZone -ne $null) {
						throw [Exception] "Internet Zone already exists in Web Application '$($WebApplication.WebAppUrl)'."
					}

					$InternetZone = $Zone
					break
				}
				'Extranet' {
					if ($ExtranetZone -ne $null) {
						throw [Exception] "Extranet Zone already exists in Web Application '$($WebApplication.WebAppUrl)'."
					}

					$ExtranetZone = $Zone
					break
				}
				'Custom' {
					if ($CustomZone -ne $null) {
						throw [Exception] "Custom Zone already exists in Web Application '$($WebApplication.WebAppUrl)'."
					}

					$CustomZone = $Zone
					break
				}
			}

			if ($Zone.Extension -ne $null)
			{
				$WebApplicationExtensionNameNoSpaces = $WebApplicationNameNoSpaces + "_" + $Zone.Name.Replace(' ', '') + "_" + $Zone.Extension.Name.Replace(' ', '') + "_Extension"
			
				# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebApplicationExtension
				SPWebApplicationExtension $WebApplicationExtensionNameNoSpaces
				{
					WebAppUrl              = $WebApplication.WebAppUrl
					Zone                   = $Zone.Name
					Name                   = $Zone.Extension.Name
					AllowAnonymous         = $Zone.Extension.AllowAnonymous
					Url                    = $Zone.Extension.Url
					HostHeader             = $Zone.Extension.HostHeader
					Path                   = $Zone.Extension.Path
					UseSSL                 = $Zone.Extension.UseSSL
					Port                   = $Zone.Extension.Port
					Ensure                 = $Zone.Extension.Ensure
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}

		$AuthenticationDefaultZone = $null
		$AuthenticationIntranetZone = $null
		$AuthenticationInternetZone = $null
		$AuthenticationExtranetZone = $null
		$AuthenticationCustomZone = $null

		$AuthenticationDefaultZone = @(
			MSFT_SPWebAppAuthenticationMode {
				AuthenticationMethod = $DefaultZone.Authentication.AuthenticationMethod
				AuthenticationProvider = $DefaultZone.Authentication.AuthenticationProvider
				MembershipProvider = $DefaultZone.Authentication.MembershipProvider
				RoleProvider = $DefaultZone.Authentication.RoleProvider
			}
		)

		if ($IntranetZone -ne $null)
		{
			$AuthenticationIntranetZone = @(
				MSFT_SPWebAppAuthenticationMode {
					AuthenticationMethod = $IntranetZone.Authentication.AuthenticationMethod
					AuthenticationProvider = $IntranetZone.Authentication.AuthenticationProvider
					MembershipProvider = $IntranetZone.Authentication.MembershipProvider
					RoleProvider = $IntranetZone.Authentication.RoleProvider
				}
			)
		}

		if ($InternetZone -ne $null)
		{
			$AuthenticationInternetZone = @(
				MSFT_SPWebAppAuthenticationMode {
					AuthenticationMethod = $InternetZone.Authentication.AuthenticationMethod
					AuthenticationProvider = $InternetZone.Authentication.AuthenticationProvider
					MembershipProvider = $InternetZone.Authentication.MembershipProvider
					RoleProvider = $InternetZone.Authentication.RoleProvider
				}
			)
		}

		if ($ExtranetZone -ne $null)
		{
			$AuthenticationExtranetZone = @( 
				MSFT_SPWebAppAuthenticationMode {
					AuthenticationMethod = $ExtranetZone.Authentication.AuthenticationMethod
					AuthenticationProvider = $ExtranetZone.Authentication.AuthenticationProvider
					MembershipProvider = $ExtranetZone.Authentication.MembershipProvider
					RoleProvider = $ExtranetZone.Authentication.RoleProvider
				}
			)
		}

		if ($CustomZone -ne $null)
		{
			$AuthenticationCustomZone = @(
				MSFT_SPWebAppAuthenticationMode {
					AuthenticationMethod = $CustomZone.Authentication.AuthenticationMethod
					AuthenticationProvider = $CustomZone.Authentication.AuthenticationProvider
					MembershipProvider = $CustomZone.Authentication.MembershipProvider
					RoleProvider = $CustomZone.Authentication.RoleProvider
				}
			)
		}

		SPWebAppAuthentication ($WebApplicationNameNoSpaces + '_WebAppAuthentication')
		{
			WebAppUrl = $WebApplication.WebAppUrl
			Default = $AuthenticationDefaultZone
			Intranet = $AuthenticationIntranetZone
			Internet = $AuthenticationInternetZone
			Extranet = $AuthenticationExtranetZone
			Custom = $AuthenticationCustomZone
			DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
		}

		if ($WebApplication.AppDomains -ne $null)
		{
			if ($ConfigurationData.NonNodeData.SharePoint.Farm.AppDomain -eq $null -or $ConfigurationData.NonNodeData.SharePoint.Farm.AppDomain.Prefix -eq $null)
			{
				throw 'Farm AppDomain Prefix must be configured prior to setting Web Application App Domain(s)'
			}

			foreach ($WebApplicationAppDomain in $WebApplication.AppDomains)
			{
				$WebApplicationAppDomainNameNoSpaces = $WebApplicationNameNoSpaces + "_" + $WebApplicationAppDomain.AppDomain + "_AppDomain"
			
				# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebApplicationAppDomain
				SPWebApplicationAppDomain $WebApplicationAppDomainNameNoSpaces
				{
					AppDomain = $WebApplicationAppDomain.AppDomain
					WebAppUrl = $WebApplication.WebAppUrl
					Zone = $WebApplicationAppDomain.Zone
					Port = $WebApplicationAppDomain.Port
					SSL = $WebApplicationAppDomain.SSL
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}

		if ($WebApplication.GeneralSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppGeneralSettings
			SPWebAppGeneralSettings ($WebApplicationNameNoSpaces + '_WebAppGeneralSettings')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				TimeZone = $WebApplication.GeneralSettings.TimeZone
				Alerts = $WebApplication.GeneralSettings.Alerts
				AlertsLimit = $WebApplication.GeneralSettings.AlertsLimit
				RSS = $WebApplication.GeneralSettings.RSS
				BlogAPI = $WebApplication.GeneralSettings.BlogAPI
				BlogAPIAuthenticated = $WebApplication.GeneralSettings.BlogAPIAuthenticated
				BrowserFileHandling = $WebApplication.GeneralSettings.BrowserFileHandling
				SecurityValidation = $WebApplication.GeneralSettings.SecurityValidation
				SecurityValidationExpires = $WebApplication.GeneralSettings.SecurityValidationExpires
				SecurityValidationTimeOutMinutes = $WebApplication.GeneralSettings.SecurityValidationTimeOutMinutes
				RecycleBinEnabled = $WebApplication.GeneralSettings.RecycleBinEnabled
				RecycleBinCleanupEnabled = $WebApplication.GeneralSettings.RecycleBinCleanupEnabled
				SecondStageRecycleBinQuota = $WebApplication.GeneralSettings.SecondStageRecycleBinQuota
				MaximumUploadSize = $WebApplication.GeneralSettings.MaximumUploadSize
				CustomerExperienceProgram = $WebApplication.GeneralSettings.CustomerExperienceProgram
				AllowOnlineWebPartCatalog = $WebApplication.GeneralSettings.AllowOnlineWebPartCatalog
				SelfServiceSiteCreationEnabled = $WebApplication.GeneralSettings.SelfServiceSiteCreationEnabled
				PresenceEnabled = $WebApplication.GeneralSettings.PresenceEnabled
				DefaultQuotaTemplate = $WebApplication.GeneralSettings.DefaultQuotaTemplate
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		if ($WebApplication.SharePointDesigner -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPDesignerSettings
			SPDesignerSettings ($WebApplicationNameNoSpaces + "_SharePointDesigner") 
            {
                WebAppUrl = $WebApplication.WebAppUrl
                SettingsScope = "WebApplication"
                AllowSharePointDesigner = $SiteCollection.SharePointDesigner.AllowSharePointDesigner
                AllowDetachPagesFromDefinition = $SiteCollection.SharePointDesigner.AllowDetachPagesFromDefinition
                AllowCustomiseMasterPage = $SiteCollection.SharePointDesigner.AllowCustomiseMasterPage
                AllowManageSiteURLStructure = $SiteCollection.SharePointDesigner.AllowManageSiteURLStructure
                AllowCreateDeclarativeWorkflow = $SiteCollection.SharePointDesigner.AllowCreateDeclarativeWorkflow
                AllowSavePublishDeclarativeWorkflow = $SiteCollection.SharePointDesigner.AllowSavePublishDeclarativeWorkflow
                AllowSaveDeclarativeWorkflowAsTemplate = $SiteCollection.SharePointDesigner.AllowSaveDeclarativeWorkflowAsTemplate
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}


		if ($WebApplication.SiteUseAndDeletion -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppSiteUseAndDeletion
			SPWebAppSiteUseAndDeletion ($WebApplicationNameNoSpaces + '_SiteUseAndDeletion')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				SendUnusedSiteCollectionNotifications = $WebApplication.SiteUseAndDeletion.SendUnusedSiteCollectionNotifications
				UnusedSiteNotificationPeriod = $WebApplication.SiteUseAndDeletion.UnusedSiteNotificationPeriod
				AutomaticallyDeleteUnusedSiteCollections = $WebApplication.SiteUseAndDeletion.AutomaticallyDeleteUnusedSiteCollections
				UnusedSiteNotificationsBeforeDeletion = $WebApplication.SiteUseAndDeletion.UnusedSiteNotificationsBeforeDeletion
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		if ($WebApplication.SelfServiceSiteCreation -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPSelfServiceSiteCreation
			SPSelfServiceSiteCreation ($WebApplicationNameNoSpaces + '_SelfServiceSiteCreation')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				Enabled = $WebApplication.SelfServiceSiteCreation.Enabled
				OnlineEnabled = $WebApplication.SelfServiceSiteCreation.OnlineEnabled
				QuotaTemplate = $WebApplication.SelfServiceSiteCreation.QuotaTemplate
				ShowStartASiteMenuItem = $WebApplication.SelfServiceSiteCreation.ShowStartASiteMenuItem
				CreateIndividualSite = $WebApplication.SelfServiceSiteCreation.CreateIndividualSite
				PolicyOption = $WebApplication.SelfServiceSiteCreation.PolicyOption
				RequireSecondaryContact = $WebApplication.SelfServiceSiteCreation.RequireSecondaryContact
				CustomFormUrl = $WebApplication.SelfServiceSiteCreation.CustomFormUrl
				ManagedPath = $WebApplication.SelfServiceSiteCreation.ManagedPath
				AlternateUrl = $WebApplication.SelfServiceSiteCreation.AlternateUrl
				UserExperienceVersion = $WebApplication.SelfServiceSiteCreation.UserExperienceVersion
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		if ($WebApplication.SuiteBar -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppSuiteBar
			SPWebAppSuiteBar ($WebApplicationNameNoSpaces + '_SuiteBar')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				SuiteNavBrandingLogoNavigationUrl = $WebApplication.SuiteBar.SuiteNavBrandingLogoNavigationUrl
				SuiteNavBrandingLogoTitle = $WebApplication.SuiteBar.SuiteNavBrandingLogoTitle
				SuiteNavBrandingLogoUrl = $WebApplication.SuiteBar.SuiteNavBrandingLogoUrl
				SuiteNavBrandingText = $WebApplication.SuiteBar.SuiteNavBrandingText
				SuiteBarBrandingElementHtml = $WebApplication.SuiteBar.SuiteBarBrandingElementHtml
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		if ($WebApplication.AppStoreSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPAppStoreSettings
			SPAppStoreSettings ($WebApplicationNameNoSpaces + '_AppStoreSettings')
            {
                WebAppUrl = $WebApplication.WebAppUrl
                AllowAppPurchases = $WebApplication.AppStoreSettings.AllowAppPurchases
				AllowAppsForOffice = $WebApplication.AppStoreSettings.AllowAppsForOffice
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}
		
		if ($WebApplication.BlockedFileTypes -ne $null)
		{
			# Blocked File Type Validation
			if ($WebApplication.BlockedFileTypes.Blocked -eq $null -and
				$WebApplication.BlockedFileTypes.EnsureAllowed -eq $null -and
				$WebApplication.BlockedFileTypes.EnsureBlocked -eq $null)
			{
				throw "Utilize either Blocked or both EnsureAllowed and EnsureBlocked to define BlockedFileTypes."
			}
			elseif ($WebApplication.BlockedFileTypes.Blocked -ne $null)
			{
				if ($WebApplication.BlockedFileTypes.EnsureAllowed -ne $null -or $WebApplication.BlockedFileTypes.EnsureBlocked -ne $null)
				{
					throw "EnsureAllowed and EnsureBlocked cannot be utilized when using Blocked to define BlockedFileTypes."
				}
				else
				{
					# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppBlockedFileTypes
					SPWebAppBlockedFileTypes ($WebApplicationNameNoSpaces + '_BlockedFileTypes')
					{
						WebAppUrl = $WebApplication.WebAppUrl
						Blocked = $WebApplication.BlockedFileTypes.Blocked
						DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
					}
				}
			}
			else
			{
				if ($WebApplication.BlockedFileTypes.EnsureAllowed -eq $null -or $WebApplication.BlockedFileTypes.EnsureBlocked -eq $null)
				{
					throw "Both EnsureAllowed and EnsureBlocked should be utilized to define BlockedFileTypes."
				}
				else
				{
					# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppBlockedFileTypes
					SPWebAppBlockedFileTypes ($WebApplicationNameNoSpaces + '_BlockedFileTypes')
					{
						WebAppUrl = $WebApplication.WebAppUrl
						EnsureAllowed = $WebApplication.BlockedFileTypes.EnsureAllowed
						EnsureBlocked = $WebApplication.BlockedFileTypes.EnsureBlocked
						DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
					}
				}
			}

		}

		if ($WebApplication.PropertyBag -ne $null)
		{
			foreach($PropertyBagItem in $WebApplication.PropertyBag) 
			{
				$PropertyBagItemKeyNoSpace = $PropertyBagItem.Key.Replace(' ', '')

				# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppPropertyBag
				SPWebAppPropertyBag ($WebApplicationNameNoSpaces + '_PropertyBag_' + $PropertyBagItemKeyNoSpace)
				{
					WebAppUrl = $WebApplication.WebAppUrl
					Key = $PropertyBagItem.Key
					Value = $PropertyBagItem.Value
					Ensure = $PropertyBagItem.Ensure
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}

		if ($WebApplication.OutgoingEmailSettings -ne $null)
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPOutgoingEmailSettings
			SPOutgoingEmailSettings ($WebApplicationNameNoSpaces + '_WebAppOutgoingEmailSettings')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				SMTPServer = $WebApplication.OutgoingEmailSettings.SMTPServer
				FromAddress = $WebApplication.OutgoingEmailSettings.FromAddress
				ReplyToAddress = $WebApplication.OutgoingEmailSettings.ReplyToAddress
				CharacterSet = $WebApplication.OutgoingEmailSettings.CharacterSet
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		#Create the managed paths
		foreach($managedPath in $WebApplication.ManagedPaths) 
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPManagedPath
			SPManagedPath ($WebApplicationNameNoSpaces + "_" + $managedPath.RelativeUrl) 
			{
				WebAppUrl = $WebApplication.WebAppUrl
				RelativeUrl = $managedPath.RelativeUrl
				Explicit = $managedPath.Explicit
				HostHeader = $WebApplication.UseHostNamedSiteCollections
				Ensure = $managedPath.Ensure
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		# Features (Only 'WebApplication' for FeatureScope)
		foreach($Feature in $WebApplication.Features) 
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPFeature
			SPFeature ($WebApplicationNameNoSpaces + "_" + $Feature.Name.Replace(' ', '')) 
			{
				Name                 = $Feature.Name
				Url                  = $WebApplication.WebAppUrl
				FeatureScope         = $Feature.FeatureScope
				Version              = $Feature.Version
				Ensure = $Feature.Ensure
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}
            
		#Set the CacheAccounts for the web application
		if ($WebApplication.CacheAccounts -ne $null) 
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPCacheAccounts
			SPCacheAccounts ($WebApplicationNameNoSpaces + '_CacheAccounts')
			{
				WebAppUrl = $WebApplication.WebAppUrl
				SuperUserAlias = $WebApplication.CacheAccounts.SuperUserAlias
				SuperReaderAlias = $WebApplication.CacheAccounts.SuperReaderAlias
				SetWebAppPolicy = $WebApplication.CacheAccounts.SetWebAppPolicy
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
			}
		}

		#Web Application Client Callable Settings
		if ($WebApplication.ClientCallableSettings -ne $null) 
		{
			$ProxyLibraries = @()
			if ($WebApplication.ClientCallableSettings.ProxyLibraries -ne $null)
			{
				foreach ($ProxyLibrary in $WebApplication.ClientCallableSettings.ProxyLibraries)
				{
					$ProxyLibraries += MSFT_SPProxyLibraryEntry {
						AssemblyName = $ProxyLibrary.AssemblyName
						SupportAppAuthentication = $ProxyLibrary.SupportAppAuthentication
					}			
				}
			}

			# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebAppClientCallableSettings
			SPWebAppClientCallableSettings ($WebApplicationNameNoSpaces + '_ClientCallableSettings')
            {
				WebAppUrl = $WebApplication.WebAppUrl
				MaxResourcesPerRequest = $WebApplication.ClientCallableSettings.MaxResourcesPerRequest
				MaxObjectPaths = $WebApplication.ClientCallableSettings.MaxObjectPaths
				ExecutionTimeout = $WebApplication.ClientCallableSettings.ExecutionTimeout
				RequestXmlMaxDepth = $WebApplication.ClientCallableSettings.RequestXmlMaxDepth
				EnableXsdValidation = $WebApplication.ClientCallableSettings.EnableXsdValidation
				EnableStackTrace = $WebApplication.ClientCallableSettings.EnableStackTrace
				RequestUsageExecutionTimeThreshold = $WebApplication.ClientCallableSettings.RequestUsageExecutionTimeThreshold
				EnableRequestUsage = $WebApplication.ClientCallableSettings.EnableRequestUsage
				LogActionsIfHasRequestException = $WebApplication.ClientCallableSettings.LogActionsIfHasRequestException
				ProxyLibraries = $ProxyLibraries
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}

		if ($WebApplication.ThrottlingSettings -ne $null) 
		{
			# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppThrottlingSettings
			SPWebAppThrottlingSettings ($WebApplicationNameNoSpaces + '_ThrottlingSettings')
            {
                WebAppUrl = $WebApplication.WebAppUrl
				AdminThreshold = $WebApplication.ThrottlingSettings.ListViewThreshold
                AllowObjectModelOverride = $WebApplication.ThrottlingSettings.AllowObjectModelOverride
				ChangeLogEnabled = $WebApplication.ThrottlingSettings.ChangeLogEnabled
				ChangeLogExpiryDays = $WebApplication.ThrottlingSettings.ChangeLogExpiryDays
				EventHandlersEnabled = $WebApplication.ThrottlingSettings.EventHandlersEnabled
                HappyHour = MSFT_SPWebApplicationHappyHour {
                    Hour = $WebApplication.ThrottlingSettings.HappyHour.Hour
                    Minute = $WebApplication.ThrottlingSettings.HappyHour.Minute
                    Duration = $WebApplication.ThrottlingSettings.HappyHour.Duration
                }
                HappyHourEnabled = $WebApplication.ThrottlingSettings.HappyHourEnabled
				ListViewLookupThreshold = $WebApplication.ThrottlingSettings.ListViewLookupThreshold
                ListViewThreshold = $WebApplication.ThrottlingSettings.ListViewThreshold
				RequestThrottling = $WebApplication.ThrottlingSettings.RequestThrottling
				UniquePermissionThreshold = $WebApplication.ThrottlingSettings.UniquePermissionThreshold
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}

		# Web App Workflow Settings
		if ($WebApplication.WorkflowSettings -ne $null) 
		{
			# https://github.com/dsccommunity/SharePointDsc/wiki/SPWebAppWorkflowSettings
			SPWebAppWorkflowSettings ($WebApplicationNameNoSpaces + '_WorkflowSettings')
            {
                WebAppUrl = $WebApplication.WebAppUrl
                EmailToNoPermissionWorkflowParticipantsEnable = $WebApplication.WorkflowSettings.EmailToNoPermissionWorkflowParticipantsEnable
                ExternalWorkflowParticipantsEnabled = $WebApplication.WorkflowSettings.ExternalWorkflowParticipantsEnabled
				UserDefinedWorkflowsEnabled = $WebApplication.WorkflowSettings.UserDefinedWorkflowsEnabled
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}

		if ($WebApplication.PeoplePickerSettings -ne $null) 
		{
			$SearchActiveDirectoryDomains = @()

			if ($WebApplication.PeoplePickerSettings.SearchActiveDirectoryDomains -ne $null)
			{
				foreach ($SearchActiveDirectoryDomain in $WebApplication.PeoplePickerSettings.SearchActiveDirectoryDomains)
				{
				    $AccessAccountPassword = $SearchActiveDirectoryDomain.AccessAccountPassword | ConvertTo-SecureString -AsPlainText -Force
					$AccessAccount = New-Object System.Management.Automation.PSCredential($SearchActiveDirectoryDomain.AccessAccount, $AccessAccountPassword)

					$SearchActiveDirectoryDomains += MSFT_SPWebAppPPSearchDomain {
						FQDN = $SearchActiveDirectoryDomain.FQDN
						IsForest = $SearchActiveDirectoryDomain.IsForest
						AccessAccount = $AccessAccount
					}
				}
			}

			# https://github.com/PowerShell/SharePointDsc/wiki/SPWebAppPeoplePickerSettings
			SPWebAppPeoplePickerSettings ($WebApplicationNameNoSpaces + '_PeoplePickerSettings')
            {
                WebAppUrl                      = $WebApplication.WebAppUrl
                ActiveDirectoryCustomFilter    = $WebApplication.PeoplePickerSettings.ActiveDirectoryCustomFilter
                ActiveDirectoryCustomQuery     = $WebApplication.PeoplePickerSettings.ActiveDirectoryCustomQuery
                ActiveDirectorySearchTimeout   = $WebApplication.PeoplePickerSettings.ActiveDirectorySearchTimeout
                OnlySearchWithinSiteCollection = $WebApplication.PeoplePickerSettings.OnlySearchWithinSiteCollection
                SearchActiveDirectoryDomains   = $SearchActiveDirectoryDomains
				DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
            }
		}

		# Content Database(s)
		if ($WebApplication.ContentDatabases -ne $null)
		{
			foreach($contentDatabase in $WebApplication.ContentDatabases) 
			{
				SharePointServerContentDatabase ($WebApplicationNameNoSpaces + "_" + $contentDatabase.Name)
				{
					WebApplication = $WebApplication
					ContentDatabase = $ContentDatabase
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}

		# Timer Job State (Web Application Level)
		# https://github.com/dsccommunity/SharePointDsc/wiki/SPTimerJobState
		if ($WebApplication.TimerJobStates -ne $null)
		{
			foreach($TimerJobState in $WebApplication.TimerJobStates) 
			{
				$TimerJobStateName = "TimerJobState_" + $WebApplicationNameNoSpaces + "_" + $TimerJobState.TypeName

				SPTimerJobState $TimerJobStateName
				{
					Enabled = $TimerJobState.Enabled
					Schedule = $TimerJobState.Schedule
					TypeName = $TimerJobState.TypeName
					WebAppUrl = $WebApplication.WebAppUrl
					DependsOn = ('[SPWebApplication]' + $WebApplicationNameNoSpaces)
				}
			}
		}
	}
} 
