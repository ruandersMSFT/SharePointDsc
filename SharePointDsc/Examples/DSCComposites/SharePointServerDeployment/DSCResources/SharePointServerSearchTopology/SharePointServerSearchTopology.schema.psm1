Configuration SharePointServerSearchTopology
{
    param
    (
    	[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$Node,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$DeployOnNodeName
	)

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SharePointServerDeployment
	
	# Apply farm wide configuration and logical components only on the first server
	if ($Node.NodeName -eq $DeployOnNodeName) {

		if ($ConfigurationData.NonNodeData.SharePoint.Farm.SearchServices -ne $null)
		{
			foreach($SearchService in $ConfigurationData.NonNodeData.SharePoint.Farm.SearchServices)
			{
				$SearchServiceInternalName = $SearchService.Name.Replace(' ', '')

				$DefaultContentAccessAccountPassword = $SearchService.DefaultContentAccessAccountPassword | ConvertTo-SecureString -AsPlainText -Force
				$DefaultContentAccessAccount = New-Object System.Management.Automation.PSCredential($SearchService.DefaultContentAccessAccount, $DefaultContentAccessAccountPassword)

				# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchServiceApp
				SPSearchServiceApp $SearchServiceInternalName
				{
					Name = $SearchService.Name
					AlertsEnabled = $SearchService.AlertsEnabled
					ApplicationPool = $SearchService.ApplicationPool
					DatabaseName = $SearchService.DatabaseName
					DatabaseServer = $SearchService.DatabaseServer
					DefaultContentAccessAccount = $DefaultContentAccessAccount
					CloudIndex = $SearchService.CloudIndex
					SearchCenterUrl = $SearchService.SearchCenterUrl
					Ensure = $SearchService.Ensure
				}

				if ($SearchService.Ensure -eq 'Present')
				{
					$PublishServiceApplicationEnsure = 'Absent'
					if ($SearchService.PublishService -ne $null -and $SearchService.PublishService -eq $true)
					{
						$PublishServiceApplicationEnsure = 'Present'
					}

					# https://github.com/dsccommunity/SharePointDsc/wiki/SPPublishServiceApplication
					SPPublishServiceApplication ($SearchServiceInternalName + '_PublishServiceApplication')
					{
						Name = $SearchService.Name
						Ensure = $PublishServiceApplicationEnsure
					}
				}

				SPSearchTopology ($SearchServiceInternalName + "_Topology")
				{
					ServiceAppName = $SearchService.Name
					Admin = $SearchService.Topology.Admin
					Crawler = $SearchService.Topology.Crawler
					ContentProcessing = $SearchService.Topology.ContentProcessing
					AnalyticsProcessing = $SearchService.Topology.AnalyticsProcessing
					QueryProcessing = $SearchService.Topology.QueryProcessing
					FirstPartitionDirectory = $SearchService.Topology.FirstPartitionDirectory
					IndexPartition = $SearchService.Topology.IndexPartition
					DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
				}
		
				if ($SearchService.IndexPartitions -ne $null)
				{
					foreach($IndexPartition in $SearchService.IndexPartitions)
					{
						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchIndexPartition
						SPSearchIndexPartition ($SearchServiceInternalName + "_IndexPartition_" + $IndexPartition.Index)
						{
							Servers = $IndexPartition.Servers
							Index = $IndexPartition.Index
							RootDirectory = $IndexPartition.RootDirectory
							ServiceAppName = $SearchService.Name
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.ContentSources -ne $null)
				{
					foreach($ContentSource in $SearchService.ContentSources)
					{
						$ContentSourceNameNoSpace = $ContentSource.Name.Replace(" ", "")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchContentSource
						SPSearchContentSource ($SearchServiceInternalName + "_ContentSource_" + $ContentSourceNameNoSpace)
						{
							Name = $ContentSource.Name
							ServiceAppName = $SearchService.Name
							ContentSourceType = $ContentSource.ContentSourceType
							Addresses = $ContentSource.Addresses
							CrawlSetting = $ContentSource.CrawlSetting
							#LimitPageDepth = $ContentSource.LimitPageDepth
							IncrementalSchedule = MSFT_SPSearchCrawlSchedule {
								ScheduleType = $ContentSource.IncrementalCrawl.ScheduleType
								StartHour = $ContentSource.IncrementalCrawl.StartHour
								StartMinute = $ContentSource.IncrementalCrawl.StartMinute
								CrawlScheduleRepeatDuration = $ContentSource.IncrementalCrawl.CrawlScheduleRepeatDuration
								CrawlScheduleRepeatInterval = $ContentSource.IncrementalCrawl.CrawlScheduleRepeatInterval
							}
							FullSchedule = MSFT_SPSearchCrawlSchedule {
								ScheduleType = $ContentSource.FullCrawl.ScheduleType
								StartHour = $ContentSource.FullCrawl.StartHour
								StartMinute = $ContentSource.FullCrawl.StartMinute
								CrawlScheduleDaysOfWeek = $ContentSource.FullCrawl.CrawlScheduleDaysOfWeek
							}
							Priority = $ContentSource.Priority
							Force = $ContentSource.Force
							Ensure = $ContentSource.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.CrawlerImpactRules -ne $null)
				{
					#todo, should the be a for each?  Only one per type?
					foreach($CrawlerImpactRule in $SearchService.CrawlerImpactRules)
					{
						if ($CrawlerImpactRule.RequestLimit -eq $null -and $CrawlerImpactRule.WaitTime -eq $null)
						{
							throw [Exception] "RequestLimit or WaitTime must be specified for Crawler Impact Rule '$($CrawlerImpactRule.Name)'."
						}
						elseif ($CrawlerImpactRule.RequestLimit -ne $null -and $CrawlerImpactRule.WaitTime -ne $null)
						{
							throw [Exception] "Only RequestLimit or WaitTime (not both) can be specified for Crawler Impact Rule '$($CrawlerImpactRule.Name)'."
						}

						$CrawlerImpactRuleInternalName = $CrawlerImpactRule.Name.Replace("://", "_").Replace("/", "_")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchCrawlerImpactRule
						SPSearchCrawlerImpactRule ("$($SearchServiceInternalName)_$($CrawlerImpactRuleInternalName)_$($CrawlerImpactRule.RequestLimit)_$($CrawlerImpactRule.WaitTime)_CrawlerImpactRule")
						{
							ServiceAppName = $SearchService.Name
							Name = $CrawlerImpactRule.Name
							RequestLimit = $CrawlerImpactRule.RequestLimit
							WaitTime = $CrawlerImpactRule.WaitTime
							Ensure = $CrawlerImpactRule.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.CrawlRules -ne $null)
				{
					foreach($CrawlRule in $SearchService.CrawlRules)
					{
						$CrawlRuleInternalName = $CrawlRule.Path.Replace("://", "_").Replace("/", "_")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchCrawlRule
						SPSearchCrawlRule ($SearchServiceInternalName + "_CrawlRule_" + $CrawlRuleInternalName)
						{
							ServiceAppName = $SearchService.Name
							Path = $CrawlRule.Path
							RuleType = $CrawlRule.RuleType
							CrawlConfigurationRules = $CrawlRule.CrawlConfigurationRules
							AuthenticationType = $CrawlRule.AuthenticationType
							CertificateName = $CrawlRule.CertificateName
							Ensure = $CrawlRule.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.CrawlMappings -ne $null)
				{
					foreach($CrawlMapping in $SearchService.CrawlMappings)
					{
						$CrawlMappingInternalName = $CrawlMapping.Url.Replace("://", "_").Replace("/", "_")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchCrawlMapping
						SPSearchCrawlMapping ($SearchServiceInternalName + "_CrawlMapping_" + $CrawlMappingInternalName)
						{
							ServiceAppName = $SearchService.Name
							Url = $CrawlMapping.Url
							Target = $CrawlMapping.Target
							Ensure = $CrawlMapping.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.MetadataCategories -ne $null)
				{
					foreach($MetadataCategory in $SearchService.MetadataCategories)
					{
						$MetadataCategoryInternalName = $MetadataCategory.Name.Replace(" ", "")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchMetadataCategory
						SPSearchMetadataCategory ($SearchServiceInternalName + "_MetadataCategory_" + $MetadataCategoryInternalName)
						{
							Name = $MetadataCategory.Name
							ServiceAppName = $SearchService.Name
							AutoCreateNewManagedProperties = $MetadataCategory.AutoCreateNewManagedProperties
							DiscoverNewProperties = $MetadataCategory.DiscoverNewProperties
							MapToContents = $MetadataCategory.MapToContents
							Ensure = $MetadataCategory.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.ManagedProperties -ne $null)
				{
					foreach($ManagedProperty in $SearchService.ManagedProperties)
					{
						$ManagedPropertyInternalName = $ManagedProperty.Name.Replace(" ", "")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchManagedProperty
						SPSearchManagedProperty ($SearchServiceInternalName + "_ManagedProperty_" + $ManagedPropertyInternalName)
						{
							Name = $ManagedProperty.Name
							ServiceAppName = $SearchService.Name
							PropertyType = $ManagedProperty.PropertyType
							Searchable = $ManagedProperty.Searchable
							Queryable = $ManagedProperty.Queryable
							Retrievable = $ManagedProperty.Retrievable
							HasMultipleValues = $ManagedProperty.HasMultipleValues
							Refinable = $ManagedProperty.Refinable
							Sortable = $ManagedProperty.Sortable
							SafeForAnonymous = $ManagedProperty.SafeForAnonymous
							Aliases = $ManagedProperty.Aliases
							TokenNormalization = $ManagedProperty.TokenNormalization
							NoWordBreaker = $ManagedProperty.NoWordBreaker
							IncludeAllCrawledProperties = $ManagedProperty.IncludeAllCrawledProperties
							CrawledProperties = $ManagedProperty.CrawledProperties
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.FileTypes -ne $null)
				{
					foreach($FileType in $SearchService.FileTypes)
					{
						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchFileType
						SPSearchFileType ($SearchServiceInternalName + "_FileType_" + $FileType.FileType)
						{
							FileType = $FileType.FileType
							ServiceAppName = $SearchService.Name
							Description = $FileType.Description
							MimeType = $FileType.MimeType
							Enabled = $FileType.Enabled
							Ensure = $FileType.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.AuthoritativePages -ne $null)
				{
					foreach($AuthoritativePage in $SearchService.AuthoritativePages)
					{
						# https://github.com/dsccommunity/SharePointDsc/wiki/SPSearchAuthoritivePage
						SPSearchAuthoritativePage ($SearchServiceInternalName + "_AuthoritativePage_" + $AuthoritativePage.Path.Replace(' ', '').Replace('.', '').Replace('/', '').Replace(':', ''))
						{
							ServiceAppName = $SearchService.Name
							Path = $AuthoritativePage.Path
							Level = $AuthoritativePage.Level
							Action = $AuthoritativePage.Action
							Ensure = $AuthoritativePage.Ensure
							DependsOn = "[SPSearchServiceApp]$($SearchServiceInternalName)"
						}
					}
				}

				if ($SearchService.ResultSources -ne $null)
				{
					foreach($ResultSource in $SearchService.ResultSources)
					{
						$ResultSourceInternalName = $ResultSource.Name.Replace(" ", "")

						# https://github.com/PowerShell/SharePointDsc/wiki/SPSearchResultSource
						SPSearchResultSource ($SearchServiceInternalName + "_ResultSource_" + $ResultSourceInternalName)
						{
							Name = $ResultSource.Name
							ScopeName = $ResultSource.ScopeName
							ScopeUrl = $ResultSource.ScopeUrl
							SearchServiceAppName = $SearchService.Name
							Query = $ResultSource.Query
							ProviderType = $ResultSource.ProviderType
							Ensure = $ResultSource.Ensure
						}
					}
				}
			}
		}
	}
}