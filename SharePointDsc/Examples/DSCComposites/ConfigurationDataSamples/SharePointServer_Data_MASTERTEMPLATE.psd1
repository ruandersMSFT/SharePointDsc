@{
    AllNodes = @(
        # All Nodes
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword=$true # https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/securemof?view=powershell-7
            PSDscAllowDomainUser=$true
        },
        # Application Servers
        # Once the farm is built ensure that this server remains the first application server defined
        @{ 
            NodeName = 'SPTest01'
            ServerRole = 'Custom'
            CentralAdministration = @{
                RunCentralAdmin = $true
                IPAddress = '*'
            }
			CustomServiceInstances = @(
				@{
					Name = 'Claims to Windows Token Service'
					Ensure = 'Present'
				},
				@{
					Name = 'App Management Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Business Data Connectivity Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Managed Metadata Web Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Subscription Settings Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Secure Store Service'
					Ensure = 'Present'
				},
				@{
					Name = 'User Profile Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Visio Graphics Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Workflow Timer Service'
					Ensure = 'Present'
				},
				@{
					Name = 'SharePoint Server Search'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Web Application'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Incoming E-Mail'
					Ensure = 'Present'
				},
				@{
					Name = 'Project Server Application Service'
					Ensure = 'Present'
				}
			)
			InternetInformationServer = @{
				Bindings = @(
					@{
						Name = 'SharePoint Sites'
						IPAddress = '*'
					}
				)
				CustomHeaders = @(
					@{
						Name = 'MyCustomHeader'
						Value = 'SPTest02'
					}
				)
			}
        },
	    @{ 
            NodeName = 'SPTest02'
            ServerRole = 'Custom'
            CentralAdministration = @{
                RunCentralAdmin = $true
                IPAddress = '*'
            }
			CustomServiceInstances = @(
				@{
					Name = 'Claims to Windows Token Service'
					Ensure = 'Present'
				},
				@{
					Name = 'App Management Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Business Data Connectivity Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Managed Metadata Web Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Subscription Settings Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Secure Store Service'
					Ensure = 'Present'
				},
				@{
					Name = 'User Profile Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Visio Graphics Service'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Workflow Timer Service'
					Ensure = 'Present'
				},
				@{
					Name = 'SharePoint Server Search'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Web Application'
					Ensure = 'Present'
				},
				@{
					Name = 'Microsoft SharePoint Foundation Incoming E-Mail'
					Ensure = 'Present'
				},
				@{
					Name = 'Project Server Application Service'
					Ensure = 'Present'
				}
			)
			InternetInformationServer = @{
				Bindings = @(
					@{
						Name = 'SharePoint Sites'
						IPAddress = '*'
					}
				)
				CustomHeaders = @(
					@{
						Name = 'MyCustomHeader'
						Value = 'SPTest02'
					}
				)
			}
        }
    )
    NonNodeData = @{
        WaitRetryIntSec = 60
        WaitRetryCount = 20
        SharePoint = @{
			WindowsSettings = @{
				DomainName = 'contoso.com'
				AdministratorMembersToInclude = 'contoso\Tier 1 SharePoint Admins','contoso\svc.dev.spexec','contoso\svc.dev.spfarm'
				PerformanceMonitorMembersToInclude = 'contoso\svc.dev.spexec','contoso\svc.dev.spfarm'
			}
			SQLAliases = @(
				@{
					Name = 'ContosoSQL02'
					ServerName = 'ContosoSQL02'
					Ensure = 'Present'
				},
				@{
					Name = 'MyAlias'
					ServerName = 'MyServer'
					Ensure = 'Present'
				}
			)
			Certificates = @{
				Pfx = @(
					@{
						Ensure = 'Present'
						Thumbprint = 'b33e301588a474746bf611183bb5cdf851076b14'
						Path = '\\ContosoDSC01\Cert\contoso.com.pfx'
						Location = 'LocalMachine'
						Store = 'My'
						Exportable = $false
						Password = 'Password123!@#' #temp as clear text, rework to handle securely
					}
				)
				Cer = @(
					@{
						Ensure = 'Present'
						Thumbprint = '62914576dc0afac83c4804bcc2c1b700a61139fe'
						Path = '\\RADC.contoso.com\Cert\bing.cer'
						Location = 'LocalMachine'
						Store = 'My'
					}
				)
			}
			InternetInformationServer = @{
				CustomHeaders = @(
					@{
						Name = 'MyCustomHeader'
						Ensure = 'Present'
					}
				)
				DisableLoopbackCheck = $true
				LogFormat = 'W3C'
				LogLocalTimeRollover = $true
				LogPath = 'c:\IIS-Logs'
				LogPeriod = 'Daily'
				RemoveIISDefaults = $true
				TraceLogPath = 'c:\inetpub\logs\FailedReqLogFiles'
				Ensure = 'Present'
			}
            Farm = @{
				Administrators = @{
					Members = @("contoso\ruanders")
					MembersToInclude = $null
					MembersToExclude = $null
				}
				Installation = @{
					SPZipPath = '\\Contosodsc01.contoso.com\InstallImages\SP2019Binaries.zip'
					SPInstallPath = 'c:\DSC\SP2019Binaries'
					PrereqInstallerPath = 'c:\DSC\SP2019Binaries\prerequisiteinstaller.exe'
					OfflineInstall = @{
						WindowsInstallPath = '\\Contosodsc01.contoso.com\InstallImages\2016WinSrv\sources\sxs'
						PreRequisitesSourcePath = '\\Contosodsc01.contoso.com\InstallImages\SP2019Prerequisities'
						PreRequisitesTargetPath = 'c:\DSC\SP2019Prerequisities'
						DotNet472InstallPath = 'c:\DSC\SP2019Prerequisities\NDP472-KB4054530-x86-x64-AllOS-ENU.exe'
						SQLNCliInstallPath = 'c:\DSC\SP2019Prerequisities\sqlncli.msi'
						SyncInstallPath = 'c:\DSC\SP2019Prerequisities\Synchronization.msi'
						AppFabricInstallPath = 'c:\DSC\SP2019Prerequisities\WindowsServerAppFabricSetup_x64.exe'
						IDFX11InstallPath = 'c:\DSC\SP2019Prerequisities\MicrosoftIdentityExtensions-64.msi'
						MSIPCClientInstallPath = 'c:\DSC\SP2019Prerequisities\setup_msipc_x64.exe'
						WCFDataServices56InstallPath = 'c:\DSC\SP2019Prerequisities\WcfDataServices.exe'
						MSVCRT11InstallPath = 'c:\DSC\SP2019Prerequisities\vcredist_x64.exe'
						MSVCRT14InstallPath = 'c:\DSC\SP2019Prerequisities\vc_redist.x64.exe'
						KB3092423InstallPath = 'c:\DSC\SP2019Prerequisities\AppFabric-KB3092423-x64-ENU.exe'
					}
				}
				SharePointVersion = '2019'
                SharePointProductKey = '7G7R6-N6QJC-JFPJX-CK8WX-66QW4'
                ProjectServerProductKey = '94D77-N9KP7-62G8M-PCX6H-8HXF4'
				AuthenticationRealm = '14757a87-4d74-4323-83b9-fb1e77e8f22f'
				DeveloperDashboard = 'Off'
				MinRoleComplianceState = 'Compliant'
				DistributionNode = 'SPTest01'
				DatabaseServer = 'SPTestSQL'
                ConfigurationDatabase = 'SP2019_Config'
				ConfigurationWizard = @{
		            DatabaseUpgradeDays = @( "sat", "sun" )
					DatabaseUpgradeTime = "3:00am to 5:00am"
				}
                PassPhrase = 'Password123!@#'
				ServiceAccounts = @{
                    Setup = @{ 
						Account =  'contoso\svc.dev.spexec'
						Password =  'Password123!@#'
					}
                    Farm = @{ 
						Account =  'contoso\svc.dev.spfarm'
						Password =  'Password123!@#'
					}
                }
				AppDomain = @{
					AppDomain = 'contosointranetapps.com'
					Prefix = 'app'
				}
                CentralAdministration = @{
					AuthenticationMode = 'Kerberos'
                    CertificateStoreName = 'My'
					CertificateThumbprint = 'a474746bf61b31183bb133edf85107688015b5c4'
	                ContentDatabase = 'SP2019_Admin_Content'
                    Port = 443
                    Protocol = 'https'
					Url = 'https://centraladmin.contoso.com'
                }
				FarmSolutions = @(
					@{
						Name = 'MySolution.wsp'
						LiteralPath = '\\contosodsc01.contoso.com\InstallImages\SP2019\FarmSolutions\MySolution.wsp'
						Ensure = 'Present'
						Version = '1.0.0'
						SolutionLevel = 'All'
						Deployed = $true
						WebAppUrls = @('https://portal.contoso.com')
					}
				)
				InfoPathFormsServiceConfig = @{
					AllowUserFormBrowserEnabling = $true
					AllowUserFormBrowserRendering = $true
					MaxDataConnectionTimeout = 20000
					DefaultDataConnectionTimeout = 10000
					MaxDataConnectionResponseSize = 1500
					RequireSslForDataConnections = $true
					AllowEmbeddedSqlForDataConnections = $false
					AllowUdcAuthenticationForDataConnections = $false
					AllowUserFormCrossDomainDataConnections = $false
					MaxPostbacksPerSession = 75
					MaxUserActionsPerPostback = 200
					ActiveSessionsTimeout = 1440
					MaxSizeOfUserFormState = 4096
					Ensure = 'Present'
				}
				ManagedAccounts = @(
					@{
						Name = 'ServicePool'
						Account = 'contoso\svc.dev.spsaapp'
						Password = 'Password123!@#'
					},
					@{
						Name = 'WebPool'
						Account = 'contoso\svc.dev.spportalapp'
						Password = 'Password123!@#'
					}
				)
				ServiceAppPools = @(
					@{
						Name = 'SharePoint Service Applications'
						ServiceAccount = 'contoso\svc.dev.spsaapp'
					}
				)
				IncomingEmailSettings = @{
					DLsRequireAuthenticatedSenders = $true
					DistributionGroupsEnabled = $true
					DropFolder = '\\MailServer\Pickup'
					RemoteDirectoryManagementURL = $null
					ServerAddress = $null
					ServerDisplayAddress = 'contoso.com'
					UseAutomaticSettings = $false
					UseDirectoryManagementService = 'No'
					Ensure = 'Present'
				}
				#Farm Wide Outgoing Email Settings
				OutgoingEmailSettings = @{
					SMTPServer = 'smtp.contoso.com'
					FromAddress = 'sharepoint@contoso.com'
					ReplyToAddress = 'noreply@contoso.com'
					CharacterSet = '65001'
                }
				AntiVirusSettings = @{
					AllowDownloadInfected = $false
					AttemptToClean = $false
					NumberOfThreads = 999
					ScanOnDownload = $true
					ScanOnUpload = $true
					TimeoutDuration = 999
				}
				PropertyBag = @(
					@{
						Key = 'MyFarmAppKey1'
						Value = 'MyFarmAppValue1'
						Ensure = 'Present'
					},
					@{
						Key = 'MyFarmAppKey2'
						Value = 'MyFarmAppValue2'
						Ensure = 'Present'
					}
				)
				DiagnosticLoggingSettings = @{
					LogPath = 'c:\ULSLogs'
					LogSpaceInGB = 10
					DaysToKeepLogs = 7
					AppAnalyticsAutomaticUploadEnabled = $false
					CustomerExperienceImprovementProgramEnabled = $true
					DownloadErrorReportingUpdatesEnabled = $false
					ErrorReportingAutomaticUploadEnabled = $false
					ErrorReportingEnabled = $false
					EventLogFloodProtectionEnabled = $true
					EventLogFloodProtectionNotifyInterval = 5
					EventLogFloodProtectionQuietPeriod = 2
					EventLogFloodProtectionThreshold = 5
					EventLogFloodProtectionTriggerPeriod = 2
					LogCutInterval = 15
					LogMaxDiskSpaceUsageEnabled = $true
					ScriptErrorReportingDelay = 30
					ScriptErrorReportingEnabled = $true
					ScriptErrorReportingRequireAuth = $true
				}
				DiagnosticProviders = @(
					@{
						Name = 'job-diagnostics-blocking-query-provider'
						MaxTotalSizeInBytes  = 10000000000000
						Retention            = 14
						Enabled              = $true
						Ensure = 'Present'
					}
				)
				UsageApplication = @{
					Name = 'Usage Service Application'
					DatabaseName = 'SP2019_Usage'
					DatabaseServer = 'SPTestSQL'
					UsageLogCutTime = 5
					UsageLogLocation = 'c:\UsageLogs'
					UsageLogMaxFileSizeKB = 1024
				}
				StateServiceApplication = @{
					Name = 'State Service Application'
					DatabaseName = 'SP2019_State'
					DatabaseServer = 'SPTestSQL'
				}
				AccessServices = @(
					@{
						Name = 'Access Services Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseServer = 'SPTestSQL'
						Ensure = 'Present'
					}
				)
				AppManagementServices = @(
					@{
						Name = 'Application Management Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseName = 'SP2019_AppManagement'
						DatabaseServer = 'SPTestSQL'
						Ensure = 'Present'
					}
				)
				BusinessDataConnectivityServices = @(
					@{
						Name ='BCS Service Application' 
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseName = 'SP2019_BCS'
						DatabaseServer = 'SPTestSQL'
						PublishService = $false
						Ensure = 'Present'
					}
				)
				<# #################### SharePoint 2013 Only
				ExcelServices = @(
					@{
						Name = 'Excel Services Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						CachingOfUnusedFilesEnable = $false
						CrossDomainAccessAllowed = $false
						EncryptedUserConnectionRequired = 'Connection'
						ExternalDataConnectionLifetime = 3600
						FileAccessMethod = 'UseImpersonation'
						LoadBalancingScheme = 'RoundRobin'
						MemoryCacheThreshold = 20
						PrivateBytesMax = 2048
						SessionsPerUserMax = 5
						SiteCollectionAnonymousSessionsMax = 10
						TerminateProcessOnAccessViolation = $true
						ThrottleAccessViolationsPerSiteCollection = 900
						TrustedFileLocations = @()
						UnattendedAccountApplicationId = $null
						UnusedObjectAgeMax = 15
						WorkbookCache = 'e:\WorkbookCache'
						WorkbookCacheSizeMax = 128
						Ensure = 'Present'
					}
				)
				#>
				MachineTranslationServiceApps = @(
					@{
						Name = 'Machine Translation Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseServer = 'SPTestSQL'
						DatabaseName = 'SP2019_MachineTranslationService'
						ProxyName = $null
						PublishService = $false
						Ensure = 'Present'
					}
				)
				ManagedMetadataServices = @(
					@{
						Name = 'Managed Metadata Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						ContentTypePushdownEnabled = $false
						ContentTypeSyndicationEnabled = $true
						DatabaseName = 'SP2019_ManagedMetadataService'
						DatabaseServer = 'SPTestSQL'
						IsDefaultColumnTermSetService = $true
						IsDefaultKeywordTermSetService = $true
						ProxyName = $null
						PublishService = $false
						TermStoreAdministrators = @( 'contoso\Tier 1 SharePoint Admins' )
						Ensure = 'Present'
					}
				)
				PerformancePointServiceApps = @(
					@{
						Name = 'Performance Point Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseServer = 'SPTestSQL'
						DatabaseName = 'SP2019_PerformancePointService'
						ProxyName = $null
						Ensure = 'Present'
					}
				)
				PowerPointAutomationServiceApps = @(
					@{
						Name = 'PowerPoint Automation Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						CacheExpirationPeriodInSeconds = 600
						MaximumConversionsPerWorker = 5
						WorkerKeepAliveTimeoutInSeconds = 120
						WorkerProcessCount = 3
						WorkerTimeoutInSeconds = 300
						ProxyName = $null
						Ensure = 'Present'
					}
				)
				ProjectServerServices = @(
					@{
						Name = 'Project Server Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						Ensure = 'Present'
					}
				)
				SearchServices = @(
					@{
						Name = 'Search Service Application'
						AlertsEnabled = $true
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseName = 'SP2019_Search'
						DatabaseServer = 'SPTestSQL'
						DefaultContentAccessAccount = 'contoso\svc.dev.spcrawl'
						DefaultContentAccessAccountPassword = 'Password123!@#'
						CloudIndex = $false
						SearchCenterUrl = ''
						PublishService = $false
						Ensure = 'Present'
						AuthoritativePages = @(
							@{
								Path = 'https://www.contoso.com/'
								Level = 1.75
								Action = 'Authoratative'
								Ensure = 'Present'
							},
							@{
								Path = 'https://www.contoso.net/'
								Level = 0.66
								Action = 'Demoted'
								Ensure = 'Present'
							}
						)
						CrawlerImpactRules = @(
							@{
								Name = 'https://www.conotoso.com'
								RequestLimit = 15
								#WaitTime = 15
								Ensure = 'Present'
							}
						)
						CrawlRules = @(
							@{
								Path = 'https://intranet.sharepoint.contoso.com'
								RuleType = 'InclusionRule'
								CrawlConfigurationRules = @( 'FollowLinksNoPageCrawl', 'CrawlComplexUrls', 'CrawlAsHTTP' )
								AuthenticationType = "DefaultRuleAccess"
								Ensure = 'Present'						
							}
						)
						CrawlMappings = @(
							@{
								Url = 'http://crawl.sharepoint.com'
								Target = 'http://site.sharepoint.com'
								Ensure = 'Present'
							}
						)
						FileTypes = @(
							@{
								FileType = 'pdf'
								Description = 'PDF'
								MimeType = 'application/pdf'
								Enabled = $true
								Ensure = 'Present'
							}
						)
						IndexPartitions = @(
							@{
								Servers = @("Server2", "Server3")
								Index = 1
								RootDirectory = "C:\SearchIndexes\1"
							}
						)
						ManagedProperties = @(
							@{
								Name = 'MyProperty'
								PropertyType = 'Text'
								Searchable = $true
								Queryable = $true
								Retrievable = $true
								HasMultipleValues = $true
								Refinable = $true
								Sortable = $true
								SafeForAnonymous = $false
								Aliases = $null
								TokenNormalization = $false
								NoWordBreaker = $false
								IncludeAllCrawledProperties = $false
								CrawledProperties = @( 'OWS_Notes' )
							}
						)
						MetadataCatagories = @(
							@{
								Name = 'My New category'
								AutoCreateNewManagedProperties = $true
								DiscoverNewProperties = $true
								MapToContents = $true
								Ensure = 'Present'
							}
						)
						ResultSources = @(
							@{
								Name = 'External SharePoint results'
								ScopeName = 'SSA'
								ScopeUrl = ''
								Query = '{searchTerms}'
								ProviderType = 'Remote SharePoint Provider'
								Ensure = 'Present'
							}
						)
						Topology = @{
							Admin = @('ContosoSRC01')
							Crawler = @('ContosoSRC01')
							ContentProcessing = @('ContosoSRC01')
							AnalyticsProcessing = @('ContosoSRC01')
							QueryProcessing = @('ContosoSRC01')
							IndexPartition = @('ContosoSRC01')
							FirstPartitionDirectory = 'C:\searchindex\0'
						}
						ContentSources = @(
							@{
								Name = 'Local SharePoint sites'
								ContentSourceType = 'SharePoint'
								CrawlSetting = 'CrawlEverything'
								Addresses = @( 'https://portal.contoso.com' )
								ContinuousCrawl = $false
								LimitPageDepth = 5
								Priority = 'Normal'
								Force = $true
								IncrementalCrawl = @{
									ScheduleType = 'Daily'
									StartHour = '0'
									StartMinute = '0'
									CrawlScheduleRepeatDuration = '1440'
									CrawlScheduleRepeatInterval = '60'
								}
								FullCrawl = @{
									ScheduleType = 'Weekly'
									StartHour = '0'
									StartMinute = '0'
									CrawlScheduleDaysOfWeek = @('Monday','Wednesday','Saturday')
								}
								Ensure = 'Present'
							}
						)
					}
				)
				SearchServiceSettings = @{
					PerformanceLevel = 'Maximum'
					ContactEmail = 'sharepoint@contoso.com'
					WindowsServiceAccount = $null #todo
				}
				SecureStoreServices = @(
					@{
						Name = 'Secure Store Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						AuditingEnabled = $true
						AuditLogMaxSize = 30
						DatabaseName = 'SP2019_SecureStore'
						DatabaseServer = 'SPTestSQL'
						PublishService = $false
						Ensure = 'Present'
					}
				)
				SubscriptionSettingsServices = @(
					@{
						Name = 'Subscription Settings Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseName = 'SP2019_SubscriptionSettings'
						DatabaseServer = 'SPTestSQL'
						Ensure = 'Present'
					}
				)
				UserProfileServices = @(
					@{
						Name = 'User Profile Service Application'
						ProxyName = $null
						ApplicationPool = 'SharePoint Service Applications'
						MySiteHostLocation = 'https://my.contoso.com'
						MySiteManagedPath = 'personal'
						ProfileDBName = 'UserProfileService_Profile'
						ProfileDBServer = 'SPTestSQL'
						SocialDBName = 'UserProfileService_Social'
						SocialDBServer = 'SPTestSQL'
						SyncDBName = 'UserProfileService_Sync'
						SyncDBServer = 'SPTestSQL'
						# SP2013 only SyncServiceNodes = @('SPTest01')
						EnableNetBIOS = $false
						NoILMUsed = $false
						SiteNamingConflictResolution = 'Username_CollisionError'
						PublishService = $false
						Ensure = 'Present'
						Connections = @(
							@{
								Name = 'contoso.com'
								Forest = 'contoso.com'
								ConnectionCredentials = @{
									Account = 'contoso\svc.dev.spsaapp'
									Password = 'Password123!@#'
								}
								Server = 'server.contoso.com'
								UseSSL = $false
								IncludedOUs = @('OU=SharePoint Users,DC=Contoso,DC=com')
								ExcludedOUs = @('OU=Notes Users,DC=Contoso,DC=com')
								Force = $false
								ConnectionType = 'ActiveDirectory'
								Ensure = 'Present'
							}
						)
						Sections = @(
							@{
								Name = 'PersonalInformationSection'
								DisplayName = 'Personal Information'
								DisplayOrder = 5000
								Ensure = 'Present'
							}
						)
						Permissions = @{
							CreatePersonalSite = @('contoso\Group', 'ra\User1')
							FollowAndEditProfile = @('Everyone')
							UseTagsAndNotes = @('None')
						}
						Properties = @(
							@{
								Name = 'WorkEmail2'
								DisplayName = 'Work Email'
								Type = 'Email'
								Description = '' #implementation isn't using it yet
								PolicySetting = 'Mandatory'
								PrivacySetting = 'Public'
								PropertyMappings = @{
									ConnectionName = 'contoso.com'
									PropertyName = 'mail'
									Direction = 'Import'
								}
								Length = 10
								DisplayOrder = 25
								IsEventLog = $false
								IsVisibleOnEditor = $true
								IsVisibleOnViewer = $true
								IsUserEditable = $true
								IsAlias = $false
								IsSearchable = $false
								TermStore = ''
								TermGroup = ''
								TermSet = ''
								UserOverridePrivacy = $false
								Ensure = 'Present'
							}
						)
					}
				)
				VisioGraphicsServices = @(
					@{
						Name = 'Visio Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						Ensure = 'Present'
					}
				)
				WordAutomationServices = @(
					@{
						Name = 'Word Automation Service Application'
						ApplicationPool = 'SharePoint Service Applications'
						DatabaseName = 'SP2019_WordAutomation'
						DatabaseServer = "SPTestSQL"
						SupportedFileFormats = "docx", "doc", "mht", "rtf", "xml"
						DisableEmbeddedFonts = $false
						MaximumMemoryUsage = 100
						RecycleThreshold = 100
						DisableBinaryFileScan = $false
						ConversionProcesses = 8
						JobConversionFrequency = 15
						NumberOfConversionsPerProcess = 12
						TimeBeforeConversionIsMonitored = 5
						MaximumConversionAttempts = 2
						MaximumSyncConversionRequests = 25 
						KeepAliveTimeout = 30
						MaximumConversionTime = 300
						Ensure = "Present"
					}
				)
				DistributedCacheService = @{
					Name = 'Distributed Cache Service'
					CacheSizeInMB = 2048
					CreateFirewallRules = $true
					ServiceAccount = 'todo'
					ServerProvisionOrder = 'todo'
				}
				DistributedCacheClientSettings = @{
					DLTCMaxConnectionsToServer  = 3
					DLTCRequestTimeout          = 1000
					DLTCChannelOpenTimeOut      = 1000
					DVSCMaxConnectionsToServer  = 3
					DVSCRequestTimeout          = 1000
					DVSCChannelOpenTimeOut      = 1000
					DACMaxConnectionsToServer   = 3
					DACRequestTimeout           = 1000
					DACChannelOpenTimeOut       = 1000
					DAFMaxConnectionsToServer   = 3
					DAFRequestTimeout           = 1000
					DAFChannelOpenTimeOut       = 1000
					DAFCMaxConnectionsToServer  = 3
					DAFCRequestTimeout          = 1000
					DAFCChannelOpenTimeOut      = 1000
					DBCMaxConnectionsToServer   = 3
					DBCRequestTimeout           = 1000
					DBCChannelOpenTimeOut       = 1000
					DDCMaxConnectionsToServer   = 3
					DDCRequestTimeout           = 1000
					DDCChannelOpenTimeOut       = 1000
					DSCMaxConnectionsToServer   = 3
					DSCRequestTimeout           = 1000
					DSCChannelOpenTimeOut       = 1000
					DTCMaxConnectionsToServer   = 3
					DTCRequestTimeout           = 1000
					DTCChannelOpenTimeOut       = 1000
					DSTACMaxConnectionsToServer = 3
					DSTACRequestTimeout         = 1000
					DSTACChannelOpenTimeOut     = 1000
				}
				HealthAnalyzerRuleStates = @(
					@{
						Name = "Drives are at risk of running out of free space."
						Enabled = $false
						RuleScope   = "All Servers"
						Schedule = "Daily"
						FixAutomatically = $false
					}
				)
				IrmSettings = @{
					RMSserver = 'https://rms.contoso.com'
				}
				LogLevels = @(
					@{
						Name = 'SPServer_defaults'
						Settings = @(
							@{
								Area = 'SharePoint Server'
								Name = '*'
								TraceLevel = 'Default'
								EventLevel = 'Default'
							}
						)
					},
					@{
						Name = 'CustomLoggingSettings'
						Settings = @(
							@{
								Area = 'SharePoint Server'
								Name = 'Database'
								TraceLevel = 'Verbose'
								EventLevel = 'Verbose'
							},
							@{
								Area = 'Business Connectivity Services'
								Name = 'Business Data'
								TraceLevel = 'Unexpected'
								EventLevel = 'Error'
							}
						)
					}
				)
				PasswordChangeSettings = @{
					MailAddress                   = "sharepoint@contoso.com"
					DaysBeforeExpiry              = 14
					PasswordChangeWaitTimeSeconds = 60
					NumberOfRetries               = 3
				}
				QuotaTemplates = @(
					@{
						Name = "TeamSite"
						MaximumUsagePointsSolutions = 1000
						StorageMaxInMB = 2048
						StorageWarningInMB = 1024
						WarningUsagePointsSolutions = 800
						Ensure = "Present"
					},
					@{
						Name = "MySite"
						MaximumUsagePointsSolutions = 250
						StorageMaxInMB = 1024
						StorageWarningInMB = 512
						WarningUsagePointsSolutions = 200
						Ensure = "Present"
					}
				)
				RemoteFarmTrusts = @(
					@{
						Name = "CentralSearchFarm"
						RemoteWebAppUrl = "https://search.sharepoint.contoso.com"
						LocalWebAppUrl = "https://local.sharepoint2.contoso.com"
						Ensure = "Present"
					}
				)
				SecurityTokenServiceConfig = @{
				    IsSingleInstance = "Yes"
					Name = "SPSecurityTokenService"
					NameIdentifier = "00000003-0000-0ff1-ce00-000000000000@9f11c5ea-2df9-4950-8dcf-da8cd7aa4eff"
					UseSessionCookies = $false
					AllowOAuthOverHttp = $false
					AllowMetadataOverHttp = $false
				}
				TimerJobStates = @(
					@{
						TypeName = 'Microsoft.Office.Access.Services.Administration.AccessServicesMonitorTimerJob'
						Enabled = $false
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.InfoPath.Server.Administration.FormsMaintenanceJobDefinition'
						Enabled = $true
						Schedule = 'daily between 01:00:00 and 23:30:00'
					},
					<#
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'hourly at 0'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'every 30 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Project.Server.Administration.ServiceApplicationLevelTimerJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 03:00:00'
					}, 
					#>
					@{
						TypeName = 'Microsoft.Office.RecordsManagement.Preservation.PreservationJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.ActivityFeed.ActivityFeedCleanupUPAJob'
						Enabled = $true
						Schedule = 'daily between 03:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.ActivityFeed.ActivityFeedUPAJob'
						Enabled = $true
						Schedule = 'every 10 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Administration.ApplicationServerAdministrationServiceJob'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					<#
					@{
						# PowerShell DSC resource MSFT_SPTimerJobState  failed to execute Test-TargetResource functionality with error message: No timer jobs found. Please check the input values 
						TypeName = 'Microsoft.Office.Server.Administration.ApplicationServerJob'
						Enabled = $false
						Schedule = 'weekly at sat 05:00:00'
					},
					#>
					@{
						TypeName = 'Microsoft.Office.Server.Administration.LicensingJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Administration.StateServiceExpiredSessionJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Administration.UserProfileApplication+LanguageSynchronizationJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Audience.AudienceCompilationJob'
						Enabled = $true
						Schedule = 'weekly between sat 01:00:00 and sat 01:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Diagnostics.StaticSqmDataCollectionJob'
						Enabled = $true
						Schedule = 'daily between 00:00:00 and 00:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Directory.SharePoint.Provider.UserChangeJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Directory.SharePoint.Provider.UserPointPublishingOperationsJob'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.CrawlReportCleanupJobDefinition'
						Enabled = $true
						Schedule = 'daily between 00:01:00 and 00:33:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.CrawlStoreRebalancerJobDefinition'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.CustomDictionaryDeploymentJobDefinition'
						Enabled = $true
						Schedule = 'every 10 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.IndexingScheduleJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.PrepareQuerySuggestionsJobDefinition'
						Enabled = $true
						Schedule = 'daily between 01:00:00 and 23:30:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.QueryClassificationDictionaryJobDefinition'
						Enabled = $true
						Schedule = 'every 30 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.QueryClassificationDictionaryPushJobDefinition'
						Enabled = $true
						Schedule = 'every 30 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.QueryClassificationDictionaryUpdateTimerJobDefinition'
						Enabled = $true
						Schedule = 'every 30 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.QueryLogJobDefinition'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.QuerySuggestionsJobDefinition'
						Enabled = $true
						Schedule = 'daily between 03:00:00 and 06:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.SearchSQMTimerJobDefinition'
						Enabled = $true
						Schedule = 'weekly at sat 03:19:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.SpellingCustomizationsUpgradeJobDefinition'
						Enabled = $false
						Schedule = 'hourly between 10 and 20'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.SpellingDictionaryUpdateJobDefinition'
						Enabled = $true
						Schedule = 'daily between 01:00:00 and 03:30:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Administration.TopologyCleanupJobDefinition'
						Enabled = $true
						Schedule = 'daily between 00:01:00 and 00:33:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Analytics.AnalyticsEventStoreRetentionJobDefinition'
						Enabled = $true
						Schedule = 'weekly at mon 23:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Analytics.AnalyticsJobDefinition'
						Enabled = $true
						Schedule = 'every 10 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Analytics.UsageAnalyticsJobDefinition'
						Enabled = $true
						Schedule = 'every 10 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Monitoring.HealthStatUpdateJobDefinition'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.Search.Monitoring.TraceDiagnosticsProvider'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.Office.Server.SocialData.SocialDataMaintenanceJob'
						Enabled = $true
						Schedule = 'hourly between 30 and 30'
					},
					@{
						TypeName = 'Microsoft.Office.Server.SocialData.SocialRatingSyncJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.ADImport.ProfileAttributeSyncJob'
						Enabled = $true
						Schedule = 'every 10 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.ADImport.UpdateMembershipsAndRelationshipsJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.ADImport.UserProfileADImportJob'
						Enabled = $false
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.FeedCacheRepopulationJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 30 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.LanguageAndRegionSyncJob'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.LMTRepopulationJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.MySiteCleanupJob'
						Enabled = $true
						Schedule = 'daily between 01:00:00 and 06:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.MySiteEmailJob'
						Enabled = $true
						Schedule = 'monthly between 15 22:00:00 and 15 22:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.UserProfileApplicationOperationsJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.UserProfileChangeCleanupJob'
						Enabled = $true
						Schedule = 'daily between 22:00:00 and 22:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.UserProfileChangeJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.WSSProfileSyncJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.Server.UserProfiles.WSSSweepSyncJob'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.TranslationServices.LanguageJob'
						Enabled = $true
						Schedule = 'weekly between sun 00:00:00 and sun 00:00:00'
					},
					<#
					@{
						TypeName = 'Microsoft.Office.TranslationServices.QueueJob'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.Office.TranslationServices.QueueJob'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 0'
					},
					#>
					@{
						TypeName = 'Microsoft.Office.TranslationServices.RemoveJobHistoryJobDefinition'
						Enabled = $true
						Schedule = 'weekly between sun 00:00:00 and sun 00:00:00'
					},
					@{
						TypeName = 'Microsoft.Office.Word.Server.Service.RemoveJobHistoryJobDefinition'
						Enabled = $true
						Schedule = 'weekly between sun 00:00:00 and sun 00:00:00'
					},
					@{
						TypeName = 'Microsoft.PerformancePoint.Scorecards.BIMaintenanceJob'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPAntivirusJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPAppInstallationJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPAppStateQueryJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPAppStatisticsProviderJobDefinition'
						Enabled = $false
						Schedule = 'daily between 00:00:01 and 04:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPAutoHostedAppInstanceCounterJobDefinition'
						Enabled = $true
						Schedule = 'weekly at sun 05:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPConfigurationCollectionCacheRefreshJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPConfigurationCollectionFullCacheRefreshJobDefinition'
						Enabled = $true
						Schedule = 'daily between 22:00:00 and 02:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPConfigurationRefreshJobDefinition'
						Enabled = $true
						Schedule = 'every 15 seconds'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPDatabaseLocksJobDefinition'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPDeleteJobHistoryJobDefinition'
						Enabled = $true
						Schedule = 'daily between 04:41:00 and 04:43:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPExtensionMapRefreshJobDefinition'
						Enabled = $true
						Schedule = 'every 10 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPIncomingEmailJobDefinition'
						Enabled = $true
						Schedule = 'every 1 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPInternalAppStateQueryJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPLicenseRenewalJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPPasswordManagementJobDefinition'
						Enabled = $true
						Schedule = 'daily between 00:31:00 and 00:33:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPPendingDistributionGroupJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPProductVersionJobDefinition'
						Enabled = $true
						Schedule = 'daily between 00:51:00 and 00:53:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPSiteLookupRefreshJobDefinition'
						Enabled = $true
						Schedule = 'every 10 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPSqmTimerJobDefinition'
						Enabled = $true
						Schedule = 'daily between 04:31:00 and 04:33:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPStartODLErrorLogUploadJobDefinition'
						Enabled = $false
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPTimerRecycleJobDefinition'
						Enabled = $true
						Schedule = 'daily at 06:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPUpgradeSessionCleanupJobDefinition'
						Enabled = $true
						Schedule = 'weekly at sun 01:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPUsageImportJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 37 and 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPUsageMaintenanceJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPUsageProcessingJobDefinition'
						Enabled = $false
						Schedule = 'daily between 01:00:00 and 03:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.SPWorkflowJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Administration.Usage.SPDatabaseWaitStatisticsJobDefinition'
						Enabled = $true
						Schedule = 'hourly between 0 and 59'
					},
					@{
						TypeName = 'Microsoft.SharePoint.AppManagement.SPAppAnalyticsUploaderJobDefinition'
						Enabled = $true
						Schedule = 'daily between 04:00:00 and 05:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDatabaseIOSqlDiagnosticsProvider'
						Enabled = $false
						Schedule = 'every 2 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDatabaseServerDiagnosticsPerformanceCounterProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsBlockingQueryProvider'
						Enabled = $true
						Schedule = 'every 15 seconds'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsEventLogProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsMetricsProvider'
						Enabled = $true
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsSqlDmvProvider'
						Enabled = $false
						Schedule = 'every 30 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsSqlMemoryProvider'
						Enabled = $false
						Schedule = 'every 15 seconds'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsULSProvider'
						Enabled = $false
						Schedule = 'every 10 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPDiagnosticsXEventQueryDataProvider'
						Enabled = $true
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPIOIntensiveQueryDiagnosticProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPSiteSizeDiagnosticProvider'
						Enabled = $false
						Schedule = 'daily between 22:00:00 and 23:00:00'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPSqlBlockingReportDiagnosticProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPSqlDeadlockDiagnosticProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Diagnostics.SPWebFrontEndDiagnosticsPerformanceCounterProvider'
						Enabled = $false
						Schedule = 'every 1 minutes at 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Publishing.SearchChangeLogGeneratorJobDefinition'
						Enabled = $true
						Schedule = 'every 5 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.SPConnectedServiceApplicationAddressesRefreshJob'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 0'
					},
					@{
						TypeName = 'Microsoft.SharePoint.Taxonomy.ContentTypeSync.Internal.HubTimerJobDefinition'
						Enabled = $true
						Schedule = 'daily between 01:00:00 and 02:00:00'
					}
					<#
					# PowerShell DSC resource MSFT_SPTimerJobState  failed to execute Test-TargetResource functionality with error message: No timer jobs found. Please check the input values 
					@{
						TypeName = 'Word Automation Services Timer Job'
						Enabled = $true
						Schedule = 'every 15 minutes between 0 and 0'
					}
					#>
				)
				TrustedIdentityTokenIssuers = @(
					@{
						Name = 'Contoso'
						Description = 'Contoso'
						Realm = 'https://sharepoint.contoso.com'
						SignInUrl = 'https://adfs.contoso.com/adfs/ls/'
						IdentifierClaim = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
						SigningCertificateThumbPrint = '62914576dc0afac83c4804bcc2c1b700a61139fe'
						ClaimMappings = @(
							@{
								Name = 'Email'
								IncomingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
							},
							@{
								Name = 'Role'
								IncomingClaimType = 'http://schemas.xmlsoap.org/ExternalSTSGroupType'
								LocalClaimType = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
							}
						)
						Realms = @(
							@{
								RealmUrl = 'https://search.contoso.com'
								RealmUrn = 'urn:sharepoint:contoso:search'
							},
							@{
								RealmUrl = 'https://intranet.contoso.com'
								RealmUrn = 'urn:sharepoint:contoso:intranet'
							}
						)
						ClaimProviderName = 'LDAPCP'
						ProviderSignOutUri = 'https://adfs.contoso.com/adfs/ls/'
						UseWReplyParameter = $true
						Ensure = 'Present'
					}
				)
				TrustedRootAuthorities = @(
					@{
						Name                  = 'Contoso'
						CertificateThumbprint = '62914576dc0afac83c4804bcc2c1b700a61139fe'
						Ensure                = 'Present'
					}
				)
				TrustedSecurityTokenIssuers = @(
					@{
						Name = 'HighTrustAddins'
						Description = 'Trust for Provider-hosted high-trust add-ins'
						RegisteredIssuerNameIdentifier = '22222222-2222-2222-2222-222222222222'
						IsTrustBroker = $true
						SigningCertificateThumbprint = '62914576dc0afac83c4804bcc2c1b700a61139fe'
						Ensure = 'Present'
					}
				)
				WebApplications = @(
                    @{
                        Name = 'Sharepoint Sites'
						AppDomains = @(
							@{
								AppDomain = 'contosointranetapps.com'
								Zone = 'Default'
								Port = 443
								SSL = $true
							}
						)
						ApplicationPool = 'SharePoint Service Applications'
						ApplicationPoolAccount = 'contoso\svc.dev.spportalapp'
						Binding = @{
							Port = 443
							Protocol = 'https'
							Store = 'My'
							Thumbprint = '‎a474746bf61b31183bb133edf85107688015b5c4'
						}
						BlockedFileTypes = @{
							Blocked = @('exe', 'dll', 'msi')
							#EnsureBlocked = @('exe', 'dll', 'msi')
							#EnsureAllowed = @('pdf', 'docx', 'xslx')
						}
						CacheAccounts = @{
							SuperReaderAlias = 'contoso\svc.dev.spsr'
							SuperUserAlias = 'contoso\svc.dev.spsu'
							SetWebAppPolicy = $true
						}
						ClientCallableSettings = @{
							MaxResourcesPerRequest = 16
							MaxObjectPaths = 256
							ExecutionTimeout = 90
							RequestXmlMaxDepth = 32
							EnableXsdValidation = $true
							EnableStackTrace = $false
							RequestUsageExecutionTimeThreshold = 800
							EnableRequestUsage = $true
							LogActionsIfHasRequestException = $true
							ProxyLibraries = @(
								@{
									AssemblyName = "Microsoft.Online.SharePoint.Dedicated.TenantAdmin.ServerStub, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"
					                SupportAppAuthentication = $true
								}
							)
						}
						ContentDatabases = @(
							@{
								Name = 'CONTENT_PWA_01'
								DatabaseServer = 'SPTestSQL'
								Enabled = $true
								WarningSiteCount = 2000
								MaximumSiteCount = 5000
								Ensure = 'Present'
								SiteCollections = @(
									@{
										Url = 'https://portal.contoso.com'
										Owner = 'contoso\Tier 1 SharePoint Admins'
										Name = 'Portal'
										Template = 'STS#0'
										HostNamedSiteCollection = $false
									},
									@{
										Url = 'https://my.contoso.com'
										Owner = 'contoso\Tier 1 SharePoint Admins'
										Name = 'OneDrive'
										Template = 'SPSMSITEHOST#0'
										HostNamedSiteCollection = $true
									},
									@{
										Url = 'https://pwa.contoso.com'
										Owner = 'contoso\Tier 1 SharePoint Admins'
										Name = 'PWA Root'
										Template = 'PWA#0'
										HostNamedSiteCollection = $true
										Features = @(
											@{
												Name = 'PWASITE'
												Version = '1.0.0.0'
												FeatureScope = 'Site'
												Ensure = 'Present'
											}
										)
										PropertyBag = @(
											@{
												Key = 'MySiteKey1'
												Value = 'MySiteValue1'
												Ensure = 'Present'
											},
											@{
												Key = 'MySiteKey2'
												Value = 'MySiteValue2'
												Ensure = 'Present'
											}
										)
										PWASettings = @{
											CreateProjectSiteMode = 'DontCreate'
											EnableProjectSiteSync = $true
											EnableProjectSiteSyncForSPTaskLists = $true
											EnableProjectWebAppSync = $true
											EnforceServerCurrency = $true
											ServerCurrency = 'USD'
											PermissionMode = 'ProjectServer'
											ProjectProfessionalMinBuildNumber = '16.0.0.0'
											TimeSheet = @{
												AllowFutureTimeReporting = $false
												AllowNewPersonalTasks = $false
												AllowTopLevelTimeReporting = $true
												EnableOvertimeAndNonBillableTracking = $true
												EnableTimesheetAuditing = $true
												DefaultReportingUnit = 'Days'
												DefaultTimesheetCreationMode = 'NoPrepopulation'
												DefaultTrackingMode = 'PercentComplete'
												DefaultTrackingUnit = 'Days'
												FixedApprovalRouting = $true
												ForceTrackingModeForAllProjects = $true
												HoursInStandardDay = 8
												HoursInStandardWeek = 40
												MaxHoursPerDay = 16
												MaxHoursPerTimesheet = 120
												MinHoursPerTimesheet = 0
												RequireLineApprovalBeforeTimesheetApproval = $false
												RequireTaskStatusManagerApproval = $true
												SingleEntryMode = $true
											}
										}
										SharePointDesigner = @{
											AllowSharePointDesigner = $false
											AllowDetachPagesFromDefinition = $false
											AllowCustomiseMasterPage = $false
											AllowManageSiteURLStructure = $false
											AllowCreateDeclarativeWorkflow = $false
											AllowSavePublishDeclarativeWorkflow = $false
											AllowSaveDeclarativeWorkflowAsTemplate = $false
										}
									}
								)
							},
							@{
								Name = 'CONTENT_PWA_02'
								DatabaseServer = 'SPTestSQL'
								Enabled = $true
								WarningSiteCount = 2000
								MaximumSiteCount = 5000
								Ensure = 'Present'
							}
						)
						ManagedPaths = @(
							@{
								RelativeUrl = 'personal'
								Explicit = $false
								HostHeader = $false
								Ensure = 'Present'
							}
						)
						GeneralSettings = @{
							TimeZone = 38 # (GMT-07:00) Arizona
							Alerts = $true
							AlertsLimit = 999
							RSS = $true
							BlogAPI = $true
							BlogAPIAuthenticated = $true
							BrowserFileHandling = 'Strict'
							SecurityValidation = $true
							SecurityValidationExpires = $true
							SecurityValidationTimeOutMinutes = 120
							RecycleBinEnabled = $true
							RecycleBinCleanupEnabled = $true
							SecondStageRecycleBinQuota = 50
							MaximumUploadSize = 500
							CustomerExperienceProgram = $false
							AllowOnlineWebPartCatalog = $false
							SelfServiceSiteCreationEnabled = $true
							PresenceEnabled = $false
							DefaultQuotaTemplate = 'TeamSite'
						}
						OutgoingEmailSettings = @{
							SMTPServer = 'smtp.contoso.com'
							FromAddress = 'sharepoint@contoso.com'
							ReplyToAddress = 'noreply@contoso.com'
							CharacterSet = '65001'
						}
						OwnerAlias = 'contoso\scrist.t1.so'
						Permissions = @{
							<#
						    ListPermissions = @('Manage Lists', 'Override List Behaviors', 'Add Items', 'Edit Items', 'Delete Items', 'View Items', 'Approve Items', 'Open Items', 'View Versions', 'Delete Versions', 'Create Alerts', 'View Application Pages')
							SitePermissions = @('Manage Permissions', 'View Web Analytics Data', 'Create Subsites', 'Manage Web Site', 'Add and Customize Pages', 'Apply Themes and Borders', 'Apply Style Sheets', 'Create Groups', 'Browse Directories', 'Use Self-Service Site Creation', 'View Pages', 'Enumerate Permissions', 'Browse User Information', 'Manage Alerts', 'Use Remote Interfaces', 'Use Client Integration Features', 'Open', 'Edit Personal User Information')
							PersonalPermissions = @('Manage Personal Views', 'Add/Remove Personal Web Parts', 'Update Personal Web Parts')
							#>
							AllPermissions = $true
						}
						PeoplePickerSettings = @{
							ActiveDirectoryCustomFilter = $null
							ActiveDirectoryCustomQuery = $null
							ActiveDirectorySearchTimeout = 30
							OnlySearchWithinSiteCollection = $false
							SearchActiveDirectoryDomains = @(
								@{
									FQDN = "contoso.com"
									IsForest = $false
									AccessAccount = 'contoso\svc.dev.spsaapp'
									AccessAccountPassword = 'Password123!@#'
								}
							)
						}
						Policy = @{
							Members = @(
								@{
									ActAsSystemAccount = $true
									IdentityType = 'Claims'
									PermissionLevel = 'Full Control'
									Username = 'contoso\user1'
								},
								@{
									IdentityType = 'Claims'
									PermissionLevel = 'Full Read'
									Username = 'contoso\Group1'
								}
							)
							<#
							MembersToInclude = @(
								@{
									ActAsSystemAccount = $true
									IdentityType = 'Claims'
									PermissionLevel = 'Full Control'
									Username = 'contoso\user1'
								},
								@{
									IdentityType = 'Claims'
									PermissionLevel = 'Full Read'
									Username = 'contoso\Group1'
								}
							)
							MembersToExclude = @('contoso\user3')
							#>
							SetCacheAccountsPolicy = $true
						}
						PropertyBag = @(
							@{
								Key = 'MyWebAppKey1'
								Value = 'MyWebAppValue1'
								Ensure = 'Present'
							},
							@{
								Key = 'MyWebAppKey2'
								Value = 'MyWebAppValue2'
								Ensure = 'Present'
							}
						)
						SelfServiceSiteCreation = @{
							Enabled = $true
							OnlineEnabled = $false
							QuotaTemplate = 'TeamSite'
							ShowStartASiteMenuItem = $true
							CreateIndividualSite = $false
							PolicyOption = 'MustHavePolicy'
							RequireSecondaryContact = $true
							CustomFormUrl = 'https://ssc.contoso.com/ssc'
							ManagedPath = 'sites'
							AlternateUrl = $null
							UserExperienceVersion = 'Latest'
						}
						SharePointDesigner = @{
							AllowSharePointDesigner = $false
							AllowDetachPagesFromDefinition = $false
							AllowCustomiseMasterPage = $false
							AllowManageSiteURLStructure = $false
							AllowCreateDeclarativeWorkflow = $false
							AllowSavePublishDeclarativeWorkflow = $false
							AllowSaveDeclarativeWorkflowAsTemplate = $false
						}
						SiteUseAndDeletion = @{
							SendUnusedSiteCollectionNotifications = $true
							UnusedSiteNotificationPeriod = 90
							AutomaticallyDeleteUnusedSiteCollections = $false
							UnusedSiteNotificationsBeforeDeletion = 24
						}
						SuiteBar = @{
							SuiteNavBrandingLogoNavigationUrl = 'https://portal.contoso.com'
							SuiteNavBrandingLogoTitle = 'This is my Logo'
							SuiteNavBrandingLogoUrl = 'https://portal.contoso.com/images/logo.gif'
							SuiteNavBrandingText = 'SharePointDSC WebApp'
							#SuiteBarBrandingElementHtml = '<div>SharePointDSC WebApp</div>'
						}
						ThrottlingSettings = @{
							AdminThreshold = 10000
							AllowObjectModelOverride = $false
							ChangeLogEnabled = $true
							ChangeLogExpiryDays = 90
							EventHandlersEnabled = $true
							ListViewLookupThreshold = 10
							ListViewThreshold = 5000
							HappyHour = @{
								Hour     = 3
								Minute   = 0
								Duration = 1
							}
							HappyHourEnabled = $true
							RequestThrottling = $true
							UniquePermissionThreshold = 500
						}
						TimerJobStates = @(
							@{
								TypeName = 'Microsoft.Office.Access.Services.Timers.AccessServicesExportToSharePointListTimerJob'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 0'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.DarProcessingJobDefinition'
								Enabled = $true
								Schedule = 'every 10 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.DarProcessingMuxJobDefinition'
								Enabled = $true
								Schedule = 'every 10 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.HiPriPolicyProcessingJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.HiPriPolicyProcessingMuxJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.PolicyProcessingJobDefinition'
								Enabled = $true
								Schedule = 'daily between 03:30:00 and 04:30:00'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.UnifiedPolicyFileSyncJobDefinition'
								Enabled = $true
								Schedule = 'every 5 minutes at 0'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.UnifiedPolicyFileSyncUrgentJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes at 0'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.Internal.UnifiedPolicyOnPremSyncTimerJob'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.CompliancePolicy.SharePoint.UnifiedPolicySyncStatusUpdateTimerJob'
								Enabled = $true
								Schedule = 'every 5 minutes at 0'
							},
							@{
								TypeName = 'Microsoft.Office.DocumentManagement.Internal.DocIdEnableWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'daily between 21:30:00 and 21:50:00'
							},
							@{
								TypeName = 'Microsoft.Office.DocumentManagement.Internal.DocIdWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 22:30:00'
							},
							@{
								TypeName = 'Microsoft.Office.DocumentManagement.Internal.DocumentSetMetadataSyncJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.DocumentManagement.Internal.DocumentSetTemplateUpdateJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.InformationPolicy.ProjectPolicyTeamMailBoxJobDefinition'
								Enabled = $true
								Schedule = 'daily between 01:00:00 and 02:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.Internal.ExpirationJobDefinition'
								Enabled = $true
								Schedule = 'weekly at sat 23:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.Internal.HoldReportJobDefinition'
								Enabled = $true
								Schedule = 'daily between 23:30:00 and 23:45:00'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.Internal.PolicyUpdatesJobDefinition'
								Enabled = $true
								Schedule = 'weekly at fri 23:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.Internal.RecordsRepositoryJobDefinition'
								Enabled = $true
								Schedule = 'daily between 23:30:00 and 23:45:00'
							},
							@{
								TypeName = 'Microsoft.Office.RecordsManagement.SearchAndProcess.SearchAndProcessWIJD'
								Enabled = $true
								Schedule = 'daily between 22:30:00 and 23:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.Server.Search.Administration.VideoQueryRuleProvisionerJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 00:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.Server.UserProfiles.InteractiveMySiteInstantiationWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.Server.UserProfiles.MySiteHostAutoUpgradeJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 23:59:00'
							},
							@{
								TypeName = 'Microsoft.Office.Server.UserProfiles.MySitesAutoUpgradeJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 02:00:00'
							},
							@{
								TypeName = 'Microsoft.Office.Server.UserProfiles.NonInteractiveMySiteInstantiationWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.Server.UserProfiles.SecondInteractiveMySiteInstantiationWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.Office.Workflow.BulkWorkflowWIJD'
								Enabled = $true
								Schedule = 'daily between 23:00:00 and 23:30:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPActivitiesAutoCleanJobDefinition'
								Enabled = $true
								Schedule = 'weekly at sat 05:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAntivirusScanningChangeJob'
								Enabled = $false
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAntivirusScanningFullJob'
								Enabled = $false
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAppInstallationQueueJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes at 0'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAsyncFeatureActivationJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAsyncFeatureActivationJobDefinition2'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPAuditLogTrimmingJobDefinition'
								Enabled = $true
								Schedule = 'monthly at 31 02:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPBulkOperationDetectionJobDefinition'
								Enabled = $false
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPChangeLogJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPCleanupLimitedPermsJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPComplianceSyncDefaultTagWIJD'
								Enabled = $true
								Schedule = 'every 5 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPCompressionScanningFullJob'
								Enabled = $false
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPContentDatabaseManageAutoIndexesForLargeListsJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 00:30:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPDeadSiteDeleteJobDefinition'
								Enabled = $false
								Schedule = 'weekly at sat 21:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPDeferredAclApplicationJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes at 0'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPDeleteUpgradeEvalSiteJobDefinition'
								Enabled = $true
								Schedule = 'daily between 01:00:00 and 01:30:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPDiskQuotaWarningJobDefinition'
								Enabled = $true
								Schedule = 'weekly at sat 22:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPDocumentListInfoSampleJobDefinition'
								Enabled = $true
								Schedule = 'daily at 23:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPFileFragmentsTableCleanupJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPFilePostProcessorJob'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPFixSiteStorageMetricsJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPGradualIndexJobDefinition'
								Enabled = $true
								Schedule = 'every 5 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPHighVolumeWriteAntivirusIncJob'
								Enabled = $false
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPIdentityColumnMaintenanceJobDefinition'
								Enabled = $true
								Schedule = 'weekly at sat 05:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPImmediateAlertsJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPMicroserviceWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPOverQuotaNotificationJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 00:30:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPOverQuotaSingleMessageJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPRecalculateThicketsJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPRecycleBinCleanupJobDefinition'
								Enabled = $true
								Schedule = 'daily at 00:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPRepairSiteJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPRepairThicketsJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSiteDeletionJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSiteInfoJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSiteMasterInvalidationJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSolutionDailyResourceUsageJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSolutionResourceUsageLogJobDefinition'
								Enabled = $true
								Schedule = 'every 3 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPSolutionResourceUsageUpdateJobDefinition'
								Enabled = $true
								Schedule = 'every 5 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPStorageMetricsProcessingJobDefinition'
								Enabled = $true
								Schedule = 'every 5 minutes between 0 and 59'
							},
							<#
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPUpgradeSiteCollectionJobDefinition'
								Enabled = $true
								Schedule = 'every 10 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPUpgradeSiteCollectionJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 02:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPUpgradeSiteCollectionJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							#>
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPUpgradeWorkItemJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:30:00 and 23:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPWebInfoJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPWorkflowAutoCleanJobDefinition'
								Enabled = $true
								Schedule = 'daily between 22:00:00 and 06:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Administration.SPWorkflowFailOverJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Administration.SPSitemapJobDefinition'
								Enabled = $true
								Schedule = 'daily between 02:00:00 and 23:59:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.ApprovalJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.CreateVariationHierarchiesJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.NotificationJobDefinition'
								Enabled = $true
								Schedule = 'daily between 00:00:00 and 00:00:00'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.PersistedNavigationTermSetSyncJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.PropagateListItemJob'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.PropogateVariationPageJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.SpawnSitesJobDefinition'
								Enabled = $true
								Schedule = 'every 30 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Publishing.Internal.UnpublishJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Taxonomy.ContentTypeSync.Internal.SubscriberTimerJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Taxonomy.HiddenListFullSyncJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Taxonomy.UpdateHiddenListJobDefinition'
								Enabled = $true
								Schedule = 'hourly between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Translation.TranslationExportTimerJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Translation.TranslationImportTimerJobDefinition'
								Enabled = $true
								Schedule = 'every 15 minutes between 0 and 59'
							},
							@{
								TypeName = 'Microsoft.SharePoint.Webhooks.SPWebhookProcessingJobDefinition'
								Enabled = $true
								Schedule = 'every 1 minutes between 0 and 59'
							}
						)
						UseHostNamedSiteCollections = $true
						WebAppUrl = 'https://portal.contoso.com'
						WorkflowSettings = @{
							EmailToNoPermissionWorkflowParticipantsEnable = $false
							ExternalWorkflowParticipantsEnabled = $false
							UserDefinedWorkflowsEnabled = $false
						}
						Zones = @(
							@{
								Authentication = @{
									AuthenticationMethod = 'WindowsAuthentication'
								}
								BlobCacheSettings = @{
									EnableCache = $true
									Location = 'e:\BlobCache'
									MaxAgeInSeconds = 3600
									MaxSizeInGB = 10
									FileTypes = '\.(gif|jpg|png|css|js)$'
								}
								Name = 'Default'
							},
							@{
								Authentication = @{
									AuthenticationMethod = 'Federated'
									AuthenticationProvider = 'Contoso'
								}
								BlobCacheSettings = @{
									EnableCache = $true
									Location = 'e:\BlobCache'
									MaxAgeInSeconds = 3600
									MaxSizeInGB = 10
									FileTypes = '\.(gif|jpg|png|css|js)$'
								}
								Extension = @{
									Name = 'Contoso Intranet Zone'
									AllowAnonymous = $false
									HostHeader = 'intranet.contoso.local'
									Path = 'c:\inetpub\wwwroot\wss\VirtualDirectories\intranet'
									Port = 80
									Url = 'http://intranet.contoso.local'
									UseSSL = $false
									Ensure = 'Present'
								}
								Name = 'Intranet'
							}
						)
						Ensure = 'Present'
					}
                )
            }
        }
    }
}