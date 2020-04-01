Configuration SharePointServerIIS
{
    param
    (
        [Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable] $CustomHeaders,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [bool] $DisableLoopbackCheck = $false,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $LogFormat,
        
        [ValidateNotNullOrEmpty()]
        [bool] $LogLocalTimeRollover = $true,
 
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $LogPath,
 
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $LogPeriod,

        [Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable] $Node,
        
        [ValidateNotNullOrEmpty()]
        [bool] $RemoveIISDefaults = $false,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TraceLogPath,
 
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Present", "Absent")]
        [string] $Ensure
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration -ModuleVersion 3.1.1
    Import-DscResource -ModuleName SharePointServerDeployment

    if ($Node -eq $null)
    {
        throw "Node parameter must be defined (when calling SharePointServerIIS)."
	}
                
    if ($Node.InternetInformationServer -eq $null -and $Ensure -eq 'Present')
    {
        throw "InternetInformationServer for Node '$($Node.NodeName)' must be defined."        
	}

    $LoopbackCheckValueData = '0'
    if ($DisableLoopbackCheck) {
        $LoopbackCheckValueData = '1'
    }

    Registry DisableLoopBackCheck {
        Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
        ValueName = 'DisableLoopbackCheck'
        ValueData = $LoopbackCheckValueData
        ValueType = 'Dword'
        Force = $true
        Ensure = $Ensure
    }

    WindowsFeature IIS {
        Name = 'Web-Server'
        Ensure = $Ensure
    }

    WindowsFeature IIS-ManagementTools {
        Name = 'Web-Mgmt-Console'
        DependsOn = '[WindowsFeature]IIS'
        Ensure = $Ensure
    }

    if ($Ensure -eq 'Present') 
    {
        xIISLogging IIS-Logging {
            LogPath = $LogPath
            LogPeriod = $LogPeriod
            LogLocalTimeRollover = $LogLocalTimeRollover
            LogFormat = $LogFormat
            DependsOn = '[WindowsFeature]IIS'
        }

        xWebSiteDefaults IISSiteDefaults {
            IsSingleInstance = 'Yes'
            LogFormat = $LogFormat
            LogDirectory = $LogPath
            TraceLogDirectory = $TraceLogPath
            DependsOn = '[WindowsFeature]IIS'
        }

        if ($RemoveIISDefaults) {

            # Remove the default web site
            xWebsite RemoveDefaultSite {
                Ensure = 'Absent'
                Name = 'Default Web Site'
                PhysicalPath = 'C:\inetpub\wwwroot'
                DependsOn = '[WindowsFeature]IIS'
            }

            #region Remove all default application pools from IIS 
            
            xWebAppPool RemoveDotNet2Pool {
                Name = '.NET v2.0'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }

            xWebAppPool RemoveDotNet2ClassicPool {
                Name = '.NET v2.0 Classic'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }

            xWebAppPool RemoveDotNet45Pool {
                Name = '.NET v4.5'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }

            xWebAppPool RemoveDotNet45ClassicPool {
                Name = '.NET v4.5 Classic'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }

            xWebAppPool RemoveClassicDotNetPool {
               Name = 'Classic .NET AppPool'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }

            xWebAppPool RemoveDefaultAppPool {
                Name = 'DefaultAppPool'
                Ensure = 'Absent'
                DependsOn = '[WindowsFeature]IIS'
            }
        }

        if ($CustomHeaders -ne $null)
        {
            foreach ($CustomHeader in $CustomHeaders)
            {
                if ($Node.InternetInformationServer.CustomHeaders -eq $null)
                {
                    throw "CustomHeaders for Node '$($Node.NodeName)' must be defined."        
				}

                $NodeCustomHeader = $Node.InternetInformationServer.CustomHeaders | ? { $_.Name -eq $CustomHeader.Name }

                if ($NodeCustomHeader -eq $null)
                {
                    throw "CustomHeader '$($CustomHeader.Name)' for Node '$($Node.NodeName)' must be defined."        
				}

                if ($NodeCustomHeader.Value -eq $null)
                {
                    throw "Value for Custom Header '$($CustomHeader.Name)' for Node '$($Node.NodeName)' must be defined."        
				}

                SharePointServerIISCustomHeader SetIISHeader {
                    HeaderName = $CustomHeader.Name
                    HeaderValue = $NodeCustomHeader.Value
			        Ensure = $CustomHeader.Ensure
                    DependsOn = '[WindowsFeature]IIS'
                    PsDscRunAsCredential = $SPSetupCredential
                }
			}
		}
    }

    #endregion

}