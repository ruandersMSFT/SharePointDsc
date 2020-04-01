Configuration SharePointServerDistributedCache
{
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$Node
	)

    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SharePointServerDeployment

	[string] $Ensure = 'Present'

	$NodeRunningDistributedCacheService = $false

	switch ($Node.ServerRole)
	{
		"WebFrontEndWithDistributedCache" { $NodeRunningDistributedCacheService = $true }
		"DistributedCache" { $NodeRunningDistributedCacheService = $true }
		"SingleServerFarm" { $NodeRunningDistributedCacheService = $true }
		"Custom" { $NodeRunningDistributedCacheService = $true }
	}
	

	if ($ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.ServerProvisionOrder -ne $null)
	{
		if ($ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.ServerProvisionOrder.Contains($Node.NodeName))
		{
			if (!$NodeRunningDistributedCacheService)
			{
				throw "Node '$($Node.NodeName)' of ServerRole '$($Node.ServerRole)' is included in the Distributed Cache ServerProvisionOrder property, but is not running the Distributed Cache Service."
			}
		}
		else
		{
			if ($NodeRunningDistributedCacheService)
			{
				throw "Node '$($Node.NodeName)' of ServerRole '$($Node.ServerRole)' is running the Distributed Cache Service, but is not included in the Distributed Cache ServerProvisionOrder property."
			}

			# Node is not in the ServerProvisionOrder array
				$Ensure = 'Absent'
		}
	}

	SPDistributedCacheService DistributedCacheService
    {
        Name                 = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.Name
        CacheSizeInMB        = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.CacheSizeInMB
        CreateFirewallRules  = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.CreateFirewallRules
        ServiceAccount       = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.ServiceAccount
        ServerProvisionOrder = $ConfigurationData.NonNodeData.SharePoint.Farm.DistributedCacheService.ServerProvisionOrder
		Ensure               = $Ensure
    }
               
} 
