Configuration SharePointServerContentDatabase
{
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$WebApplication,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$ContentDatabase
	)

    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SharePointServerDeployment

    $WebApplicationNameNoSpaces = $WebApplication.Name.Replace(' ', '')

    SPContentDatabase ($WebApplicationNameNoSpaces + $contentDatabase.Name) {
        Name = $ContentDatabase.Name
        DatabaseServer = $ContentDatabase.DatabaseServer
        Enabled = $ContentDatabase.Enabled
        WarningSiteCount = $ContentDatabase.WarningSiteCount
        MaximumSiteCount = $ContentDatabase.MaximumSiteCount
        WebAppUrl = $WebApplication.WebAppUrl
		Ensure = $ContentDatabase.Ensure
    }

    # Site Collections
    foreach($SiteCollection in $contentDatabase.SiteCollections) {
        SharePointServerSiteCollection ($WebApplicationNameNoSpaces + "_" + $SiteCollection.Name.Replace(' ', '')) {
            WebApplication = $WebApplication
			ContentDatabase = $ContentDatabase
            SiteCollection = $SiteCollection
            DependsOn = "[SPContentDatabase]$($WebApplicationNameNoSpaces)$($contentDatabase.Name)"
        }
    }
                
} 
