Configuration SharePointServerSiteCollection
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$WebApplication,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$ContentDatabase,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$SiteCollection
    )

    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0
    Import-DscResource -ModuleName SharePointServerDeployment

    $WebAppSiteNameNoSpace = "$($WebApplication.Name.Replace(' ', ''))_$($SiteCollection.Name.Replace(' ', ''))"

    $HostHeaderWebApplication = $null
    if (($WebApplication.UseHostNamedSiteCollections -eq $true) -and ($SiteCollection.HostNamedSiteCollection -eq $true)) {
        $HostHeaderWebApplication = $WebApplication.WebAppUrl
    }

    SPSite $WebAppSiteNameNoSpace
	{
        Url = $SiteCollection.Url
        OwnerAlias = $SiteCollection.Owner
        HostHeaderWebApplication = $HostHeaderWebApplication
        Name = $SiteCollection.Name
        Template = $SiteCollection.Template
        ContentDatabase = $ContentDatabase.Name
		# Ensure:  As of Oct 11 2019, Ensure is not a supported property on SPSite DSC Resource
    }

	if ($SiteCollection.PropertyBag -ne $null)
	{
		foreach($PropertyBagItem in $SiteCollection.PropertyBag) 
		{
			$PropertyBagItemKeyNoSpace = $PropertyBagItem.Key.Replace(' ', '')
			SPSitePropertyBag ($SiteCollection.Name.Replace(' ' , '') + '_PropertyBag_' + $PropertyBagItemKeyNoSpace)
			{
				Url = $SiteCollection.Url
				Key = $PropertyBagItem.Key
				Value = $PropertyBagItem.Value
				Ensure = $PropertyBagItem.Ensure
	            DependsOn = "[SPSite]$($WebAppSiteNameNoSpace)"
			}
		}
	}

	if ($SiteCollection.SharePointDesigner -ne $null)
	{
		if ($SiteCollection.Url -eq $WebApplication.WebAppUrl -and
			$WebApplication.SharePointDesigner -ne $null)
		{
			# Test-ConflictingResources : A conflict was detected between resources (WebApplication vs Site Collection Designer Settings)
			throw "SharePoint Designer Settings cannot be set at both the Web Application and Root Site Collection.  Remove SharePointDesigner from either the Web Application or Root Site Collection."
		}

		SPDesignerSettings ($SiteCollection.Name.Replace(' ' , '') + "_SharePointDesigner") 
        {
            WebAppUrl = $SiteCollection.Url
            SettingsScope = "SiteCollection"
            AllowSharePointDesigner = $SiteCollection.SharePointDesigner.AllowSharePointDesigner
            AllowDetachPagesFromDefinition = $SiteCollection.SharePointDesigner.AllowDetachPagesFromDefinition
            AllowCustomiseMasterPage = $SiteCollection.SharePointDesigner.AllowCustomiseMasterPage
            AllowManageSiteURLStructure = $SiteCollection.SharePointDesigner.AllowManageSiteURLStructure
            AllowCreateDeclarativeWorkflow = $SiteCollection.SharePointDesigner.AllowCreateDeclarativeWorkflow
            AllowSavePublishDeclarativeWorkflow = $SiteCollection.SharePointDesigner.AllowSavePublishDeclarativeWorkflow
            AllowSaveDeclarativeWorkflowAsTemplate = $SiteCollection.SharePointDesigner.AllowSaveDeclarativeWorkflowAsTemplate
            DependsOn = "[SPSite]$($WebAppSiteNameNoSpace)"
        }
	}

    # Features (Only 'Site' for Site Collection or 'Web' for FeatureScope)
    foreach($Feature in $SiteCollection.Features) 
	{
        SPFeature ($SiteCollection.Name.Replace(' ' , '') + "_" + $Feature.Name.Replace(' ', '')) 
		{
            Name = $Feature.Name
            Url = $SiteCollection.Url
            FeatureScope = $Feature.FeatureScope
            Version = $Feature.Version
            Ensure = $Feature.Ensure
            DependsOn = "[SPSite]$($WebAppSiteNameNoSpace)"
        }
    }

    # If Project Web App Site, configure PWA Settings
    if ($SiteCollection.Template.ToUpper() -eq 'PWA#0') {
        
        SharePointServerProjectWebApp ConfigureProjectWebApp 
		{
            WebApplication = $WebApplication
            SiteCollection = $SiteCollection
            DependsOn = @( "[SPSite]$($WebAppSiteNameNoSpace)", "[SPFeature]$($SiteCollection.Name.Replace(' ' , ''))_PWASite" )
        }
    }
    
	# Register as the App Catalog within Web Application
	if ($SiteCollection.Template.ToUpper() -eq "APPCATALOG#0") {
		SPAppCatalog ($WebAppSiteNameNoSpace + "_SetAppCatalogSite")
        {
            SiteUrl = $SiteCollection.Url
            DependsOn = "[SPSite]$($WebAppSiteNameNoSpace)"
        }
	}

    # Sub Webs (Recursive)    
    foreach($Web in $SiteCollection.Webs) {
        SharePointServerWeb ($WebAppSiteNameNoSpace + "_" + $Web.Name.Replace(' ', '')) 
		{
            Web = $Web
            DependsOn = "[SPSite]$($WebAppSiteNameNoSpace)"
        }
    }
} 

