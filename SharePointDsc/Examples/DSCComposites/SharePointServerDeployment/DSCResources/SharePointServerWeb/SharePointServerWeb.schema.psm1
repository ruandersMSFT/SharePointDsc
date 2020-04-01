Configuration SharePointServerWeb
{
param
(
[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[System.Collections.Hashtable]$Web

)
    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0

    # https://github.com/PowerShell/SharePointDsc/wiki/SPWeb
    SPWeb ($Web.Name.Replace(' ' , '')) {
        Url =  $Web.Url
        Ensure = $Web.Ensure
        Name = $Web.Name
        Language = $Web.Language
        Template = $Web.Template
        UniquePermissions = $Web.UniquePermissions
        UseParentTopNav = $Web.UseParentTopNav
        AddToQuickLaunch = $Web.AddToQuickLaunch
        AddToTopNav = $Web.AddToTopNav
        RequestAccessEmail = $Web.RequestAccessEmail
    }

     # Features (Only 'Web' for FeatureScope)
    foreach($Feature in $Web.Features) {
        SPFeature ($Web.Name.Replace(' ' , '') + "_" + $Feature.Name.Replace(' ', '')) {
            Name                 = $Feature.Name
            Url                  = $Web.Url
            FeatureScope         = $Feature.FeatureScope
            Version              = $Feature.Version
            Ensure = $Feature.Ensure
            PsDscRunAsCredential = $SPFarmCredential
            DependsOn = "[SPWeb]$($Web.Name.Replace(' ' , ''))"
        }
    }

     foreach($ChildWeb in $Web.Webs) {
        SharePointServerWeb ($Web.Name.Replace(' ' , '') + "_" + $ChildWeb.Name.Replace(' ', '')) {
            Web = $ChildWeb
            PsDscRunAsCredential = $SPFarmCredential
            DependsOn = "[SPWeb]$($Web.Name.Replace(' ' , ''))"
        }
    }
} 
