Configuration SharePointServerProjectWebApp
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$WebApplication,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$SiteCollection
    )

    Import-DscResource -ModuleName SharePointDSC -ModuleVersion 4.0.0

    SPProjectServerPermissionMode PWAPermMode {
        Url                  = $SiteCollection.Url
        PermissionMode       = $SiteCollection.PWASettings.PermissionMode
    }

    SPProjectServerAdditionalSettings PWAAdditionalSettings {
        Url                  = $SiteCollection.Url
        EnforceServerCurrency = $SiteCollection.PWASettings.EnforceServerCurrency
        ProjectProfessionalMinBuildNumber = $SiteCollection.PWASettings.ProjectProfessionalMinBuildNumber
        ServerCurrency       = $SiteCollection.PWASettings.ServerCurrency
    }

    SPProjectServerTimeSheetSettings PWATimeSheetSettings {
        Url                  = $SiteCollection.Url
        AllowFutureTimeReporting = $SiteCollection.PWASettings.TimeSheet.AllowFutureTimeReporting
        AllowNewPersonalTasks = $SiteCollection.PWASettings.TimeSheet.AllowNewPersonalTasks
        AllowTopLevelTimeReporting = $SiteCollection.PWASettings.TimeSheet.AllowTopLevelTimeReporting
        EnableOvertimeAndNonBillableTracking = $SiteCollection.PWASettings.TimeSheet.EnableOvertimeAndNonBillableTracking
        EnableTimesheetAuditing = $SiteCollection.PWASettings.TimeSheet.EnableTimesheetAuditing
        DefaultReportingUnit = $SiteCollection.PWASettings.TimeSheet.DefaultReportingUnit
        DefaultTimesheetCreationMode = $SiteCollection.PWASettings.TimeSheet.DefaultTimesheetCreationMode
        DefaultTrackingMode = $SiteCollection.PWASettings.TimeSheet.DefaultTrackingMode
        DefaultTrackingUnit = $SiteCollection.PWASettings.TimeSheet.DefaultTrackingUnit
        FixedApprovalRouting = $SiteCollection.PWASettings.TimeSheet.FixedApprovalRouting
        ForceTrackingModeForAllProjects = $SiteCollection.PWASettings.TimeSheet.ForceTrackingModeForAllProjects
        HoursInStandardDay = $SiteCollection.PWASettings.TimeSheet.HoursInStandardDay
        HoursInStandardWeek = $SiteCollection.PWASettings.TimeSheet.HoursInStandardWeek
        MaxHoursPerDay = $SiteCollection.PWASettings.TimeSheet.MaxHoursPerDay
        MaxHoursPerTimesheet = $SiteCollection.PWASettings.TimeSheet.MaxHoursPerTimesheet
        MinHoursPerTimesheet = $SiteCollection.PWASettings.TimeSheet.MinHoursPerTimesheet
        RequireLineApprovalBeforeTimesheetApproval = $SiteCollection.PWASettings.TimeSheet.RequireLineApprovalBeforeTimesheetApproval
        RequireTaskStatusManagerApproval = $SiteCollection.PWASettings.TimeSheet.RequireTaskStatusManagerApproval
        SingleEntryMode = $SiteCollection.PWASettings.TimeSheet.SingleEntryMode
    }

    SPProjectServerUserSyncSettings PWAUserSyncSettings {
        Url                  = $SiteCollection.Url
        EnableProjectSiteSync = $SiteCollection.PWASettings.EnableProjectSiteSync
        EnableProjectSiteSyncForSPTaskLists = $SiteCollection.PWASettings.EnableProjectSiteSyncForSPTaskLists
        EnableProjectWebAppSync = $SiteCollection.PWASettings.EnableProjectWebAppSync
    }

    SPProjectServerWssSettings PWAWssSettings {
        Url                  = $SiteCollection.Url
        CreateProjectSiteMode = $SiteCollection.PWASettings.CreateProjectSiteMode
    }

}