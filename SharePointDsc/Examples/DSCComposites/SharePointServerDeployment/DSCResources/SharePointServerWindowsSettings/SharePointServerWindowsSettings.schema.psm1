Configuration SharePointServerWindowsSettings
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$Node
    )

    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 8.0.0
    Import-DscResource -ModuleName xCredSSP -ModuleVersion 1.3.0.0

    #region Set Credential Security Support Provider

    xCredSSP CredSSPServer { 
        Ensure = 'Present'
        Role = 'Server' 
    } 

    xCredSSP CredSSPClient {
        Ensure = 'Present'
        Role = 'Client'
        DelegateComputers = ('*.' + $ConfigurationData.NonNodeData.SharePoint.WindowsSettings.DomainName)
    }

    #endregion

    #region Add accounts to the local admin group and performance monitor group

    Group AddADUserToLocalAdminGroup {
        GroupName='Administrators'   
        Ensure= 'Present'            
        MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.WindowsSettings.AdministratorMembersToInclude
    }

    Group AddADUserToLocalPerfMonitorGroup {
        GroupName='Performance Monitor Users'   
        Ensure= 'Present'            
        MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.WindowsSettings.PerformanceMonitorMembersToInclude
    }

    #endregion
 
    #region Disable IE Enhanced Security

    IEEnhancedSecurityConfiguration DisableIEEnhancedSecurityConfiguration {
        Enabled = $false
        Role = 'Administrators'
        SuppressRestart = $false
    }
            
    #endregion 

    #region Windows Firewall Settings

    # Windows Firewall Port 80

    Firewall Port80 {
        Direction = 'Inbound'
        Name = 'SharePoint Web Port 80'
        DisplayName = 'SharePoint Web Port 80'
        Description = 'Inbound rule to allow http traffic to the SharePoint server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'    
        Protocol = 'TCP'
        LocalPort = '80'
        InterfaceType = 'Any'
        Profile = 'domain'
        Ensure = 'Present'
    }

    # Windows Firewall Port 443

    Firewall Port443 {
        Direction = 'Inbound'
        Name = 'SharePoint Web Port 443'
        DisplayName = 'SharePoint Web Port 443'
        Description = 'Inbound rule to allow https traffic to the SharePoint server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'    
        Protocol = 'TCP'
        LocalPort = '443'
        InterfaceType = 'Any'
        Profile = 'domain'
        Ensure = 'Present'
    }

    # Windows Firewall Ports 32843-32845

    Firewall SharePointWebServicePorts {
        Direction = 'Inbound'
        Name = 'SharePoint Web Service Ports (TCP 32843-32845)'
        DisplayName = 'SharePoint Web Service Ports (TCP 32843-32845)'
        Description = 'Allows SharePoint Intrafarm Comm'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '32843-32845'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Port 808

    Firewall SharePointCommunicationFoundation808 {
        Direction = 'Inbound'
        Name = 'SharePoint Communication Foundation Port (TCP 808)'
        DisplayName = 'SharePoint Communication Foundation Port (TCP 808)'
        Description = 'Allows SharePoint Search Connections'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '808'
        Profile = 'domain'
        Ensure = 'Present'
    }

    # Windows Firewall Ports 16500-16519

    Firewall SharePointSearchPorts16500-16519 {
        Direction = 'Inbound'
        Name = 'SharePoint Search Ports (TCP 16500-16519)'
        DisplayName = 'SharePoint Search Ports (TCP 16500-16519)'
        Description = 'Allows SharePoint Search Connections'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '16500-16519'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Ports 17000-17009

    Firewall SharePointSearchPorts17000-17009 {
        Direction = 'Inbound'
        Name = 'SharePoint Search Ports (TCP 17000-17009)'
        DisplayName = 'SharePoint Search Ports (TCP 17000-17009)'
        Description = 'Allows SharePoint Search Connections'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '17000-17009'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Ports 22233-22236

    Firewall SharePointDistributedCachePorts {
        Direction = 'Inbound'
        Name = 'SharePoint Distributed Cache Ports (TCP 22233-22236)'
        DisplayName = 'SharePoint Distributed Cache Ports (TCP 22233-22236)'
        Description = 'Allows SharePoint Distributed Cache'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '22233-22236'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Outbound Port 1433 (SQL)

    Firewall SharePointOBTCPSQLPort {
        Direction = 'Outbound'
        Name = 'SharePoint Outbound TCP SQL Port (TCP 1433)'
        DisplayName = 'SharePoint Outbound TCP SQL Port (TCP 1433)'
        Description = 'Allows SharePoint Communication With SQL Server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '1433'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Inbound Port 1433 (SQL)

    Firewall SharePointIBTCPSQLPort {
        Direction = 'Inbound'
        Name = 'SharePoint Inbound TCP SQL Port (TCP 1433)'
        DisplayName = 'SharePoint Inbound TCP SQL Port (TCP 1433)'
        Description = 'Allows SharePoint Communication With SQL Server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '1433'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Outbound Port 1434 (SQL)

    Firewall SharePointOBUDPSQLPort {
        Direction = 'Outbound'
        Name = 'SharePoint Outbound UDP SQL Port (TCP 1434)'
        DisplayName = 'SharePoint Outbound UDP SQL Port (TCP 1434)'
        Description = 'Allows SharePoint Communication With SQL Server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'UDP'
        LocalPort = '1434'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Inbound Port 1434 (SQL)

    Firewall SharePointIBUDPSQLPort {
        Direction = 'Inbound'
        Name = 'SharePoint Inbound UDP SQL Port (TCP 1434)'
        DisplayName = 'SharePoint Inbound UDP SQL Port (TCP 1434)'
        Description = 'Allows SharePoint Communication With SQL Server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'UDP'
        LocalPort = '1434'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Port 25 (SMTP)

    Firewall SharePointSMTPPort {
        Direction = 'Outbound'
        Name = 'SharePoint SMTP Port (TCP 25)'
        DisplayName = 'SharePoint SMTP Port (TCP 25)'
        Description = 'Allows SharePoint E-Mail'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '25'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    # Windows Firewall Port 809 (OOS)

    Firewall SharePointOOSPort {
        Direction = 'Outbound'
        Name = 'SharePoint OOS Port (TCP 809)'
        DisplayName = 'SharePoint OOS Port (TCP 809)'
        Description = 'Allows Communication With Office Online Server'
        Group = 'SharePoint'
        Enabled = 'True'
        Action = 'Allow'
        Protocol = 'TCP'
        LocalPort = '809'
        Profile = 'domain' 
        Ensure = 'Present'
    }

    #endregion
} 
