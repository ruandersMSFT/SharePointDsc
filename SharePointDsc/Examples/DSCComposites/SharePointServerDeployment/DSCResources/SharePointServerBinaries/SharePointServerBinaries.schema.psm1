Configuration SharePointServerBinaries
{
param
(
[Parameter(Mandatory)]
[ValidateSet("Present", "Absent")]
[ValidateNotNullOrEmpty()]
[string]$Ensure,
 
#[Parameter(Mandatory)]
#[ValidateNotNullOrEmpty()]
#[string]$SourcePath,

[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string]$SharePointBinarySourceArchive,

[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string]$SharePointBinaryPath,

[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string]$SharePointPreRequisitesSourcePath,

[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string]$SharePointPreRequisitesTargetPath
)
	Import-DscResource -ModuleName PSDesiredStateConfiguration

    if($Ensure -eq 'Present') {

        # Unpack the SharePoint zip file
        Archive UnpackSPInstallFiles {
            Ensure = 'Present'
            Path = $SharePointBinarySourceArchive
            Destination = $SharePointBinaryPath
            Force = $true
        } 

        # Copy SharePoint PreRequistes
        File CopySharePointPrerequistes {
            Ensure = 'Present'
            Type = 'Directory'
            SourcePath = $SharePointPreRequisitesSourcePath
            DestinationPath = $SharePointPreRequisitesTargetPath
            Recurse = $true
            MatchSource = $true
        }

    } 
    else {

        # Remove the installation files
        File RemoveSPInstallFiles {
            Ensure = 'Absent'
            Type = 'Directory'
            DestinationPath = $SharePointBinaryPath
            Force = $true
        }

		File RemoveSharePointPrerequistes {
            Ensure = 'Absent'
            Type = 'Directory'
            DestinationPath = $SharePointPreRequisitesTargetPath
            Force = $true
        }

    }

} 
