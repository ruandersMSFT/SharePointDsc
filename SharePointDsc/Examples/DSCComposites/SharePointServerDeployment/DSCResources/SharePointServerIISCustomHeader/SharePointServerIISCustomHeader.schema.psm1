Configuration SharePointServerIISCustomHeader
{
    param
    (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HeaderValue,
    
    [Parameter(Mandatory)]
    [ValidateSet("Present", "Absent")]
    [ValidateNotNullOrEmpty()]
    [string]$Ensure
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $PSPath =  'MACHINE/WEBROOT/APPHOST'
    $filter = "system.webServer/httpProtocol/customHeaders/add[@Name='$($HeaderName)']"

    Script SetIISHeaders {
        GetScript = {
            $returnVal = @{name=$null;value=$null}

            $currentSetting = Get-WebConfigurationProperty -PSPath $using:PSPath -Filter $using:filter -Name .

            if ($currentSetting -ne $null) {
                $returnVal = @{name=$currentSetting.name;value=$currentSetting.value}
            }

            return $returnVal
        }

        SetScript = {
            $valueString = $using:headervalue
            $currentSetting = Get-WebConfigurationProperty -PSPath $using:PSPath -Filter $using:filter -Name .

            if ($currentSetting -ne $null) {
                if ($currentSetting.value -ne $using:HeaderValue) {
                    Write-Verbose -Message 'Need to set value to $using:HeaderValue'
                    Set-WebConfigurationProperty -PSPath $using:PSPath -Filter $using:filter -Name .  -Value @{name=$using:HeaderName;value=$using:HeaderValue} -Verbose
                }                    
            } else {
                Write-Verbose -Message 'Need to add value $HeaderValue'
                Add-WebConfigurationProperty -PSPath $using:PSPath -Filter system.webServer/httpProtocol/customHeaders -Name . -Value @{name=$using:HeaderName;value=$using:HeaderValue} -Verbose
            }
        }

        TestScript = {
            $state = @{name=$null;value=$null}
            $returnTestVal = $false
            $valueString = $using:HeaderValue

            $currentSetting = Get-WebConfigurationProperty -PSPath $using:PSPath -Filter $using:filter -Name .

            if ($currentSetting -ne $null) {
                $state = @{name=$currentSetting.name;value=$currentSetting.value}
            }

            return $state.value -eq $HeaderValue
        }

	}
} 
