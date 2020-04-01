Configuration SharePointServerEnforceTLS12
{
    param(

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Present", "Absent")]
        [string]$Ensure

    )

    #region import DSC modules

    Import-DscResource -ModuleName PSDesiredStateConfiguration -ModuleVersion 1.1

    #endregion


    #region TLS Registry Settings

    If($Ensure -eq 'Present'){

        #.Net Framework 3.5 Enable Strong Crypto
        Registry Enable_Net_3_5_Strong_x86{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Enable_Net_3_5_Strong_x64{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        #.Net Framework 3.5 Default TLS 1.2

        Registry Net_3_5_TLS_1_2_x86{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Net_3_5_TLS_1_2_x64{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
            ValueName = 'SystemDefaultTlsVersions'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        #.Net Framework 4.6 Enable Strong Crypto
        Registry Enable_Net_4_6_Strong_x86{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Enable_Net_4_6_Strong_x64{
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\Software\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        # Disable SSL 2.0
        Registry Disable_SSL_2_0_Server_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_SSL_2_0_Server_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Disable_SSL_2_0_Client_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

         Registry Disable_SSL_2_0_Client_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

       # Disable SSL 3.0
        Registry Disable_SSL_3_0_Server_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_SSL_3_0_Server_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Disable_SSL_3_0_Client_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_SSL_3_0_Client_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        # Disable TLS 1.0
        Registry Disable_TLS_1_0_Server_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_0_Server_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_0_Client_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_0_Client_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        # Disable TLS 1.1
        Registry Disable_TLS_1_1_Server_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_1_Server_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_1_Client_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'Enabled'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Disable_TLS_1_1_Client_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        # Enable TLS 1.2
        Registry Enable_TLS_1_2_Server_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'Enabled'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Enable_TLS_1_2_Server_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'DisabledByDefault'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

        Registry Enable_TLS_1_2_Client_Enabled {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'Enabled'
            ValueData = '00000001'
            ValueType = 'Dword'
	    }

        Registry Enable_TLS_1_2_Client_DisabledByDefault {
            Ensure = 'Present'
            Force = $true
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'DisabledByDefault'
            ValueData = '00000000'
            ValueType = 'Dword'
	    }

	}
    #endregion

}