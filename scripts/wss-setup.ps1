$ScriptPath = $MyInvocation.MyCommand.Path
$RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegistryEntry = "WSSSetup"
$Logfile = "C:\Windows\Temp\wss-setup.log"

function LogWrite {
   Param ([string]$logstring)
   $now = Get-Date -format s
   Add-Content $Logfile -value "$now $logstring"
   Write-Host $logstring
}

switch ( (Get-WssConfigurationStatus).Status) {
    'NotStarted' {
        $UserName= "Admin"
        $PlainTextPassword = "P@ssword!"
        $password = $PlainTextPassword | ConvertTo-SecureString -Force -AsPlainText
        $Credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $UserName, $Password
        $CompanyName = "Contoso"
        $ServerName = "MyServer"
        $NetbiosName = "contoso"
        $DNSName = "contoso.local"
        $Settings="None"

        LogWrite 'Starting WSS Configuration'

        Start-WssConfigurationService `
            -CompanyName $CompanyName `
            -DNSName $DNSName `
            -NetBiosName $NetbiosName `
            -ComputerName $ServerName `
            –NewAdminCredential $Credential `
            -Setting $Settings `
            -Force

        LogWrite 'Adding registry key'

        Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $($ScriptPath) -MaxUpdatesPerCycle $($MaxUpdatesPerCycle)"

    }

    'Running' {
        while ( (Get-WssConfigurationStatus).Status -ne "Finished" ) {
            LogWrite 'Waiting for WSS Configuration to finish'
            Sleep -Seconds 120
        }

        if ( (Get-WssConfigurationStatus).Status -eq "Finished" ) {
            Write-Log 'WSS Configuration finished'
            Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
            Invoke-Expression 'a:\openssh.ps1 -AutoStart'
        }

    }

    'Finished' {
        # Enable SSH
        LogWrite 'WSS Configuration finished'
        Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
        Invoke-Expression 'a:\openssh.ps1 -AutoStart'
    }

}

