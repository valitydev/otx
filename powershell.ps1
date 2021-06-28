
new-module -name install_agent -scriptblock {
    function AgentDoStart() {
        $kServiceName = "osqueryd"
        $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"
        if ($osquerydService) {
          Start-Service $kServiceName
          Write-Host "'$kServiceName' system service is started." -foregroundcolor Cyan
          return 1
        } else {
          Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
          return 0
        }
    }
    
    function AgentDoStop() {
        $kServiceName = "osqueryd"
        $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"
    
        if ($osquerydService) {
          Stop-Service $kServiceName
          Start-Sleep -s 1
          $proc = Get-Process osqueryd -ErrorAction SilentlyContinue
          if ($proc) {
              Write-Host "osqueryd still running, killing processes"
              Stop-Process -Force -Name osqueryd
          }
          Write-Host "'$kServiceName' system service is stopped." -foregroundcolor Cyan
          return 1
        } else {
          Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
          return 0
        }
    }
    
    Function Install-Project() {
        param(
            [string]$apikey="",
            [string]$controlnodeid="",
            [string]$hostid="",
            [string]$assetid=""
        )
        Install-Project-Internal -apikey $apikey -controlnodeid $controlnodeid -hostid $hostid -assetid $assetid
        Write-Host "See install.log for details" -ForegroundColor Cyan
    }

    Function Install-Project-Internal() {
        param(
            [string]$apikey="",
            [string]$controlnodeid="",
            [string]$hostid="",
            [string]$assetid=""
        )

        If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" 
            Return
        }

        If ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Error "This script must be run using Powershell version 3 or higher.  You have version $PSVersionTable.PSVersion.Major installed" 
            Return
        }

        $kServiceName = "osqueryd"

        $BASE = "$($env:SYSTEMDRIVE)\Program Files\osquery"
        $OLDBASE = "$($env:SYSTEMDRIVE)\ProgramData\osquery"
        $secretfile = $(Join-Path $BASE "secret")
        $flagfile = $(Join-Path $BASE "osquery.flags")

        if ([string]::IsNullOrEmpty($hostid)) {
            $hostid = $assetid
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            $apikey = $controlnodeid
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            if ([System.IO.File]::Exists("$secretfile")) {
                $apikey = [IO.File]::ReadAllText("$secretfile").Trim()
            }
        }
        if ([string]::IsNullOrEmpty($apikey)) {
            # check old location in ProgramData
            $oldsecretfile = $(Join-Path $OLDBASE "secret")
            if ([System.IO.File]::Exists("$oldsecretfile")) {
                $apikey = [IO.File]::ReadAllText("$oldsecretfile").Trim()
            }
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            Write-Warning "You must supply either the -apikey or -controlnodeid parameters to identify your agent account"
            return
        }
        
        # use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        #===================================================
        #1. Download Sysmon
        #===================================================
        
        $source = "https://download.sysinternals.com/files/Sysmon.zip"
        Write-Host "Downloading Sysmon from $source" -ForegroundColor Cyan
        $file = "$($env:TEMP)\Sysmon.zip"
        Invoke-WebRequest $source -OutFile $file
        
        
        #===================================================
        #2. Clean & Prepare Sysmon installation target        
        #===================================================
        $targetondisk = "$($env:USERPROFILE)\Documents\Sysmon\"
        Write-Host "Preparing Sysmon target path $($targetondisk)" -ForegroundColor Cyan
        Remove-Item $targetondisk -Recurse -ErrorAction Ignore
        # Suppress output, but not errors:
        [void](New-Item -ItemType Directory -Force -Path $targetondisk)
        If (-Not (Test-Path -Path $targetondisk)) {
            Write-Error "Skipping Sysmon... Destination path $($targetondisk) does not exist."
        } Else {
            #===================================================
            #3. Unzip Sysmon
            #===================================================
            Unblock-File -Path $file
            Write-Host "Uncompressing the Zip file to $($targetondisk)" -ForegroundColor Cyan

            $FoundExtractionAssembly = 0
            try {
                # Load preferred extraction method's assembly (.NET 4.5 or later)
                # Write-Host "Using preferred extraction method..."
                Add-Type -As System.IO.Compression.FileSystem -ErrorAction Stop
                $FoundExtractionAssembly = 1
            }
            catch [System.Exception] {
                # Write-Host "Preferred extraction method not found. Attempting fall-back method..."
            }

            If ($FoundExtractionAssembly) {
                [IO.Compression.ZipFile]::ExtractToDirectory($file, $targetondisk)
            } Else {
                # Fall-back method, may fail in sessions lacking access to interactive shell
                $continue_flag = 1
                try {
                    $shell_app = New-Object -COMObject "Shell.Application"
                } catch {
                    Write-Error "Could not create Shell.Application object"
                    $continue_flag = 0
                }
                if ($continue_flag) {
                    $zip_file = $shell_app.namespace($file)
                    $destination = $shell_app.namespace($targetondisk)
                    if ($destination -ne $null) {
                            $destination.Copyhere($zip_file.items(), 0x10)
                    }
                }
            }
        }
        
        #===================================================
        #3. Download Sysmon Config File
        #===================================================
        
        $source = "https://www.alienvault.com/documentation/resources/downloads/sysmon_config_schema4_0.xml"
        Write-Host "Downloading Sysmon config file from $source" -ForegroundColor Cyan
        $destination = [System.IO.Path]::GetTempFileName()
        Invoke-WebRequest $source -OutFile $destination
        
        #===================================================
        #3. Install Sysmon
        #===================================================
        
        Write-Host "Installing Sysmon from $source" -ForegroundColor Cyan
        If ( (get-childitem $destination).length -eq 0 ) {
           $command = "& '$targetondisk\sysmon' -accepteula -h md5 -n -l -i"
           Write-Host "Not using an additional Sysmon configuration file" -ForegroundColor Cyan
        } 
        Else {
           $command = "& '$targetondisk\sysmon' -accepteula -h md5 -n -l -i '$destination'"
           Write-Host "Sysmon configuration file to use $destination" -ForegroundColor Cyan
        }
        Write-Host "Installing Sysmon with command $command" -ForegroundColor Cyan
        
        iex $command

        #===================================================
        #4. Download and install osquery
        #===================================================
        try {
            AgentDoStop
        } catch { 
            Write-Error "Did not stop osqueryd service.  Hopefully, this is fine." 
        }

        Write-Host "Downloading installer"
        $webclient = New-Object System.Net.WebClient
        $webclient.DownloadFile("https://s3-us-west-2.amazonaws.com/prod-otxb-portal-osquery/repo/windows/alienvault-agent-20.01.0203.0301.msi", "$env:TEMP\alienvault-agent.msi")

        Write-Host "Installing"
        try {
            Start-Process C:\Windows\System32\msiexec.exe -ArgumentList "/i $env:TEMP\alienvault-agent.msi ALLUSERS=1 /qn /l*v .\install.log" -wait
            echo "INSTALLATION SUCCESSFULLY COMPLETED" >> .\install.log
        } catch {
            echo "INSTALLATION ERROR (ERRORLEVEL=%ERRORLEVEL%)" >> .\install.log
            Write-Error "INSTALLATION ERROR (ERRORLEVEL=%ERRORLEVEL%)" 
            Return
        }
        
        # If the install directory doesn't exist, bail 
        if (![System.IO.Directory]::Exists("$BASE")) {
            echo "Installation directory does not exist: $BASE" >> .\install.log
            Write-Error "Installation directory does not exist: $BASE" 
            Return
        }

        # $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='osqueryd'"
        # if ($osquerydService) {
        #     Write-Host "Service exists, uninstalling"
        #     try {
        #       Stop-Service $kServiceName
        #       AgentDoStop
        # 
        #       Write-Host "Found '$kServiceName', stopping the system service..."
        #       Start-Sleep -s 5
        #       Write-Host "System service should be stopped."
        #       $osquerydService.Delete()
        #       Write-Host "System service '$kServiceName' uninstalled." -foregroundcolor Cyan
        #     } catch { 
        #         Write-Error "Did not uninstall osqueryd service.  Hopefully, it's not already installed." 
        #     }
        # }

        Write-Host "Writing secret"
        [IO.File]::WriteAllLines("$secretfile", $apikey)

        # if hostid is not specified, try to extract from flag file
        if ([string]::IsNullOrEmpty($hostid)) {
            if ([System.IO.File]::Exists($flagfile)) {
                $match = (Select-String -Path $flagfile -Pattern "specified_identifier=(.*)")
                if ($match.Matches.Groups.success) {
                    $hostid = $match.Matches.Groups[1].Value.Trim()
                    Write-Host "Detected and re-using previously selected host id from ${flagfile}: $hostid"
                } else {
                    Write-Host "Existing host id not found in ${flagfile}"
                }
            } 
        }

        # if still not found, check old ProgramData location
        if ([string]::IsNullOrEmpty($hostid)) {
            $oldflagfile = $(Join-Path $OLDBASE "osquery.flags")
            if ([System.IO.File]::Exists($oldflagfile)) {
                $match = (Select-String -Path $oldflagfile -Pattern "specified_identifier=(.*)")
                if ($match.Matches.Groups.success) {
                    $hostid = $match.Matches.Groups[1].Value.Trim()
                    Write-Host "Detected and re-using previously selected host id from ${oldflagfile}: $hostid"
                } else {
                    Write-Host "Existing host id not found in ${oldflagfile}"
                }
            } 
        }

        echo "Creating flag file"
        copy $BASE\osquery.flags.example $flagfile

        Write-Host "Setting host identifier"
           
        # if still no hostid, use generated default
        if ([string]::IsNullOrEmpty($hostid)) {
            $hostid="00000000-5987-4310-95b2-512e23c5df62"
        }

        $output = "--tls_hostname=api.agent.otxb.io/osquery-api-otx", "--host_identifier=specified", "--specified_identifier=$hostid"
        [IO.File]::AppendAllLines([string]$flagfile, [string[]]$output)

        # add customer certs if present
        $custpem = "$($env:SYSTEMROOT)\System32\drivers\etc\osquery_customer_certs.pem"
        if ([System.IO.File]::Exists($custpem)) {
          Write-Host "Adding customer certs"
          type "$custpem" >> "$BASE\certs\certs.pem"
        }

        # start service    
        if (-NOT (AgentDoStop)) {
            return
        }
        AgentDoStart

        Write-Host "Deleting installer"
        del $env:TEMP\alienvault-agent.msi

        if (($BASE -ne $OLDBASE) -And [System.IO.Directory]::Exists($OLDBASE)) {
           Write-Host "renaming old ProgramData/osquery directory"
           move "$OLDBASE" "$($OLDBASE).renamed"
        }

    }  
    set-alias install_agent -value Install-Project
    export-modulemember -alias 'install_agent' -function 'Install-Project'
}