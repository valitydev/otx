param(
   [string] $command
)

$osqdir = "c:/program files/osquery"
$flagfile = "$osqdir/osquery.flags"
$secretfile = "$osqdir/secret"
$kServiceName = "osqueryd"

function DoHelp {
    $programName = (Get-Item $PSCommandPath ).Name

    Write-Host "Usage: $programName (start|stop|restart|uninstall|update|force-update|osqueryi|config|help)" -foregroundcolor Yellow
    Write-Host ""
    Write-Host "  Only one of the following options can be used."
    Write-Host "    restart                  Restart the osqueryd service"
    Write-Host "    start                    Start the osqueryd service"
    Write-Host "    stop                     Stop the osqueryd service"
    Write-Host "    uninstall                Uninstall the alienvault agent"
    Write-Host "    update                   Update alienvault agent to most recent version"
    Write-Host "    force-update             Force update the alienvault agent to most recent version"
    Write-Host "    osqueryi                 Run osqueryi, the osquery interactive shell"
    Write-Host "    config                   Download and display osquery config"
    Write-Host "    version                  Show installed version"
    Write-Host "    report                   Print diagnostic report"
    Write-Host "    help                     Shows this help screen"

    Exit 1
}

function DoRestart() {
    DoStop
    DoStart
}

function DoStart() {
    $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"

    if ($osquerydService) {
      Start-Service $kServiceName
      Write-Host "'$kServiceName' system service is started." -foregroundcolor Cyan
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1
    }
}

function DoStop() {
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
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      # Exit 1
    }
}

function DoUninstall($notify=$true, $unschedule=$true) {
    if ($notify) {
        $hostn = LoadTlsHostname
        $node_key=(LoadApiKey) + ":" + (LoadHostID)
    }

    if ($unschedule) {
        DoUninstallScheduledUpdate
    }

    # stop service
    DoStop

    # remove service
    $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"
    if ($osquerydService) {
        Write-Host "Found '$kServiceName', stopping the system service..."
        Start-Sleep -s 5
        Write-Host "System service should be stopped."
        $osquerydService.Delete()
        Write-Host "System service '$kServiceName' uninstalled." -foregroundcolor Cyan
    }

    # uninstall sysmon
    #$targetondisk = "$($env:USERPROFILE)\Documents\Sysmon\"
    #invoke-expression -Command "& '$targetondisk/sysmon.exe' -u"
    #Remove-Item $targetondisk -force -recurse

    # uninstall osquery
    $app = GetInstalledApp
    $app.Uninstall()

    if ($notify) {
        $url = "https://$hostn/uninstall?node_key=$node_key"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        (new-object Net.WebClient).DownloadString($url)
    }
}

function DoUpdate($checkfirst=$true) {
    if($checkfirst) {
        if (-Not (NeedsUpdate)) {
            Write-Host "Already running latest version"
            return
        }
    }

    $hostn = LoadTlsHostname
    DoUninstall $false $false
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $url = "https://$hostn/bootstrap?flavor=powershell"
    Write-Host "Reinstalling using bootstrap url: $url" -foreground Cyan
    (new-object Net.WebClient).DownloadString($url) | iex
    install_agent
}

function DoForceUpdate() {
    # change this once we make DoUpdate more gentle?
    DoUpdate($false)
}

function DoOsqueryi() {
    if (-Not (Test-Path "$osqdir/log2")) {
        mkdir "$osqdir/log2"
    }
    invoke-expression -Command "& '$osqdir/osqueryi.exe' --verbose --tls_dump --flagfile='$flagfile' --logger_path='$osqdir/log2' --tls_server_certs='$osqdir/certs/certs.pem'"
}

function DoConfig() {
    $node_key=(LoadApiKey) + ":" + (LoadHostID)
    $hostn=LoadTlsHostname
    $url = "https://$hostn/configure?node_key=$node_key"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    (new-object Net.WebClient).DownloadString($url)
}

function DoVersion() {
    EnsureEmptyTxt | Out-Null
    $query = "select substr(version, instr(version, '_')+1) from osquery_info"
    invoke-expression -Command "& '$osqdir/osqueryi.exe' --flagfile='$osqdir/empty.txt' --disable-extensions=1 --logger_min_status=1 --csv ""$query""" | Select-Object -Last 1
}

function DoReport() {
    $winver = [System.Environment]::OSVersion.Version
    $latest, $current, $needs_update = VersionInfo

    @"
Enroll Secret:     $(LoadApiKey)
Host Identifier:   $(LoadHostId)
API Host:          https://$(LoadTLSHostname)
Installed Version: $current
Latest Version:    $latest
Needs Update:      $needs_update
Platform:          $winver
"@
}

function DoInstallScheduledUpdate() {
    param(
        [string] $at="8:15pm"
    )

    Write-Host "Installing scheduled task to update to latest Alienvault agent version.  Will run at $at"
    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy ByPass -f "$($env:programfiles)\osquery\alienvault-agent.ps1" update'
    $trigger =  New-ScheduledTaskTrigger -Daily -At $at
    Register-ScheduledTask -Action $action -Trigger $trigger -AsJob -User SYSTEM -RunLevel Highest -TaskName "AlienvaultAgentUpdateCheck" -Description "Update agent if new version available."
}

function DoUninstallScheduledUpdate() {
    try {
        $result = Get-ScheduledTask -TaskName AlienvaultAgentUpdateCheck -ErrorAction Stop
    } catch {
        $result = $null
    }
    if (-Not $result) {
        Write-Host "Scheduled task does not seem to be installed, bailing"
        return
    }

    Write-Host "Uninstalling scheduled update task"
    Unregister-ScheduledTask -TaskName "AlienvaultAgentUpdateCheck" -Confirm:$false
}

function LoadApiKey() {
    return [IO.File]::ReadAllText("$secretfile").Trim()
}

function GetInstalledApp() {
    return Get-WmiObject -Class Win32_Product -Filter "Name = 'AlienVault Agent'"
}

function LoadHostID() {
    $hostid = ""
    $match = (Select-String -Path "$flagfile" -Pattern "specified_identifier=(.*)")
    if ($match.Matches.Groups.success) {
        $hostid = $match.Matches.Groups[1].Value.Trim()
    }

    return $hostid
}

function LoadTlsHostname() {
    $hostn = ""
    $match = (Select-String -Path "$flagfile" -Pattern "tls_hostname=(.*)")
    if ($match.Matches.Groups.success) {
        $hostn = $match.Matches.Groups[1].Value.Trim()
    }

    return $hostn
}

function LatestVersion() {
    $hostn = LoadTlsHostname
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $url = "https://$hostn/latest_version?platform=windows"
    (new-object Net.WebClient).DownloadString($url).Trim("""")
}

function EnsureEmptyTxt() {
  if ( -Not (Test-Path "$osqdir\empty.txt")) {
    New-Item -Path "$osqdir\empty.txt" -ItemType File
  }
}

function VersionInfo() {
    $latest = LatestVersion
    $current = DoVersion

    $needs_update = $true
    if ($latest -le $current) {
      $needs_update = $false
    }
    Return $latest, $current, $needs_update
}

function NeedsUpdate() {
    $latest, $current, $needs_update = VersionInfo
    return $needs_update
}

function Main {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        Exit -1
    }

    if ($command -eq "help") {
        DoHelp
    } elseif ($command -eq "restart") {
        DoRestart
    } elseif ($command -eq "start") {
        DoStart
    } elseif ($command -eq "stop") {
        DoStop
    } elseif ($command -eq "update") {
        DoUpdate
    } elseif ($command -eq "force-update") {
        DoForceUpdate
    } elseif ($command -eq "uninstall") {
        DoUninstall
    } elseif ($command -eq "osqueryi") {
        DoOsqueryi
    } elseif ($command -eq "config") {
        DoConfig
    } elseif ($command -eq "version") {
        DoVersion
    } elseif ($command -eq "report") {
        DoReport
    } elseif ($command -eq "install_scheduled_update") {
        DoInstallScheduledUpdate @args
    } elseif ($command -eq "uninstall_scheduled_update") {
        DoUninstallScheduledUpdate
    } else {
        DoHelp
    }
}

Main @args
