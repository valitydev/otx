# OTX
## Установка 
### Этапы
- Downloading Sysmon from https://download.sysinternals.com/files/Sysmon.zip
- Preparing Sysmon target path C:\Users\User\Documents\Sysmon\
- Uncompressing the Zip file to C:\Users\User\Documents\Sysmon\
- Downloading Sysmon config file from https://www.alienvault.com/documentation/resources/downloads/sysmon_config_schema4_0.xml
- Installing Sysmon from https://www.alienvault.com/documentation/resources/downloads/sysmon_config_schema4_0.xml
- Sysmon configuration file to use C:\Users\User\AppData\Local\Temp\tmpCDE9.tmp
- Installing Sysmon with command & 'C:\Users\User\Documents\Sysmon\\sysmon' -accepteula -h md5 -n -l -i 'C:\Users\User\AppData\Local\Temp\tmpCDE9.tmp'
powershell.ps1 

## Конфиги 
### Sysmon 
### Osquery 
