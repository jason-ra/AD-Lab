# Remember to run the baseline variables from Part 1
###

$nsg5Name = "jr-trustlab-nsg-b-ad"

az network nsg create -n $nsg5Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet4Name --vnet-name $vnetName --network-security-group $nsg5Name
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet4Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Allow_AD_TCP" --priority 110 --access "allow" --source-address-prefixes $subnet4Range $subnet5Range $subnet6Range --destination-address-prefixes $subnet4Range --destination-port-ranges 135 389 636 53 88 445 49152-65535 --protocol "TCP" --description "Allow AD traffic TCP"
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Allow_AD_UDP" --priority 111 --access "allow" --source-address-prefixes $subnet4Range $subnet5Range $subnet6Range --destination-address-prefixes $subnet4Range --destination-port-ranges 53 88 389 --protocol "UDP" --description "Allow AD traffic UDP"
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Allow_A_AD_TCP" --priority 120 --access "allow" --source-address-prefixes $vm2IPAddress $vm4IPAddress --destination-address-prefixes $subnet4Range --destination-port-ranges 135 389 636 53 88 445 49152-65535 --protocol "TCP" --description "Allow AD traffic TCP"
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Allow_A_AD_UDP" --priority 121 --access "allow" --source-address-prefixes $vm2IPAddress $vm4IPAddress --destination-address-prefixes $subnet4Range --destination-port-ranges 53 88 389 --protocol "UDP" --description "Allow AD traffic UDP"
az network nsg rule create --nsg-name $nsg5Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet4Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"

$logWsName = "jr-trustlab-logs"
$flow5LogName = "jr-trustlab-flow-b-ad"
az network watcher flow-log create -n $flow5LogName -g $rgName --enabled true --nsg $nsg5Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 --traffic-analytics --workspace $logWsName
###

$vmB1Image = "Win2019Datacenter"
$vmB1User = "lcladmin"
$vmB1Pass = $vmPass
$vmB1Size = "Standard_B2ms"
$vmB1DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vmB1Name -g $rgName --image $vmB1Image --admin-username $vmB1User --admin-password $vmB1Pass --computer-name $vmB1Name --size $vmB1Size --vnet-name $vnetName --subnet $subnet4Name --private-ip-address $vmB1IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vmB1Name)-OSdisk-$($vmB1DiskGuid)" --nsg '""' --public-ip-address '""'

# attach data disk
$diskB1Guid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)
$diskB1Name = "$($vmB1Name)-DataDisk-$($diskB1Guid)"
$diskB1Size = "64"
$diskB1Cache = "None"
az vm unmanaged-disk attach -g $rgName --vm-name $vmB1Name --new --name $diskB1Name --size-gb $diskB1Size --caching $diskB1Cache
###

$dcA2Domain="contoso.internal"
$dcBDomain="wingtip.root"
$dcBDomainNetbios="wingtip"
$dcBUPNSuffix="wingtip.net"
$dcBDomainDN = "DC=wingtip,DC=root"

$scriptBDC01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$disks = Get-Disk | Where partitionstyle -eq 'raw'
If (`$disks) {
  `$disks | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter ""G"" | Format-Volume -FileSystem NTFS -NewFileSystemLabel ""Data"" -Confirm:`$false -Force
}
`$domain = ""$dcBDomain""
`$domainnetbios = ""$dcBDomainNetbios""
`$IP = ""$vmB1IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vmB1IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vmB1IPAddress""
`$IPType = ""IPv4""
`$adapter = Get-NetAdapter | ? {`$_.Status -eq ""up""}
`$interface = `$adapter | Get-NetIPInterface -AddressFamily `$IPType
If (`$interface.Dhcp -eq ""Enabled"") {
  Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding
  If ((`$adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
    `$adapter | Remove-NetIPAddress -AddressFamily `$IPType -Confirm:`$false
  }
  If ((`$adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
    `$adapter | Remove-NetRoute -AddressFamily `$IPType -Confirm:`$false
  }
  `$adapter | New-NetIPAddress -AddressFamily `$IPType -IPAddress `$IP -PrefixLength `$MaskBits -DefaultGateway `$Gateway
  `$adapter | Set-DnsClientServerAddress -ServerAddresses `$DNS
}

Install-WindowsFeature AD-Domain-Services, rsat-adds -IncludeAllSubFeature
Install-ADDSForest -DomainName `$domain -SafeModeAdministratorPassword (convertto-securestring '$vmB1Pass' -asplaintext -force)  -DomainMode Win2012 -DomainNetbiosName `$domainnetbios -ForestMode Win2012 -DatabasePath """G:\NTDS""" -SysvolPath """G:\SYSVOL""" -LogPath """G:\Logs""" -Force"

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB1Name -g $rgName --scripts $scriptBDC01_1

az vm restart -g $rgName -n $vmB1Name
###

$scriptBDC01_2 = @"
try{
  Import-Module ActiveDirectory -ErrorAction Stop
}catch{
  throw ""Module ActiveDirectory not installed""
}

if ((Get-ADForest).UPNsuffixes -notcontains ""$dcBUPNSuffix""){
  Get-ADForest | Set-ADForest -UPNSuffixes @{add=""$dcBUPNSuffix""}
}

function New-ADOU {
  # http://www.alexandreviot.net/2015/04/27/active-directory-create-ou-using-powershell
  param([parameter(Mandatory=`$true)] [array]`$ouList)
  ForEach(`$OU in `$ouList){
    try{
      #Write-Host -Foregroundcolor Yellow `$OU.Name `$OU.Path
      New-ADOrganizationalUnit -Name ""`$(`$OU.Name)"" -Path ""`$(`$OU.Path)""
      #Write-Host -ForegroundColor Green ""OU `$OU.Name created""
    }catch{
       Write-Host `$error[0].Exception.Message
    }
  }
}
`$ouCSV = ""Name;Path
M_SERVERS;$dcBDomainDN
M_USERS;$dcBDomainDN
ServiceAccounts;OU=M_USERS,$dcBDomainDN
Staff;OU=M_USERS,$dcBDomainDN
M_WORKSTATIONS;$dcBDomainDN
M_GROUPS;$dcBDomainDN""
`$ouList = `$ouCSV | ConvertFrom-CSV -Delimiter "";""

New-ADOU `$ouList
New-ADGroup -Name ""Grp_AllStaff"" -SamAccountName Grp_AllStaff -GroupCategory Security -GroupScope Global -DisplayName ""All Staff"" -Path ""OU=M_GROUPS,$dcBDomainDN""

function Create-TestUsers {
  param(
    [parameter(Mandatory=`$true)] [array]`$UserList,
    [parameter(Mandatory=`$true)] [string]`$UserPass,
    [parameter(Mandatory=`$true)] [string]`$DomainSuffix,
    [parameter(Mandatory=`$true)] [string]`$OUPath
  )

  # https://365lab.net/2014/01/08/create-test-users-in-a-domain-with-powershell/
  `$departments = @(""IT"",""Finance"",""Logistics"",""Sourcing"",""Human Resources"")
  ForEach(`$user in `$userList){
    `$firstname = (Get-Culture).TextInfo.ToTitleCase(`$user.Firstname)
    `$lastname = (Get-Culture).TextInfo.ToTitleCase(`$user.Lastname)
    `$i = get-random -Minimum 0 -Maximum `$departments.count
    `$department = `$departments[`$i]
    `$username = `$firstname.Substring(0,2).tolower() + `$lastname.Substring(0,4).tolower()
    `$exit = 0
    `$count = 1
    do {
      try {
        `$userexists = Get-AdUser -Identity `$username
        `$username = `$firstname.Substring(0,2).tolower() + `$lastname.Substring(0,4).tolower() + `$count++
      } catch {
        `$exit = 1
      }
    } while (`$exit -eq 0)
    `$displayname = `$firstname + "" "" + `$lastname
    `$upn = `$username + ""@"" + `$DomainSuffix
    `$email = `$firstname + ""."" + `$lastname + ""@"" + `$DomainSuffix
    Write-Host ""Creating user `$username in `$OUPath""
    New-ADUser -Name `$displayName -DisplayName `$displayName -SamAccountName `$username -UserPrincipalName `$upn -EmailAddress `$email -GivenName `$firstname -Surname `$lastname -description ""Test User"" -Path `$OUPath -Enabled `$true -ChangePasswordAtLogon `$false -Department `$Department -AccountPassword (ConvertTo-SecureString `$userPass -AsPlainText -force)
  }
}

`$userOU = ""OU=Staff,OU=M_USERS,$dcBDomainDN""
`$userPass = '$userPass'
`$usersCSV = ""Firstname;Lastname
Aaron;Alfort
Abraham;Allendorf
Acea;Alsop
Adam;Amaker
Aidan;Angus
Ainslee;Annan
Alan;Annesley
Aleen;Appleby
Alexa;Arbuthnot
Alexander;Armitage
Alixandria;Artois
Aliyah;Arundel
Alka;Ashburton
Alp;Astor
Alyson;Athill""
`$userList = `$usersCSV | ConvertFrom-CSV -Delimiter "";""

`$users = Get-ADUser -Filter * -SearchBase `$userOU | select -expand samAccountName
If ((`$users) -eq `$null) {
  Create-TestUsers `$userList `$userPass ""$dcBUPNSuffix"" `$userOU
}
`$users = Get-ADUser -Filter * -SearchBase `$userOU | select -expand samAccountName
`$group = ""Grp_AllStaff""
Add-ADGroupMember -Identity `$group -Members `$users

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB1Name -g $rgName --scripts $scriptBDC01_2
###

$scriptBDC01_3 = @"
Add-DnsServerConditionalForwarderZone -Name ""$dcA2Domain"" -ReplicationScope ""Forest"" -MasterServers $vm2IPaddress

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB1Name -g $rgName --scripts $scriptBDC01_3
###

$scriptBDC01_4 = @"
`$displayName = ""svc_azuresync""
`$username = ""svc_azuresync""
`$upn = ""svc_azuresync@$dcB1Domain""
`$OUPath = ""OU=ServiceAccounts,OU=M_USERS,$dcBDomainDN""
`$userPass = '$vmPass'

New-ADUser -Name `$displayName -DisplayName `$displayName -SamAccountName `$username -UserPrincipalName `$upn -description ""AAD Connect"" -Path `$OUPath -Enabled `$true -ChangePasswordAtLogon `$false -Department `$Department -AccountPassword (ConvertTo-SecureString `$userPass -AsPlainText -force)

`$displayName = ""svc_a-azuresync""
`$username = ""svc_a-azuresync""
`$upn = ""svc_a-azuresync@$dcB1Domain""
`$OUPath = ""OU=ServiceAccounts,OU=M_USERS,$dcBDomainDN""
`$userPass = '$vmPass'

New-ADUser -Name `$displayName -DisplayName `$displayName -SamAccountName `$username -UserPrincipalName `$upn -description ""AAD Connect"" -Path `$OUPath -Enabled `$true -ChangePasswordAtLogon `$false -Department `$Department -AccountPassword (ConvertTo-SecureString `$userPass -AsPlainText -force)

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB1Name -g $rgName --scripts $scriptBDC01_4
###

$nsg6Name = "jr-trustlab-nsg-b-app"

az network nsg create -n $nsg6Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet5Name --vnet-name $vnetName --network-security-group $nsg6Name
az network nsg rule create --nsg-name $nsg6Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet5Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg6Name -g $rgName -n "Allow_HTTP" --priority 110 --access "allow" --source-address-prefixes $subnet4Range $subnet5Range --destination-address-prefixes $subnet5Range --destination-port-ranges 80 443 --protocol "TCP" --description "Allow HTTP traffic"
az network nsg rule create --nsg-name $nsg6Name -g $rgName -n "Allow_A_HTTP" --priority 120 --access "allow" --source-address-prefixes $subnet3Range --destination-address-prefixes $subnet5Range --destination-port-ranges 80 443 --protocol "TCP" --description "Allow HTTP traffic"
az network nsg rule create --nsg-name $nsg6Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet5Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"

$logWsName = "jr-trustlab-logs"
$flow6LogName = "jr-trustlab-flow-b-app"
az network watcher flow-log create -n $flow6LogName -g $rgName --enabled true --nsg $nsg6Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 --traffic-analytics --workspace $logWsName
###

$vmB2Image = "Win2019Datacenter"
$vmB2User = "lcladmin"
$vmB2Pass = $vmPass
$vmB2Size = "Standard_B2ms"
$vmB2DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vmB2Name -g $rgName --image $vmB2Image --admin-username $vmB2User --admin-password $vmB2Pass --computer-name $vmB2Name --size $vmB2Size --vnet-name $vnetName --subnet $subnet5Name --private-ip-address $vmB2IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vmB2Name)-OSdisk-$($vmB2DiskGuid)" --nsg '""' --public-ip-address '""'
###

$scriptBAPP01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$IP = ""$vmB2IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vmB2IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vmB1IPAddress""
`$IPType = ""IPv4""
`$adapter = Get-NetAdapter | ? {`$_.Status -eq ""up""}
`$interface = `$adapter | Get-NetIPInterface -AddressFamily `$IPType
If (`$interface.Dhcp -eq ""Enabled"") {
  Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding
  If ((`$adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
    `$adapter | Remove-NetIPAddress -AddressFamily `$IPType -Confirm:`$false
  }
  If ((`$adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
    `$adapter | Remove-NetRoute -AddressFamily `$IPType -Confirm:`$false
  }
  `$adapter | New-NetIPAddress -AddressFamily `$IPType -IPAddress `$IP -PrefixLength `$MaskBits -DefaultGateway `$Gateway
  `$adapter | Set-DnsClientServerAddress -ServerAddresses `$DNS
}
Start-Sleep -Seconds 15 # Wait for DNS changes
Add-Computer -DomainName ""$dcBDomain"" -Credential (New-Object System.Management.Automation.PSCredential(""$vmB2Domain\$vmB1User"",(ConvertTo-SecureString '$vmB1Pass' -AsPlainText -Force))) -OUPath ""OU=M_SERVERS,$dcBDomainDN"" -Restart

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB2Name -g $rgName --scripts $scriptBAPP01_1
###

$scriptBAPP01_2 = @"
`$installPath = ""c:\install""
If ((Test-Path ""c:\inetpub\wwwroot"") -eq `$false) {
  `$IISFeatures = ""Web-WebServer"",""Web-Common-Http"",""Web-Default-Doc"",""Web-Http-Errors"",""Web-Http-Redirect"",""Web-Health"",""Web-Http-Logging"",""Web-Security"",""Web-Filtering"",""Web-Basic-Auth"",""Web-Client-Auth"",""Web-IP-Security"",""Web-Windows-Auth"",""Web-Net-Ext"",""Web-Net-Ext45"",""Web-Asp-Net"",""Web-Asp-Net45"",""Web-ISAPI-Ext"",""Web-ISAPI-Filter"",""Web-Mgmt-Tools"",""Web-Mgmt-Console""
  Install-WindowsFeature -Name `$IISFeatures -ErrorAction SilentlyContinue
} 

If ((Test-Path ""`$installPath\authpage\authpage\default.aspx"") -eq `$false) {
  mkdir `$installPath -Force
  Invoke-WebRequest -Uri ""https://msdnshared.blob.core.windows.net/media/MSDNBlogsFS/prod.evol.blogs.msdn.com/CommunityServer.Components.PostAttachments/00/10/38/31/92/Authpage.zip"" -OutFile ""`$installPath\authpage.zip""
  Expand-Archive -LiteralPath ""`$installPath\authpage.zip"" -DestinationPath ""`$installPath\authpage""
}

If (Test-Path ""`$installPath\authpage\authpage\default.aspx"") {
  If (Test-Path ""c:\inetpub\wwwroot\iisstart.htm"") {
    Get-ChildItem -Path ""`$installPath\authpage\authpage"" -Recurse | Copy-Item -Destination ""c:\inetpub\wwwroot""
    Remove-Item ""c:\inetpub\wwwroot\iisstart.htm"" -ErrorAction SilentlyContinue
  }
} Else {
  Write-Output ""Extract of AuthPage failed""
}

If ((Test-Path ""c:\install\installer.flag"") -eq `$false) {
  Set-WebConfigurationProperty -Filter ""/system.webServer/security/authentication/anonymousAuthentication"" -Name Enabled -Value False -PSPath IIS:\ -location ""Default Web Site""
  Set-WebConfigurationProperty -Filter ""/system.webServer/security/authentication/windowsAuthentication"" -Name Enabled -Value True -PSPath IIS:\ -location ""Default Web Site""
  & `$ENV:windir\system32\inetsrv\appcmd.exe set AppPool DefaultAppPool -""processModel.identityType:NetworkService""
  `$Acl = (Get-Item ""c:\inetpub\wwwroot"").GetAccessControl(""Access"")
  `$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule(""NETWORK SERVICE"", ""ReadAndExecute"", ""ContainerInherit,ObjectInherit"", ""None"", ""Allow"")
  `$Acl.SetAccessRule(`$Ar)
  Set-Acl ""c:\inetpub\wwwroot"" `$Acl
  ""Install complete"" | Out-File ""c:\install\installer.flag""
} Else { Write-Output ""Install flag found - skipping setup tasks"" }
"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB2Name -g $rgName --scripts $scriptBAPP01_2
###

$scriptBAPP01_3 = @"
Install-WindowsFeature rsat-adds -IncludeAllSubFeature
try{
  Import-Module ActiveDirectory -ErrorAction Stop
}catch{
  throw ""Module ActiveDirectory not installed""
}
`$installPath = ""c:\install""
If ((Test-Path `$installPath) -eq `$false) {mkdir `$installPath -Force}

If ((Test-Path ""`$installPath\AzureADConnect.msi"") -eq `$false) {
  try {
    `$URi = ""https://www.microsoft.com/en-us/download/confirmation.aspx?id=47594""
    `$downloadPage = Invoke-WebRequest -Uri `$URi  -usebasicparsing
    `$fileUri = (`$downloadPage.RawContent.Split('""') -like ""https://*AzureADConnect.msi"")[0]
    Invoke-WebRequest -Uri `$fileUri -OutFile ""`$installPath\AzureADConnect.msi""
    Write-Output (""File {0} size: {1}"" -f (gci ""`$installPath\AzureADConnect.msi"").Name, ((gci ""`$installPath\AzureADConnect.msi"").Length / 1MB).ToString("".""))
  } catch {
    Write-Host `$(`$_.Exception.Message)
    throw 'ERROR: Could not download file'
  }
}

If ((Test-Path ""`$env:ProgramFiles\Microsoft Azure Active Directory Connect\AzureADConnect.exe"") -eq `$false) {
  & ""`$ENV:windir\system32\msiexec.exe"" /i ""`$installPath\AzureADConnect.msi"" /qb-
}

try {
  `$URi = ""https://www.powershellgallery.com/api/v2/package/AADConnectPermissions/7.3""
  Invoke-WebRequest -Uri `$URi  -OutFile ""`$installPath\AADConnectPermissions.zip""
  If ((Test-Path ""`$installPath\AADCP\AADConnectPermissions.ps1"") -eq `$false) { Expand-Archive -Path ""`$installPath\AADConnectPermissions.zip"" -DestinationPath ""`$installPath\AADCP"" }
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc_azuresync -PasswordHashSync
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc_azuresync -msDsConsistencyGuid -ExchangeHybridWriteBackOUs ""OU=Staff,OU=M_USERS,$dcBDomainDN""
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc_azuresync -PasswordWriteBack -ExchangeHybridWriteBackOUs ""OU=Staff,OU=M_USERS,$dcBDomainDN""
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc_a-azuresync -msDsConsistencyGuid -ExchangeHybridWriteBackOUs ""OU=Staff,OU=M_USERS,$dcBDomainDN""
} catch {
  Write-Host `$(`$_.Exception.Message)
  throw 'ERROR: Could not download file'
}

"@
az vm run-command invoke --command-id RunPowerShellScript --name $vmB2Name -g $rgName --scripts $scriptBAPP01_3
###

$nsg7Name = "jr-trustlab-nsg-b-client"

az network nsg create -n $nsg7Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet6Name --vnet-name $vnetName --network-security-group $nsg7Name
az network nsg rule create --nsg-name $nsg7Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet6Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg7Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet6Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"

$logWsName = "jr-trustlab-logs"
$flow7LogName = "jr-trustlab-flow-b-app"
az network watcher flow-log create -n $flow7LogName -g $rgName --enabled true --nsg $nsg7Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 --traffic-analytics --workspace $logWsName
###

$vmB3Image = "MicrosoftWindowsDesktop:Windows-10:20h2-ent:19042.867.2103051748"
$vmB3User = "lcladmin"
$vmB3Pass = $vmPass
$vmB3Size = "Standard_B2ms"
$vmB3DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vmB3Name -g $rgName --image $vmB3Image --admin-username $vmB3User --admin-password $vmB3Pass --computer-name $vmB3Name --size $vmB3Size --vnet-name $vnetName --subnet $subnet6Name --private-ip-address $vmB3IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vmB3Name)-OSdisk-$($vmB3DiskGuid)" --nsg '""' --public-ip-address '""'
###

$scriptBCLIENT01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$IP = ""$vmB3IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vmB3IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vmB1IPAddress""
`$IPType = ""IPv4""
`$adapter = Get-NetAdapter | ? {`$_.Status -eq ""up""}
`$interface = `$adapter | Get-NetIPInterface -AddressFamily `$IPType
If (`$interface.Dhcp -eq ""Enabled"") {
  Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding
  If ((`$adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
    `$adapter | Remove-NetIPAddress -AddressFamily `$IPType -Confirm:`$false
  }
  If ((`$adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
    `$adapter | Remove-NetRoute -AddressFamily `$IPType -Confirm:`$false
  }
  `$adapter | New-NetIPAddress -AddressFamily `$IPType -IPAddress `$IP -PrefixLength `$MaskBits -DefaultGateway `$Gateway
  `$adapter | Set-DnsClientServerAddress -ServerAddresses `$DNS
}
Start-Sleep -Seconds 15 # Wait for DNS changes

Add-Computer -DomainName ""$dcBDomain"" -Credential (New-Object System.Management.Automation.PSCredential(""$dcBDomain\$vmB1User"",(ConvertTo-SecureString '$vmB1Pass' -AsPlainText -Force))) -OUPath ""OU=M_WORKSTATIONS,$dcBDomainDN"" -Restart
"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB3Name -g $rgName --scripts $scriptBCLIENT01_1

$scriptBCLIENT01_2 = @"
Add-LocalGroupMember -Group ""Remote Desktop Users"" -Member ""$dcBDomain\Grp_AllStaff""

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vmB3Name -g $rgName --scripts $scriptBCLIENT01_2
###

az network public-ip list -g $rgName --query "[].dnsSettings" --output table
###