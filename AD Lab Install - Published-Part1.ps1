$rgName = "jr-trustlab-rg"
$vnetName = "jr-trustlab-vnet-01"
$vnetRange = "10.1.0.0/16"
$subnet1Name = "domainA-ad"
$subnet1Range = "10.1.10.0/24"
$subnet2Name = "domainA-app"
$subnet2Range = "10.1.20.0/24"
$subnet3Name = "domainA-client"
$subnet3Range = "10.1.30.0/24"
$subnet4Name = "domainB-ad"
$subnet4Range = "10.1.110.0/24"
$subnet5Name = "domainB-app"
$subnet5Range = "10.1.120.0/24"
$subnet6Name = "domainB-client"
$subnet6Range = "10.1.130.0/24"
$subnet99Name = "public"
$subnet99Range = "10.1.200.0/24"
$storageName = "jrtrustlabstore"
$region = "EastUS"
$vmPass = '' # Password used in local admin & AD recovery
$userPass = '' # Password used for test user accounts

$vm0Name = "vm-bas01"
$vm1Name = "vm-a-dc01"
$vm1IPAddress = "10.1.10.10"
$vm2Name = "vm-a-dc02"
$vm2IPAddress = "10.1.10.11"
$vm3Name = "vm-a-app01"
$vm3IPAddress = "10.1.20.20"
$vm4Name = "vm-a-app02"
$vm4IPAddress = "10.1.20.21"
$vm5Name = "vm-a-client01"
$vm5IPAddress = "10.1.30.30"
$vmB1Name = "vm-b-dc01"
$vmB1IPAddress = "10.1.110.10"
$vmB2Name = "vm-b-app01"
$vmB2IPAddress = "10.1.120.20"
$vmB3Name = "vm-b-client01"
$vmB3IPAddress = "10.1.130.30"
###

az group create -l $region -n $rgName
###

az network vnet create -g $rgName -n $vnetName --address-prefix $vnetRange --subnet-name $subnet1Name --subnet-prefixes $subnet1Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet2Name --address-prefixes $subnet2Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet3Name --address-prefixes $subnet3Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet4Name --address-prefixes $subnet4Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet5Name --address-prefixes $subnet5Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet6Name --address-prefixes $subnet6Range
az network vnet subnet create -g $rgName --vnet-name $vnetName -n $subnet99Name --address-prefixes $subnet99Range

# Optional - create Log Analaytics Workspace for Network Watcher traffic analysis
$logWsName = "jr-trustlab-logs"
az monitor log-analytics workspace create -g $rgName -n $logWsName --quota 1
az provider register --namespace Microsoft.Insights
###

$storageSku = "Standard_LRS"
$storageKind = "StorageV2"
az storage account create -n $storageName -g $rgName --sku $storageSku --kind $storageKind
###

$nsg0Name = "jr-trustlab-nsg-bastion"
$nsg0TrustedIP = "" # Replace with own source IP(s) where you'll allow RDP

az network nsg create -n $nsg0Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet99Name --vnet-name $vnetName --network-security-group $nsg0Name
az network nsg rule create --nsg-name $nsg0Name -g $rgName -n "AllowRDP" --priority 100 --access "allow" --source-address-prefixes $nsg0TrustedIP --destination-address-prefixes $subnet99Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from trusted IPs"

# Think twice about flow logging on a public IP - could be noisy ... and you pay for data generated
# Or at least consider Flow Logs without Traffic Analytics.
$flow0LogName = "jr-trustlab-flow-public"
az network watcher flow-log create -n $flow0LogName -g $rgName --enabled true --nsg $nsg0Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 #--traffic-analytics --workspace $logWsName
###

$vm0Image = "Win2019Datacenter"
$vm0User = "lcladmin"
$vm0Pass = $vmPass
$vm0Size = "Standard_DS2_v2"
$vm0PublicName = "jr-trustlab-bas" # jr-bas.eastus.cloudapp.azure.com
$vm0PIPName = "jr-trustlab-pip01"
$vm0DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vm0Name -g $rgName --image $vm0Image --admin-username $vm0User --admin-password $vm0Pass --computer-name $vm0Name --size $vm0Size --vnet-name $vnetName --subnet $subnet99Name --storage-account $storageName --use-unmanaged-disk --public-ip-address-dns-name $vm0PublicName --public-ip-address $vm0PIPName --os-disk-name "$($vm0Name)-OSdisk-$($vm0DiskGuid)" --nsg '""'

# Install-WindowsFeature rsat-adds -IncludeAllSubFeature
az vm extension set -n BGInfo --publisher Microsoft.Compute --version 2.1 --vm-name $vm0Name -g $rgName
###

# Create NSG - A-DC
$nsg1Name = "jr-trustlab-nsg-a-ad"
az network nsg create -n $nsg1Name -g $rgName

# Add rules to NSG to allow AD traffic
az network vnet subnet update -g $rgName -n $subnet1Name --vnet-name $vnetName --network-security-group $nsg1Name
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet1Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Allow_AD_TCP" --priority 110 --access "allow" --source-address-prefixes $subnet1Range $subnet2Range $subnet3Range --destination-address-prefixes $subnet1Range --destination-port-ranges 135 389 636 53 88 445 49152-65535 --protocol "TCP" --description "Allow AD traffic TCP"
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Allow_AD_UDP" --priority 111 --access "allow" --source-address-prefixes $subnet1Range $subnet2Range $subnet3Range --destination-address-prefixes $subnet1Range --destination-port-ranges 53 88 389 --protocol "UDP" --description "Allow AD traffic UDP"
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Allow_B_AD_TCP" --priority 120 --access "allow" --source-address-prefixes $vmB1IPAddress --destination-address-prefixes $vm3IPAddress --destination-port-ranges 135 389 636 53 88 445 49152-65535 --protocol "TCP" --description "Allow AD traffic TCP"
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Allow_B_AD_UDP" --priority 121 --access "allow" --source-address-prefixes $vmB1IPAddress --destination-address-prefixes $vm3IPAddress --destination-port-ranges 53 88 389 --protocol "UDP" --description "Allow AD traffic UDP"
az network nsg rule create --nsg-name $nsg1Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet1Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"

# Enable Network Watcher with Traffic Analytics
$flowLogName = "jr-trustlab-flow-ad"
az network watcher flow-log create -n $flowLogName -g $rgName --enabled true --nsg $nsg1Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 --traffic-analytics --workspace $logWsName
###

$vm1Image = "Win2019Datacenter"
$vm1User = "lcladmin"
$vm1Pass = $vmPass
$vm1Size = "Standard_B2ms"
$vm1DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

# Create VM
az vm create -n $vm1Name -g $rgName --image $vm1Image --admin-username $vm1User --admin-password $vm1Pass --computer-name $vm1Name --size $vm1Size --vnet-name $vnetName --subnet $subnet1Name --private-ip-address $vm1IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vm1Name)-OSdisk-$($vm1DiskGuid)" --nsg '""' --public-ip-address '""'

# Attach data disk
$disk1Guid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)
$disk1Name = "$($vm1Name)-DataDisk-$($disk1Guid)"
$disk1Size = "64"
$disk1Cache = "None"
az vm unmanaged-disk attach -g $rgName --vm-name $vm1Name --new --name $disk1Name --size-gb $disk1Size --caching $disk1Cache
###

$dcA1Domain="corp.local"
$dcA1DomainNetbios="corp"

$scriptADC01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$disks = Get-Disk | Where partitionstyle -eq 'raw'
If (`$disks) {
  `$disks | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter ""G"" | Format-Volume -FileSystem NTFS -NewFileSystemLabel ""Data"" -Confirm:`$false -Force
}
`$domain = ""$dcA1Domain""
`$domainnetbios = ""$dcA1DomainNetbios""
`$IP = ""$vm1IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vm1IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vm1IPAddress""
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
Install-ADDSForest -DomainName `$domain -SafeModeAdministratorPassword (convertto-securestring '$vm1Pass' -asplaintext -force)  -DomainMode Win2012R2 -DomainNetbiosName `$domainnetbios -ForestMode Win2012R2 -DatabasePath """G:\NTDS""" -SysvolPath """G:\SYSVOL""" -LogPath """G:\Logs""" -Force"

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm1Name -g $rgName --scripts $scriptADC01_1
### RUN THIS LATER

$dcA2UPNSuffix = "contoso.com"

$scriptADC01_2 = @"
try{
  Import-Module ActiveDirectory -ErrorAction Stop
}catch{
  throw ""Module ActiveDirectory not installed""
}

if ((Get-ADForest).UPNsuffixes -notcontains ""$dcA2UPNSuffix""){
  Get-ADForest | Set-ADForest -UPNSuffixes @{add=""$dcA2UPNSuffix""}
}
"@
az vm run-command invoke --command-id RunPowerShellScript --name $vm1Name -g $rgName --scripts $scriptADC01_2
###

$vm2Image = "Win2019Datacenter"
$vm2User = "lcladmin"
$vm2Pass = $vmPass
$vm2Size = "Standard_B2ms"
$vm2DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vm2Name -g $rgName --image $vm2Image --admin-username $vm2User --admin-password $vm2Pass --computer-name $vm2Name --size $vm2Size --vnet-name $vnetName --subnet $subnet1Name --private-ip-address $vm2IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vm2Name)-OSdisk-$($vm2DiskGuid)" --nsg '""' --public-ip-address '""'

# Attach data disk
$disk2Guid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)
$disk2Name = "$($vm2Name)-DataDisk-$($vm2DiskGuid)"
$disk2Size = "64"
$disk2Cache = "None"
az vm unmanaged-disk attach -g $rgName --vm-name $vm2Name --new --name $disk2Name --size-gb $disk2Size --caching $disk2Cache
###

$dcA1Domain="corp.local"
$dcA1DomainNetbios="corp"
$dcA1DomainDN="DC=corp,DC=local"
$dcA2Domain="contoso.internal"
$dcA2DomainNetbios="contoso"
$dcA2UPNSuffix="contoso.com"
$dcA2DomainDN="DC=contoso,DC=internal"
$dcBDomain="wingtip.root"

$scriptADC02_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$disks = Get-Disk | Where partitionstyle -eq 'raw'
If (`$disks) {
  `$disks | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter ""G"" | Format-Volume -FileSystem NTFS -NewFileSystemLabel ""Data"" -Confirm:`$false -Force
}
`$domain = ""$dcA2Domain""
`$domainnetbios = ""$dcA2DomainNetbios""
`$IP = ""$vm2IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vm2IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vm1IPAddress""
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

`$password = ConvertTo-SecureString '$vm2Pass' -AsPlainText -Force
`$adminCred = New-Object System.Management.Automation.PSCredential -ArgumentList (""$dcA1Domain\$vm1User"", `$password)

Install-ADDSDomain -Credential `$adminCred -SafeModeAdministratorPassword (convertto-securestring '$vm2Pass' -asplaintext -force) -NewDomainName `$domain -NewDomainNetbiosName `$domainNetbios -ParentDomainName ""$dcA1Domain"" -InstallDNS -DomainMode Win2012R2 -DomainType TreeDomain -ReplicationSourceDC ""$vm1Name.$dcA1Domain"" -DatabasePath ""G:\NTDS"" -SYSVOLPath ""G:\SYSVOL"" -LogPath ""G:\Logs"" -Force 

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm2Name -g $rgName --scripts $scriptADC02_1
###

$scriptADC02_2 = @"
try{
  Import-Module ActiveDirectory -ErrorAction Stop
}catch{
  throw ""Module ActiveDirectory not installed""
}

`$password = ConvertTo-SecureString '$vm2Pass' -AsPlainText -Force
`$adminCred = New-Object System.Management.Automation.PSCredential -ArgumentList (""$dcA1Domain\$vm1User"", `$password)

Enable-ADOptionalFeature -Identity ""CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$dcA1DomainDN"" -Scope ForestOrConfigurationSet -Target ""$dcA2Domain"" -Confirm:`$false -Credential `$adminCred

if ((Get-ADForest).UPNsuffixes -notcontains ""$dcA2UPNSuffix""){
  `$password = ConvertTo-SecureString '$vm1Pass' -AsPlainText -Force
  `$adminCred = New-Object System.Management.Automation.PSCredential -ArgumentList (""$dcA1Domain\$vm1User"", `$password)
  Get-ADForest | Set-ADForest -UPNSuffixes @{add=""$dcA2UPNSuffix""} -Credential `$adminCred
}

function New-ADOU {
  # http://www.alexandreviot.net/2015/04/27/active-directory-create-ou-using-powershell
  param([parameter(Mandatory=`$true)] [array]`$ouList)
  ForEach(`$OU in `$ouList){
    try{
      New-ADOrganizationalUnit -Name ""`$(`$OU.Name)"" -Path ""`$(`$OU.Path)""
    }catch{
       Write-Host `$error[0].Exception.Message
    }
  }
}
`$ouCSV = ""Name;Path
S_SERVERS;$dcA2DomainDN
S_USERS;$dcA2DomainDN
ServiceAccounts;ou=S_USERS,$dcA2DomainDN
Staff;ou=S_USERS,$dcA2DomainDN
S_WORKSTATIONS;$dcA2DomainDN
S_GROUPS;$dcA2DomainDN""
`$ouList = `$ouCSV | ConvertFrom-CSV -Delimiter "";""

New-ADOU `$ouList
New-ADGroup -Name ""Grp_AllStaff"" -SamAccountName Grp_AllStaff -GroupCategory Security -GroupScope Global -DisplayName ""Grp_All Staff"" -Path ""OU=S_GROUPS,$dcA2DomainDN""

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm2Name -g $rgName --scripts $scriptADC02_2
###

$scriptADC02_3 = @"
try{
  Import-Module ActiveDirectory -ErrorAction Stop
}catch{
  throw ""Module ActiveDirectory not installed""
}

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

`$userOU = ""ou=Staff,ou=S_USERS,$dcA2DomainDN""
`$userPass = '$userPass'
`$usersCSV = ""Firstname;Lastname
barry;tycholiz
benjamin;rogers
bill;rapp
bill;williams
brad;mckay
cara;semperger
carol;stclair
chris;dorland
chris;germany
chris;stokley
cooper;richey
craig;dean
dana;davis
danny;mccarty
dan;hyvl
daren;farmer
darrell;schoolcraft
darron;cgiron
david;delainey""
`$userList = `$usersCSV | ConvertFrom-CSV -Delimiter "";""

`$users = Get-ADUser -Filter * -SearchBase `$userOU | select -expand samAccountName
If ((`$users) -eq `$null) {
  Create-TestUsers `$userList `$userPass ""$dcA2UPNSuffix"" `$userOU
}
`$users = Get-ADUser -Filter * -SearchBase `$userOU | select -expand samAccountName
`$group = ""Grp_AllStaff""
Add-ADGroupMember -Identity `$group -Members `$users

"@
az vm run-command invoke --command-id RunPowerShellScript --name $vm2Name -g $rgName --scripts $scriptADC02_3
###

$scriptADC02_4 = @"

`$displayName = ""svc-azuresync""
`$username = ""svc-azuresync""
`$upn = ""svc-azuresync@$dcA2UPNSuffix""
`$OUPath = ""OU=ServiceAccounts,OU=S_USERS,$dcA2DomainDN""
`$userPass = '$vmPass'

New-ADUser -Name `$displayName -DisplayName `$displayName -SamAccountName `$username -UserPrincipalName `$upn -description ""AAD Connect"" -Path `$OUPath -Enabled `$true -ChangePasswordAtLogon `$false -Department `$Department -AccountPassword (ConvertTo-SecureString `$userPass -AsPlainText -force)
"@
az vm run-command invoke --command-id RunPowerShellScript --name $vm2Name -g $rgName --scripts $scriptADC02_4
###

$scriptADC02_5 = @"
Add-DnsServerConditionalForwarderZone -Name ""$dcBDomain"" -ReplicationScope ""Domain"" -MasterServers $vmB1IPAddress
"@
az vm run-command invoke --command-id RunPowerShellScript --name $vm2Name -g $rgName --scripts $scriptADC02_5
###

