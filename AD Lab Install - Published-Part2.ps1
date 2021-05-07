# Remember to run the baseline variables from Part 1
###

$nsg3Name = "jr-trustlab-nsg-a-app"

az network nsg create -n $nsg3Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet2Name --vnet-name $vnetName --network-security-group $nsg3Name
az network nsg rule create --nsg-name $nsg3Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet2Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg3Name -g $rgName -n "Allow_HTTP" --priority 110 --access "allow" --source-address-prefixes $subnet1Range $subnet2Range $subnet3Range --destination-address-prefixes $subnet2Range --destination-port-ranges 80 443 --protocol "TCP" --description "Allow HTTP traffic"
az network nsg rule create --nsg-name $nsg3Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet2Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"

$logWsName = "jr-trustlab-logs"
$flow2LogName = "jr-trustlab-flow-a-app"
az network watcher flow-log create -n $flow2LogName -g $rgName --enabled true --nsg $nsg3Name --storage-account $storageName --location $region --format JSON --log-version 2 --retention 7 --traffic-analytics --workspace $logWsName
###

$vm3Image = "Win2019Datacenter"
$vm3User = "lcladmin"
$vm3Pass = $vmPass
$vm3Size = "Standard_B2ms"
$vm3DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vm3Name -g $rgName --image $vm3Image --admin-username $vm3User --admin-password $vm3Pass --computer-name $vm3Name --size $vm3Size --vnet-name $vnetName --subnet $subnet2Name --private-ip-address $vm3IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vm3Name)-OSdisk-$($vm3DiskGuid)" --nsg '""' --public-ip-address '""'
###

$scriptAAPP01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$IP = ""$vm3IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vm3IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vm2IPAddress""
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

Add-Computer -DomainName ""$dcA2Domain"" -Credential (New-Object System.Management.Automation.PSCredential(""$dcA2Domain\$vm3User"",(ConvertTo-SecureString '$vm3Pass' -AsPlainText -Force))) -OUPath ""OU=S_SERVERS,$dcA2DomainDN"" -Restart

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm3Name -g $rgName --scripts $scriptAAPP01_1
###

$scriptAAPP01_2 = @"
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

az vm run-command invoke --command-id RunPowerShellScript --name $vm3Name -g $rgName --scripts $scriptAAPP01_2
###

$vm5Image = "Win2019Datacenter"
$vm5User = "lcladmin"
$vm5Pass = $vmPass
$vm5Size = "Standard_B2ms"
$vm5DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vm5Name -g $rgName --image $vm5Image --admin-username $vm5User --admin-password $vm5Pass --computer-name $vm5Name --size $vm5Size --vnet-name $vnetName --subnet $subnet2Name --private-ip-address $vm5IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vm5Name)-OSdisk-$($vm5DiskGuid)" --nsg '""' --public-ip-address '""'###

$scriptAAPP02_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$IP = ""$vm4IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vm4IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vm2IPAddress""
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

Add-Computer -DomainName ""$dcA2Domain"" -Credential (New-Object System.Management.Automation.PSCredential(""$dcA2Domain\$vm4User"",(ConvertTo-SecureString '$vm4Pass' -AsPlainText -Force))) -OUPath ""OU=S_SERVERS,$dcA2DomainDN"" -Restart

"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm4Name -g $rgName --scripts $scriptAAPP02_1
###

$scriptAAPP02_2 = @"
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
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc-azuresync -PasswordHashSync
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc-azuresync -msDsConsistencyGuid -ExchangeHybridWriteBackOUs ""OU=Staff,OU=S_USERS,$dcA2DomainDN""
  & ""`$installPath\AADCP\AADConnectPermissions.ps1"" -User svc-azuresync -PasswordWriteBack -ExchangeHybridWriteBackOUs ""OU=Staff,OU=S_USERS,$dcA2DomainDN""
} catch {
  Write-Host `$(`$_.Exception.Message)
  throw 'ERROR: Could not download file'
}

"@
az vm run-command invoke --command-id RunPowerShellScript --name $vm4Name -g $rgName --scripts $scriptAAPP02_2
###

$nsg4Name = "jr-trustlab-nsg-a-client"

az network nsg create -n $nsg4Name -g $rgName
az network vnet subnet update -g $rgName -n $subnet3Name --vnet-name $vnetName --network-security-group $nsg4Name
az network nsg rule create --nsg-name $nsg4Name -g $rgName -n "Allow_RDP" --priority 100 --access "allow" --source-address-prefixes $subnet99Range --destination-address-prefixes $subnet3Range --destination-port-ranges "3389" --protocol "TCP" --description "Allow RDP from Bastion"
az network nsg rule create --nsg-name $nsg4Name -g $rgName -n "Deny_Inbound" --priority 4000 --access "deny" --source-address-prefixes "*" --destination-address-prefixes $subnet3Range --destination-port-ranges "*" --protocol "*" --description "Deny inbound traffic"
###

$vm5Image = "MicrosoftWindowsDesktop:Windows-10:20h2-ent:19042.867.2103051748"
$vm5User = "lcladmin"
$vm5Pass = $vmPass
$vm5Size = "Standard_B2ms"
$vm5DiskGuid = [guid]::NewGuid().ToString().Replace("-","").Substring(0,10)

az vm create -n $vm5Name -g $rgName --image $vm5Image --admin-username $vm5User --admin-password $vm5Pass --computer-name $vm5Name --size $vm5Size --vnet-name $vnetName --subnet $subnet3Name --private-ip-address $vm5IPAddress --storage-account $storageName --use-unmanaged-disk --os-disk-name "$($vm5Name)-OSdisk-$($vm5DiskGuid)" --nsg '""' --public-ip-address '""'
###

$scriptACLIENT01_1 = @"
Set-TimeZone -id 'E. Australia Standard Time'
`$IP = ""$vm5IPAddress""
`$MaskBits = 24
`$Gateway = ""$($vm5IPAddress -split "\d{1,3}$" -join "1")""
`$DNS = ""$vm2IPAddress""
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

Add-Computer -DomainName ""$dcA2Domain"" -Credential (New-Object System.Management.Automation.PSCredential(""$dcA2Domain\$vm5User"",(ConvertTo-SecureString '$vm5Pass' -AsPlainText -Force))) -OUPath ""OU=S_WORKSTATIONS,$dcA2DomainDN"" -Restart
"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm5Name -g $rgName --scripts $scriptACLIENT01_1
###

$scriptACLIENT01_2 = @"
Add-LocalGroupMember -Group ""Remote Desktop Users"" -Member ""$dcA2Domain\Grp_AllStaff""
"@

az vm run-command invoke --command-id RunPowerShellScript --name $vm5Name -g $rgName --scripts $scriptACLIENT01_2
###
