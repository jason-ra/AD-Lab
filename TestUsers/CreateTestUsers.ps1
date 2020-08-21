# Adapted from

param ([parameter(Mandatory=$false)]
[string]
$OU = "OU=TestUsers,OU=Cloud Inc.,DC=cloud,DC=lab"
[string]
$path = "c:\install"
[string]
$UPNsuffix = "tailspintoys.com"
)
#Define variables
$Departments = @("IT","Finance","Logistics","Sourcing","Human Resources")
$Names = Import-CSV "$($path)\EnronUserList.csv"
$Password = "Password1"

try{
  Import-Module ActiveDirectory -ErrorAction Stop
}
catch{
  throw "Module ActiveDirectory not Installed"
}
foreach ($Name in $Names) {
      $firstname = $Name.Firstname
      $stname = $Name.Lastname
      $Department = $Departments | Get-Random
      $username = $firstname.Substring(0,2).tolower() + $lastname.Substring(0,3).tolower()
      $exit = 0
      $count = 1
        do
        {
             try {
                 $userexists = Get-AdUser -Identity $username
                 $username = $firstname.Substring(0,2).tolower() + $lastname.Substring(0,3).tolower() + $count++
             }
             catch {
                 $exit = 1
             }
         }
        while ($exit -eq 0)
       $displayname = $firstname + " " + $lastname
       $upn = $username + "@" + $UPNsuffix

       New-ADUser –Name $displayname –DisplayName $displayname `
                 –SamAccountName $username -UserPrincipalName $upn `
                 -GivenName $firstname -Surname $lastname -description "Test User" `
                 -Path $ou –Enabled $true –ChangePasswordAtLogon $false -Department $Department `
                 -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -force)
}
