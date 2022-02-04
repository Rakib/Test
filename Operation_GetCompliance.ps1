<#
.Description
Leverandøren anser at avtalen i sin helhet er underlagt konfidensialitet jf. SSA-D punkt 7.3. Leverandøren har også markert informasjon som er ansett for å være særlig konfidensiell med vannmerket «konfidensielt». Denne informasjonen må ikke gjøres tilgjengelig for tredjeparter eller kundens underleverandører uten at Leverandøren har samtykket til dette. Antall ansatte hos Kundens leverandører og tredjeparter som gis tilgang til slik informasjon skal begrenses til det som er strengt nødvendige for at disse skal kunne handle på Kundens vegne. Det skal inngås individuelle taushetserklæringer med slike ansatte som er minst like strene som kravene i SSA-D.
.Author
Helge Garder - Right Experience Device Management - Sopra Steria
#>
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
}

$module = Get-InstalledModule -Name "AzureAD"

if ($module -eq $null) {
    Clear-Host
    Write-Host '
    ################################################################
    ######## Please wait while AzureAD module is installing ########
    ################################################################
    ' -ForegroundColor cyan
    Install-Module -Name "AzureAD" -AllowClobber -Force
}

else {
    Clear-Host
    Write-Host '
    #########################################################################
    ######## Please wait while AzureAD module is imported to session ########
    #########################################################################
    ' -ForegroundColor cyan
    Import-Module -Name $module.Name
}

$module1 = Get-InstalledModule -Name "ImportExcel"

if ($module1 -eq $null) {
    Clear-Host
    Write-Host '
    ####################################################################
    ######## Please wait while ImportExcel module is installing ########
    ####################################################################
    ' -ForegroundColor cyan
    Install-Module -Name "ImportExcel" -AllowClobber -Force
}

else {
    Clear-Host
    Write-Host '
    #############################################################################
    ######## Please wait while ImportExcel module is imported to session ########
    #############################################################################
    ' -ForegroundColor cyan
    Import-Module -Name $module1.Name
}

$module2 = Get-InstalledModule -Name "Microsoft.Graph.Intune"

if ($module2 -eq $null) {
    Clear-Host
    Write-Host '
    ########################################################################
    ######## Please wait while Microsoft Graph module is installing ########
    ########################################################################
    ' -ForegroundColor cyan
    Install-Module -Name "Microsoft.Graph.Intune" -AllowClobber -Force
}

else {
    Clear-Host
    Write-Host '
    #################################################################################
    ######## Please wait while Microsoft Graph module is imported to session ########
    #################################################################################
    ' -ForegroundColor cyan
    Import-Module -Name $module2.Name
}

function Get-AuthToken {

    <#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1) {

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($AadModule.count -gt 1) {

            $aadModule = $AadModule | select -Unique

        }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken) {

            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }

            return $authHeader

        }

        else {

            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break

        }

    }

    catch {

        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break

    }

}

Function Test-AuthToken() {

    # Checking if authToken exists before running authentication
    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if ($User -eq $null -or $User -eq "") {

                $Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host

            }

            $global:authToken = Get-AuthToken -User $User

        }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

    else {

        if ($User -eq $null -or $User -eq "") {

            $Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

        }

        # Getting the authorization token
        $global:authToken = Get-AuthToken -User $User

    }
}


Function Get-WindowsCompliance {       

Function Get-ComplianceActiveFirewall {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.ActiveFirewallRequired/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceAntiSpyware {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.AntiSpywareRequired/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceAntiVirus {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.AntivirusRequired/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceBitlocker {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.BitLockerEnabled/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceCodeIntegrity {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.CodeIntegrityEnabled/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceMicrosoftDefender {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.DefenderEnabled/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceMDATPSecurityLevel {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.DeviceThreatProtectionRequiredSecurityLevel/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceMinimumOSVersion {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.OsMinimumVersion/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceSimplePassword {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.PasswordBlockSimple/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-CompliancePassword {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.PasswordRequired/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceRTP {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.RtpEnabled/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceSignatureOutOfDate {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.SignatureOutOfDate/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceEncryption {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.StorageRequireEncryption/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceTPM {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.TpmRequired/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceSecureBoot {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/Windows10CompliancePolicy.secureBootEnabled/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceIsActive {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireRemainContact/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-CompliancePolicyAssigned {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}

Function Get-ComplianceUserExistence {

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireUserExistence/deviceComplianceSettingStates"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
}



$CompanyName = $Connect.TenantDomain

$date = Get-Date -Format "dd-MM-yy HH-mm-ss"

$OutputFile = "C:\Skript\Reports\$CompanyName - Windows Compliance Report - $date.xlsx"

$Devices = Get-IntuneManagedDevice | Get-MSGraphAllPages | Where operatingSystem -eq "Windows"

# Table Name
$tabName = "Compliance Report"

# Create Table object
$table = New-Object system.Data.DataTable “$tabName”

# User Info
$table.columns.add("FullDisplayName") | Out-Null
$table.columns.add("Email") | Out-Null

# Device State
$table.columns.add("ObjectID") | Out-Null
$table.columns.add("DeviceName") | Out-Null
$table.columns.add("Enrolled") | Out-Null
$table.columns.add("LastSync") | Out-Null
$table.columns.add("OverallCompliance") | Out-Null

# Compliance Settings
$table.columns.add("CompliancePolicyAssigned") | Out-Null
$table.columns.add("UserExistence") | Out-Null
$table.columns.add("IsActive") | Out-Null
$table.columns.add("ActiveFirewall") | Out-Null
$table.columns.add("AntiSpyware") | Out-Null
$table.columns.add("Antivirus") | Out-Null
$table.columns.add("Bitlocker") | Out-Null
$table.columns.add("CodeIntegrity") | Out-Null
$table.columns.add("MicrosoftDefender") | Out-Null
$table.columns.add("SecurityLevel") | Out-Null
$table.columns.add("WinOsVersion") | Out-Null
$table.columns.add("SimplePassword") | Out-Null
$table.columns.add("Password") | Out-Null
$table.columns.add("RealTimeProtection") | Out-Null
$table.columns.add("SignatureOutOfDate") | Out-Null
$table.columns.add("Encryption") | Out-Null
$table.columns.add("TPM") | Out-Null
$table.columns.add("SecureBoot") | Out-Null

$isActive = Get-ComplianceIsActive | Get-MSGraphAllPages
$policyAssigned = Get-CompliancePolicyAssigned | Get-MSGraphAllPages
$userExistence = Get-ComplianceUserExistence | Get-MSGraphAllPages
$Firewall = Get-ComplianceActiveFirewall | Get-MSGraphAllPages
$AntiSpyware = Get-ComplianceAntiSpyware | Get-MSGraphAllPages
$AntiVirus = Get-ComplianceAntiVirus | Get-MSGraphAllPages
$Bitlocker = Get-ComplianceBitLocker | Get-MSGraphAllPages
$CodeIntegrity = Get-ComplianceCodeIntegrity | Get-MSGraphAllPages
$MSDefender = Get-ComplianceMicrosoftDefender | Get-MSGraphAllPages
$SecurityLevel = Get-ComplianceMDATPSecurityLevel | Get-MSGraphAllPages
$WinOsVersion = Get-ComplianceMinimumOSVersion | Get-MSGraphAllPages
$SimplePassword = Get-ComplianceSimplePassword | Get-MSGraphAllPages
$Password = Get-CompliancePassword | Get-MSGraphAllPages
$RTP = Get-ComplianceRTP | Get-MSGraphAllPages
$SignatureOutOfDate = Get-ComplianceSignatureOutOfDate | Get-MSGraphAllPages
$Encryption = Get-ComplianceEncryption | Get-MSGraphAllPages
$TPM = Get-ComplianceTPM | Get-MSGraphAllPages
$SecureBoot = Get-ComplianceSecureBoot | Get-MSGraphAllPages

$counter = 0

Foreach ($Device in $Devices) {

    $counter++
    $counterString = $counter.ToString()
    $devicetoString = ($devices.Count).ToString()
    $operation = "$counterString/$devicetoString Devices"

    Write-Progress -Activity 'Processing Windows Compliance' -CurrentOperation $operation -PercentComplete (($counter / $Devices.count) * 100)

    #Creating new row
    $row = $table.NewRow()

    # User Info
    $row.Email = $Device.userPrincipalName
    $row.FullDisplayName = $device.userDisplayName

    # Device State
    $row.ObjectID = $Device.id
    $row.DeviceName = $Device.deviceName
    $row.Enrolled = $Device.enrolledDateTime
    $row.LastSync = $Device.lastSyncDateTime
    $row.OverallCompliance = $Device.complianceState

    if ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $PolicyArray = $policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $PolicyArray.Count; $i++) {
                if ($PolicyArray[$i].state -ne $PolicyArray[$i + 1].state) {
                    if (($PolicyArray[$i].state -eq "NonCompliant") -or ($PolicyArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($PolicyArray[$i].state -eq "Error") -or ($PolicyArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($PolicyArray[$i].state -eq "Not Applicable") -or ($PolicyArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.CompliancePolicyAssigned = $state
        }

        elseif (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.CompliancePolicyAssigned = ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.CompliancePolicyAssigned = "NotConfigured"
    }



    if ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $UserArray = $userExistence | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $UserArray.Count; $i++) {
                if ($UserArray[$i].state -ne $UserArray[$i + 1].state) {
                    if (($UserArray[$i].state -eq "NonCompliant") -or ($UserArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($UserArray[$i].state -eq "Error") -or ($UserArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($UserArray[$i].state -eq "Not Applicable") -or ($UserArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.UserExistence = $state
        }

        elseif (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.UserExistence = ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.UserExistence = "NotConfigured"
    }




    if ($isActive | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $isActiveArray = $isActive | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $isActiveArray.Count; $i++) {
                if ($isActiveArray[$i].state -ne $isActiveArray[$i + 1].state) {
                    if (($isActiveArray[$i].state -eq "NonCompliant") -or ($isActiveArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($isActiveArray[$i].state -eq "Error") -or ($isActiveArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($isActiveArray[$i].state -eq "Not Applicable") -or ($isActiveArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.IsActive = $state
        }

        elseif (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.IsActive = ($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.IsActive = "NotConfigured"
    }


    if ($Firewall | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($Firewall | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $FirewallArray = $Firewall | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $FirewallArray.Count; $i++) {
                if ($FirewallArray[$i].state -ne $FirewallArray[$i + 1].state) {
                    if (($FirewallArray[$i].state -eq "NonCompliant") -or ($FirewallArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($FirewallArray[$i].state -eq "Error") -or ($FirewallArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($FirewallArray[$i].state -eq "Not Applicable") -or ($FirewallArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.ActiveFirewall = $state
        }

        elseif (($Firewall | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.ActiveFirewall = ($Firewall | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.ActiveFirewall = "NotConfigured"
    }

    if ($AntiSpyware | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($AntiSpyware | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $AntiSpywareArray = $AntiSpyware | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $AntiSpywareArray.Count; $i++) {
                if ($AntiSpywareArray[$i].state -ne $AntiSpywareArray[$i + 1].state) {
                    if (($AntiSpywareArray[$i].state -eq "NonCompliant") -or ($AntiSpywareArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($AntiSpywareArray[$i].state -eq "Error") -or ($AntiSpywareArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($AntiSpywareArray[$i].state -eq "Not Applicable") -or ($AntiSpywareArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.AntiSpyware = $state
        }

        elseif (($AntiSpyware | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.AntiSpyware = ($AntiSpyware | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.AntiSpyware = "NotConfigured"
    }

    if ($AntiVirus | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($AntiVirus | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $AntiVirusArray = $AntiVirus | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $AntiVirusArray.Count; $i++) {
                if ($AntiVirusArray[$i].state -ne $AntiVirusArray[$i + 1].state) {
                    if (($AntiVirusArray[$i].state -eq "NonCompliant") -or ($AntiVirusArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($AntiVirusArray[$i].state -eq "Error") -or ($AntiVirusArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($AntiVirusArray[$i].state -eq "Not Applicable") -or ($AntiVirusArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.AntiVirus = $state
        }

        elseif (($AntiVirus | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.AntiVirus = ($AntiVirus | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.AntiVirus = "NotConfigured"
    }

    if ($Bitlocker | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($Bitlocker | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $BitlockerArray = $Bitlocker | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $BitlockerArray.Count; $i++) {
                if ($BitlockerArray[$i].state -ne $BitlockerArray[$i + 1].state) {
                    if (($BitlockerArray[$i].state -eq "NonCompliant") -or ($BitlockerArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($BitlockerArray[$i].state -eq "Error") -or ($BitlockerArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($BitlockerArray[$i].state -eq "Not Applicable") -or ($BitlockerArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.Bitlocker = $state
        }

        elseif (($Bitlocker | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.Bitlocker = ($Bitlocker | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.Bitlocker = "NotConfigured"
    }





    if ($CodeIntegrity | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($CodeIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $CodeArray = $CodeIntegrity | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $CodeArray.Count; $i++) {
                if ($CodeArray[$i].state -ne $CodeArray[$i + 1].state) {
                    if (($CodeArray[$i].state -eq "NonCompliant") -or ($CodeArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($CodeArray[$i].state -eq "Error") -or ($CodeArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($CodeArray[$i].state -eq "Not Applicable") -or ($CodeArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.CodeIntegrity = $state
        }

        elseif (($CodeIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.CodeIntegrity = ($CodeIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.CodeIntegrity = "NotConfigured"
    }



    if ($MSDefender | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($MSDefender | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $MSDefenderArray = $MSDefender | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $MSDefenderArray.Count; $i++) {
                if ($MSDefenderArray[$i].state -ne $MSDefenderArray[$i + 1].state) {
                    if (($MSDefenderArray[$i].state -eq "NonCompliant") -or ($MSDefenderArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($MSDefenderArray[$i].state -eq "Error") -or ($MSDefenderArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($MSDefenderArray[$i].state -eq "Not Applicable") -or ($MSDefenderArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.MicrosoftDefender = $state
        }

        elseif (($MSDefender | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.MicrosoftDefender = ($MSDefender | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.MicrosoftDefender = "NotConfigured"
    }


    if ($SecurityLevel | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($SecurityLevel | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $SecurityArray = $SecurityLevel | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $SecurityArray.Count; $i++) {
                if ($SecurityArray[$i].state -ne $SecurityArray[$i + 1].state) {
                    if (($SecurityArray[$i].state -eq "NonCompliant") -or ($SecurityArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($SecurityArray[$i].state -eq "Error") -or ($SecurityArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($SecurityArray[$i].state -eq "Not Applicable") -or ($SecurityArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.SecurityLevel = $state
        }

        elseif (($SecurityLevel | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.SecurityLevel = ($SecurityLevel | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.SecurityLevel = "NotConfigured"
    }



    if ($WinOsVersion | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($WinOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $WinOSArray = $WinOsVersion | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $WinOSArray.Count; $i++) {
                if ($WinOSArray[$i].state -ne $WinOSArray[$i + 1].state) {
                    if (($WinOSArray[$i].state -eq "NonCompliant") -or ($WinOSArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($WinOSArray[$i].state -eq "Error") -or ($WinOSArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($WinOSArray[$i].state -eq "Not Applicable") -or ($WinOSArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.WinOsVersion = $state
        }

        elseif (($WinOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.WinOsVersion = ($WinOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.WinOsVersion = "NotConfigured"
    }


    if ($SimplePassword | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($SimplePassword | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $SimplePWArray = $SimplePassword | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $SimplePWArray.Count; $i++) {
                if ($SimplePWArray[$i].state -ne $SimplePWArray[$i + 1].state) {
                    if (($SimplePWArray[$i].state -eq "NonCompliant") -or ($SimplePWArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($SimplePWArray[$i].state -eq "Error") -or ($SimplePWArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($SimplePWArray[$i].state -eq "Not Applicable") -or ($SimplePWArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.SimplePassword = $state
        }

        elseif (($SimplePassword | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.SimplePassword = ($SimplePassword | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.SimplePassword = "NotConfigured"
    }



    if ($Password | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($Password | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $PWArray = $Password | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $PWArray.Count; $i++) {
                if ($PWArray[$i].state -ne $PWArray[$i + 1].state) {
                    if (($PWArray[$i].state -eq "NonCompliant") -or ($PWArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($PWArray[$i].state -eq "Error") -or ($PWArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($PWArray[$i].state -eq "Not Applicable") -or ($PWArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.Password = $state
        }

        elseif (($Password | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.Password = ($Password | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.Password = "NotConfigured"
    }

    if ($RTP | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($RTP | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $RTPArray = $RTP | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $RTPArray.Count; $i++) {
                if ($RTPArray[$i].state -ne $RTPArray[$i + 1].state) {
                    if (($RTPArray[$i].state -eq "NonCompliant") -or ($RTPArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($RTPArray[$i].state -eq "Error") -or ($RTPArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($RTPArray[$i].state -eq "Not Applicable") -or ($RTPArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.RealTimeProtection = $state
        }

        elseif (($RTP | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.RealTimeProtection = ($RTP | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.RealTimeProtection = "NotConfigured"
    }




    if ($SignatureOutOfDate | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($SignatureOutOfDate | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $SignatureArray = $SignatureOutOfDate | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $SignatureArray.Count; $i++) {
                if ($SignatureArray[$i].state -ne $SignatureArray[$i + 1].state) {
                    if (($SignatureArray[$i].state -eq "NonCompliant") -or ($SignatureArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($SignatureArray[$i].state -eq "Error") -or ($SignatureArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($SignatureArray[$i].state -eq "Not Applicable") -or ($SignatureArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.SignatureOutOfDate = $state
        }

        elseif (($SignatureOutOfDate | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.SignatureOutOfDate = ($SignatureOutOfDate | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.SignatureOutOfDate = "NotConfigured"
    }


    if ($Encryption | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($Encryption | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $EncryptionArray = $Encryption | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $EncryptionArray.Count; $i++) {
                if ($EncryptionArray[$i].state -ne $EncryptionArray[$i + 1].state) {
                    if (($EncryptionArray[$i].state -eq "NonCompliant") -or ($EncryptionArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($EncryptionArray[$i].state -eq "Error") -or ($EncryptionArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($EncryptionArray[$i].state -eq "Not Applicable") -or ($EncryptionArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.Encryption = $state
        }

        elseif (($Encryption | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.Encryption = ($Encryption | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.Encryption = "NotConfigured"
    }





    if ($TPM | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($TPM | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $TPMArray = $TPM | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $TPMArray.Count; $i++) {
                if ($TPMArray[$i].state -ne $TPMArray[$i + 1].state) {
                    if (($TPMArray[$i].state -eq "NonCompliant") -or ($TPMArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($TPMArray[$i].state -eq "Error") -or ($TPMArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($TPMArray[$i].state -eq "Not Applicable") -or ($TPMArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.TPM = $state
        }

        elseif (($TPM | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.TPM = ($TPM | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.TPM = "NotConfigured"
    }






    if ($SecureBoot | Where-Object { ($_.deviceid -eq $device.id) }) {
        If (($SecureBoot | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
            $SecureBootArray = $SecureBoot | Where-Object { ($_.deviceid -eq $device.id) }

            For ($i = 0; $i -lt $SecureBootArray.Count; $i++) {
                if ($SecureBootArray[$i].state -ne $SecureBootArray[$i + 1].state) {
                    if (($SecureBootArray[$i].state -eq "NonCompliant") -or ($SecureBootArray[$i + 1].state -eq "NonCompliant")) {
                        $state = "NonCompliant"
                    }
                    elseif (($SecureBootArray[$i].state -eq "Error") -or ($SecureBootArray[$i + 1].state -eq "Error")) {
                        $state = "Error"
                    }
                    
                    elseif (($SecureBootArray[$i].state -eq "Not Applicable") -or ($SecureBootArray[$i + 1].state -eq "Not Applicable")) {
                        $state = "NotApplicable"
                    }
                }
                else {
                    $state = "Compliant"
                }
            }
            $row.SecureBoot = $state
        }

        elseif (($SecureBoot | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
            $row.SecureBoot = ($SecureBoot | Where-Object { ($_.deviceid -eq $device.id) }).state
        }

    }

    else {
        $row.SecureBoot = "NotConfigured"
    }


    $table.Rows.Add($row) | Out-Null
}


$table | Select * -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors | Export-Excel $OutputFile -NoNumberConversion Mobile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -ConditionalText $(
    New-ConditionalText error white red
    New-ConditionalText -Text "noncompliant" -ConditionalTextColor black -BackgroundColor orangered -Range "G2:G50000"
    New-ConditionalText -Text "compliant" -ConditionalTextColor black -BackgroundColor lightgreen -Range "G2:G50000"
    New-ConditionalText -Text "unknown" -ConditionalTextColor black -BackgroundColor  cyan -Range "G2:G50000"
    New-ConditionalText nonCompliant black yellow
    New-ConditionalText compliant wheat green
    New-ConditionalText 'unknown' yellow black
    New-ConditionalText notApplicable white orange
    New-ConditionalText inGracePeriod white orange
    New-ConditionalText NotConfigured white blue  
)

$ptdefCompliance = New-PivotTableDefinition -PivotTableName "Compliance Overview" -PivotColumns "OverallCompliance" -PivotData @{"OverallCompliance" = "count" } -IncludePivotChart -ChartTitle "OverallCompliance Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefCompliance
 
$ptdefPolicy = New-PivotTableDefinition -PivotTableName "PolicyAssigned Overview" -PivotColumns "CompliancePolicyAssigned" -PivotData @{"CompliancePolicyAssigned" = "count" } -IncludePivotChart -ChartTitle "PolicyAssigned Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPolicy

$ptdefUserExistence = New-PivotTableDefinition -PivotTableName "UserExistence Overview" -PivotColumns "UserExistence" -PivotData @{"UserExistence" = "count" } -IncludePivotChart -ChartTitle "UserExistence Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefUserExistence

$ptdefIsActive = New-PivotTableDefinition -PivotTableName "IsActive Overview" -PivotColumns "IsActive" -PivotData @{"IsActive" = "count" } -IncludePivotChart -ChartTitle "IsActive Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefIsActive

$ptdefActiveFirewall = New-PivotTableDefinition -PivotTableName "ActiveFirewall Overview" -PivotColumns "ActiveFirewall" -PivotData @{"ActiveFirewall" = "count" } -IncludePivotChart -ChartTitle "ActiveFirewall Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefActiveFirewall

$ptdefAntiSpyware = New-PivotTableDefinition -PivotTableName "AntiSpyware Overview" -PivotColumns "AntiSpyware" -PivotData @{"AntiSpyware" = "count" } -IncludePivotChart -ChartTitle "AntiSpyware Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefAntiSpyware

$ptdefAntivirus = New-PivotTableDefinition -PivotTableName "Antivirus Overview" -PivotColumns "Antivirus" -PivotData @{"Antivirus" = "count" } -IncludePivotChart -ChartTitle "Antivirus Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefAntivirus

$ptdefBitlocker = New-PivotTableDefinition -PivotTableName "Bitlocker Overview" -PivotColumns "Bitlocker" -PivotData @{"Bitlocker" = "count" } -IncludePivotChart -ChartTitle "Bitlocker Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefBitlocker

$ptdefCodeIntegrity = New-PivotTableDefinition -PivotTableName "CodeIntegrity Overview" -PivotColumns "CodeIntegrity" -PivotData @{"CodeIntegrity" = "count" } -IncludePivotChart -ChartTitle "CodeIntegrity Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefCodeIntegrity

$ptdefMicrosoftDefender = New-PivotTableDefinition -PivotTableName "MicrosoftDefender Overview" -PivotColumns "MicrosoftDefender" -PivotData @{"MicrosoftDefender" = "count" } -IncludePivotChart -ChartTitle "MicrosoftDefender Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefMicrosoftDefender

$ptdefSecurityLevel = New-PivotTableDefinition -PivotTableName "SecurityLevel Overview" -PivotColumns "SecurityLevel" -PivotData @{"SecurityLevel" = "count" } -IncludePivotChart -ChartTitle "SecurityLevel Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile  -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefSecurityLevel

$ptdefWinOsVersion = New-PivotTableDefinition -PivotTableName "WinOsVersion Overview" -PivotColumns "WinOsVersion" -PivotData @{"WinOsVersion" = "count" } -IncludePivotChart -ChartTitle "WinOsVersion Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefWinOsVersion

$ptdefSimplePassword = New-PivotTableDefinition -PivotTableName "SimplePassword Overview" -PivotColumns "SimplePassword" -PivotData @{"SimplePassword" = "count" } -IncludePivotChart -ChartTitle "SimplePassword Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefSimplePassword

$ptdefPassword = New-PivotTableDefinition -PivotTableName "Password Overview" -PivotColumns "Password" -PivotData @{"Password" = "count" } -IncludePivotChart -ChartTitle "Password Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPassword

$ptdefRTP = New-PivotTableDefinition -PivotTableName "RealTimeProtection Overview" -PivotColumns "RealTimeProtection" -PivotData @{"RealTimeProtection" = "count" } -IncludePivotChart -ChartTitle "RealTimeProtection Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefRTP

$ptdefSignatureOutOfDate = New-PivotTableDefinition -PivotTableName "SignatureOutOfDate Overview" -PivotColumns "SignatureOutOfDate" -PivotData @{"SignatureOutOfDate" = "count" } -IncludePivotChart -ChartTitle "SignatureOutOfDate Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefSignatureOutOfDate

$ptdefEncryption = New-PivotTableDefinition -PivotTableName "Encryption Overview" -PivotColumns "Encryption" -PivotData @{"Encryption" = "count" } -IncludePivotChart -ChartTitle "Encryption Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefEncryption

$ptdefTPM = New-PivotTableDefinition -PivotTableName "TPM Overview" -PivotColumns "TPM" -PivotData @{"TPM" = "count" } -IncludePivotChart -ChartTitle "TPM Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefTPM

$ptdefSecureBoot = New-PivotTableDefinition -PivotTableName "SecureBoot Overview" -PivotColumns "SecureBoot" -PivotData @{"SecureBoot" = "count" } -IncludePivotChart -ChartTitle "SecureBoot Overview" -ChartType ColumnClustered -ChartColumn 6
Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefSecureBoot -Show

}

Function Get-AndroidCompliance {

    Function Get-ComplianceIsActive {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireRemainContact/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePolicyAssigned {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceUserExistence {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireUserExistence/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceOsVersion {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.OsMinimumVersion/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceInactivityLock {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.PasswordMinutesOfInactivityBeforeLock/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePasswordRequired {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.PasswordRequired/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePasswordType {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.PasswordRequiredType/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceCompanyPortalAppIntegrity {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.SecurityRequireCompanyPortalAppIntegrity/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceStorageEncryption {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/AndroidWorkProfileCompliancePolicy.StorageRequireEncryption/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    $CompanyName = $Connect.TenantDomain

    $date = Get-Date -Format "dd-MM-yy HH-mm-ss"

    $OutputFile = "C:\Skript\Reports\$CompanyName - Android Compliance Report - $date.xlsx"

    $Devices = Get-IntuneManagedDevice | Get-MSGraphAllPages | Where devicename -like "*AndroidForWork*"

    # Table Name
    $tabName = "Compliance Report"

    # Create Table object
    $table = New-Object system.Data.DataTable “$tabName”

    # User Info
    $table.columns.add("FullDisplayName") | Out-Null
    $table.columns.add("Email") | Out-Null

    # Device State
    $table.columns.add("ObjectID") | Out-Null
    $table.columns.add("DeviceName") | Out-Null
    $table.columns.add("Enrolled") | Out-Null
    $table.columns.add("LastSync") | Out-Null
    $table.columns.add("Jailbroken") | Out-Null
    $table.columns.add("OverallCompliance") | Out-Null

    # Compliance Settings
    $table.columns.add("CompliancePolicyAssigned") | Out-Null
    $table.columns.add("UserExistence") | Out-Null
    $table.columns.add("IsActive") | Out-Null
    $table.columns.add("AndroidOsVersion") | Out-Null
    $table.columns.add("InactivityLock") | Out-Null
    $table.columns.add("PasswordRequired") | Out-Null
    $table.columns.add("PasswordType") | Out-Null
    $table.columns.add("AppIntegrity") | Out-Null
    $table.columns.add("StorageEncryption") | Out-Null

    $isActive = Get-ComplianceIsActive | Get-MSGraphAllPages
    $policyAssigned = Get-CompliancePolicyAssigned | Get-MSGraphAllPages
    $userExistence = Get-ComplianceUserExistence | Get-MSGraphAllPages
    $AndroidOsVersion = Get-ComplianceOsVersion | Get-MSGraphAllPages
    $InactivityLock = Get-ComplianceInactivityLock | Get-MSGraphAllPages
    $PasswordRequired = Get-CompliancePasswordRequired | Get-MSGraphAllPages
    $PasswordType = Get-CompliancePasswordType | Get-MSGraphAllPages
    $AppIntegrity = Get-ComplianceCompanyPortalAppIntegrity | Get-MSGraphAllPages
    $StorageEncryption = Get-ComplianceStorageEncryption | Get-MSGraphAllPages


    $counter = 0

    Foreach ($Device in $Devices) {

        $counter++
        $counterString = $counter.ToString()
        $devicetoString = ($devices.Count).ToString()
        $operation = "$counterString/$devicetoString Devices"

        Write-Progress -Activity 'Processing Android Compliance' -CurrentOperation $operation -PercentComplete (($counter / $Devices.count) * 100)

        #Creating new row
        $row = $table.NewRow()

        # User Info
        $row.Email = $Device.userPrincipalName
        $row.FullDisplayName = $device.userDisplayName

        # Device State
        $row.ObjectID = $Device.id
        $row.DeviceName = $Device.deviceName
        $row.Enrolled = $Device.enrolledDateTime
        $row.LastSync = $Device.lastSyncDateTime
        $row.Jailbroken = $Device.jailBroken
        $row.OverallCompliance = $Device.complianceState

        if ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PolicyArray = $policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PolicyArray.Count; $i++) {
                    if ($PolicyArray[$i].state -ne $PolicyArray[$i + 1].state) {
                        if (($PolicyArray[$i].state -eq "NonCompliant") -or ($PolicyArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PolicyArray[$i].state -eq "Error") -or ($PolicyArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PolicyArray[$i].state -eq "Not Applicable") -or ($PolicyArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.CompliancePolicyAssigned = $state
            }

            elseif (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.CompliancePolicyAssigned = ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.CompliancePolicyAssigned = "NotConfigured"
        }



        if ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $UserArray = $userExistence | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $UserArray.Count; $i++) {
                    if ($UserArray[$i].state -ne $UserArray[$i + 1].state) {
                        if (($UserArray[$i].state -eq "NonCompliant") -or ($UserArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($UserArray[$i].state -eq "Error") -or ($UserArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($UserArray[$i].state -eq "Not Applicable") -or ($UserArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.UserExistence = $state
            }

            elseif (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.UserExistence = ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.UserExistence = "NotConfigured"
        }


        if ($isActive | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $isActiveArray = $isActive | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $isActiveArray.Count; $i++) {
                    if ($isActiveArray[$i].state -ne $isActiveArray[$i + 1].state) {
                        if (($isActiveArray[$i].state -eq "NonCompliant") -or ($isActiveArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($isActiveArray[$i].state -eq "Error") -or ($isActiveArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($isActiveArray[$i].state -eq "Not Applicable") -or ($isActiveArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.IsActive = $state
            }

            elseif (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.IsActive = ($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.IsActive = "NotConfigured"
        }

        if ($AndroidOsVersion | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($AndroidOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $AndroidOsVersionArray = $AndroidOsVersion | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $AndroidOsVersionArray.Count; $i++) {
                    if ($AndroidOsVersionArray[$i].state -ne $AndroidOsVersionArray[$i + 1].state) {
                        if (($AndroidOsVersionArray[$i].state -eq "NonCompliant") -or ($AndroidOsVersionArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($AndroidOsVersionArray[$i].state -eq "Error") -or ($AndroidOsVersionArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($AndroidOsVersionArray[$i].state -eq "Not Applicable") -or ($AndroidOsVersionArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.AndroidOsVersion = $state
            }

            elseif (($AndroidOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.AndroidOsVersion = ($AndroidOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.AndroidOsVersion = "NotConfigured"
        }


        if ($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $InactivityLockArray = $InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $InactivityLockArray.Count; $i++) {
                    if ($InactivityLockArray[$i].state -ne $InactivityLockArray[$i + 1].state) {
                        if (($InactivityLockArray[$i].state -eq "NonCompliant") -or ($InactivityLockArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($InactivityLockArray[$i].state -eq "Error") -or ($InactivityLockArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($InactivityLockArray[$i].state -eq "Not Applicable") -or ($InactivityLockArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.InactivityLock = $state
            }

            elseif (($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.InactivityLock = ($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.InactivityLock = "NotConfigured"
        }


        if ($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PasswordRequiredArray = $PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PasswordRequiredArray.Count; $i++) {
                    if ($PasswordRequiredArray[$i].state -ne $PasswordRequiredArray[$i + 1].state) {
                        if (($PasswordRequiredArray[$i].state -eq "NonCompliant") -or ($PasswordRequiredArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PasswordRequiredArray[$i].state -eq "Error") -or ($PasswordRequiredArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PasswordRequiredArray[$i].state -eq "Not Applicable") -or ($PasswordRequiredArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PasswordRequired = $state
            }

            elseif (($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PasswordRequired = ($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PasswordRequired = "NotConfigured"
        }


        if ($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PasswordTypeArray = $PasswordType | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PasswordTypeArray.Count; $i++) {
                    if ($PasswordTypeArray[$i].state -ne $PasswordTypeArray[$i + 1].state) {
                        if (($PasswordTypeArray[$i].state -eq "NonCompliant") -or ($PasswordTypeArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PasswordTypeArray[$i].state -eq "Error") -or ($PasswordTypeArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PasswordTypeArray[$i].state -eq "Not Applicable") -or ($PasswordTypeArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PasswordType = $state
            }

            elseif (($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PasswordType = ($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PasswordType = "NotConfigured"
        }


        if ($AppIntegrity | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($AppIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $AppIntegrityArray = $AppIntegrity | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $AppIntegrityArray.Count; $i++) {
                    if ($AppIntegrityArray[$i].state -ne $AppIntegrityArray[$i + 1].state) {
                        if (($AppIntegrityArray[$i].state -eq "NonCompliant") -or ($AppIntegrityArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($AppIntegrityArray[$i].state -eq "Error") -or ($AppIntegrityArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($AppIntegrityArray[$i].state -eq "Not Applicable") -or ($AppIntegrityArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.AppIntegrity = $state
            }

            elseif (($AppIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.AppIntegrity = ($AppIntegrity | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.AppIntegrity = "NotConfigured"
        }

        if ($StorageEncryption | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($StorageEncryption | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $StorageEncryptionArray = $StorageEncryption | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $StorageEncryptionArray.Count; $i++) {
                    if ($StorageEncryptionArray[$i].state -ne $StorageEncryptionArray[$i + 1].state) {
                        if (($StorageEncryptionArray[$i].state -eq "NonCompliant") -or ($StorageEncryptionArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($StorageEncryptionArray[$i].state -eq "Error") -or ($StorageEncryptionArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($StorageEncryptionArray[$i].state -eq "Not Applicable") -or ($StorageEncryptionArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.StorageEncryption = $state
            }

            elseif (($StorageEncryption | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.StorageEncryption = ($StorageEncryption | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.StorageEncryption = "NotConfigured"
        }

    $table.Rows.Add($row) | Out-Null

}

    $table | Select * -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors | Export-Excel $OutputFile -NoNumberConversion Mobile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -ConditionalText $(
        New-ConditionalText error white red
        New-ConditionalText -Text "noncompliant" -ConditionalTextColor black -BackgroundColor orangered -Range "H2:H50000"
        New-ConditionalText -Text "compliant" -ConditionalTextColor black -BackgroundColor lightgreen -Range "H2:H50000"
        New-ConditionalText -Text "unknown" -ConditionalTextColor black -BackgroundColor cyan -Range "H2:H50000"
        New-ConditionalText nonCompliant black yellow
        New-ConditionalText compliant wheat green
        New-ConditionalText 'unknown' yellow black
        New-ConditionalText notApplicable white orange
        New-ConditionalText inGracePeriod white orange
        New-ConditionalText NotConfigured white blue  
    )


    $ptdefCompliance = New-PivotTableDefinition -PivotTableName "Compliance Overview" -PivotColumns "OverallCompliance" -PivotData @{"OverallCompliance" = "count" } -IncludePivotChart -ChartTitle "OverallCompliance Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefCompliance
 
    $ptdefPolicy = New-PivotTableDefinition -PivotTableName "PolicyAssigned Overview" -PivotColumns "CompliancePolicyAssigned" -PivotData @{"CompliancePolicyAssigned" = "count" } -IncludePivotChart -ChartTitle "PolicyAssigned Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPolicy

    $ptdefUserExistence = New-PivotTableDefinition -PivotTableName "UserExistence Overview" -PivotColumns "UserExistence" -PivotData @{"UserExistence" = "count" } -IncludePivotChart -ChartTitle "UserExistence Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefUserExistence

    $ptdefIsActive = New-PivotTableDefinition -PivotTableName "IsActive Overview" -PivotColumns "IsActive" -PivotData @{"IsActive" = "count" } -IncludePivotChart -ChartTitle "IsActive Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefIsActive

    $ptdefAndroidOsVersion = New-PivotTableDefinition -PivotTableName "AndroidOsVersion Overview" -PivotColumns "AndroidOsVersion" -PivotData @{"AndroidOsVersion" = "count" } -IncludePivotChart -ChartTitle "AndroidOsVersion Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefAndroidOsVersion

    $ptdefInactivityLock = New-PivotTableDefinition -PivotTableName "InactivityLock Overview" -PivotColumns "InactivityLock" -PivotData @{"InactivityLock" = "count" } -IncludePivotChart -ChartTitle "InactivityLock Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefInactivityLock

    $ptdefPasswordRequired = New-PivotTableDefinition -PivotTableName "PasswordRequired Overview" -PivotColumns "PasswordRequired" -PivotData @{"PasswordRequired" = "count" } -IncludePivotChart -ChartTitle "PasswordRequired Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPasswordRequired

    $ptdefPasswordType = New-PivotTableDefinition -PivotTableName "PasswordType Overview" -PivotColumns "PasswordType" -PivotData @{"PasswordType" = "count" } -IncludePivotChart -ChartTitle "PasswordType Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPasswordType

    $ptdefAppIntegrity = New-PivotTableDefinition -PivotTableName "AppIntegrity Overview" -PivotColumns "AppIntegrity" -PivotData @{"AppIntegrity" = "count" } -IncludePivotChart -ChartTitle "AppIntegrity Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefAppIntegrity

    $ptdefStorageEncryption = New-PivotTableDefinition -PivotTableName "StorageEncryption Overview" -PivotColumns "StorageEncryption" -PivotData @{"StorageEncryption" = "count" } -IncludePivotChart -ChartTitle "StorageEncryption Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefStorageEncryption -Show

}


Function Get-iOSCompliance {

    Function Get-ComplianceIsActive {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireRemainContact/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePolicyAssigned {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceUserExistence {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireUserExistence/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceOsVersionBuild {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.OsMinimumBuildVersion/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceOsVersion {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.OsMinimumVersion/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePasswordLength {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodeMinimumLength/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceInactivityLock {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodeMinutesOfInactivityBeforeLock/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-ComplianceScreenTimeout {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodeMinutesOfInactivityBeforeScreenTimeout/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePreviousPasswordBlock {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodePreviousPasscodeBlockCount/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePasswordRequired {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodeRequired/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    Function Get-CompliancePasswordType {

        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicySettingStateSummaries/IOSCompliancePolicy.PasscodeRequiredType/deviceComplianceSettingStates"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method GET -Body $JSON -ContentType "application/json"
    }

    $CompanyName = $Connect.TenantDomain

    $date = Get-Date -Format "dd-MM-yy HH-mm-ss"

    $OutputFile = "C:\Skript\Reports\$CompanyName - iOS Compliance Report - $date.xlsx"

    $Devices = Get-IntuneManagedDevice | Get-MSGraphAllPages | Where operatingSystem -eq "iOS"

    # Table Name
    $tabName = "Compliance Report"

    # Create Table object
    $table = New-Object system.Data.DataTable “$tabName”

    # User Info
    $table.columns.add("FullDisplayName") | Out-Null
    $table.columns.add("Email") | Out-Null

    # Device State
    $table.columns.add("ObjectID") | Out-Null
    $table.columns.add("DeviceName") | Out-Null
    $table.columns.add("Enrolled") | Out-Null
    $table.columns.add("LastSync") | Out-Null
    $table.columns.add("Jailbroken") | Out-Null
    $table.columns.add("OverallCompliance") | Out-Null

    # Compliance Settings
    $table.columns.add("CompliancePolicyAssigned") | Out-Null
    $table.columns.add("UserExistence") | Out-Null
    $table.columns.add("IsActive") | Out-Null
    $table.columns.add("OsMinimumBuildVersion") | Out-Null
    $table.columns.add("OsMinimumVersion") | Out-Null
    $table.columns.add("PasswordMinimumLength") | Out-Null
    $table.columns.add("InactivityLock") | Out-Null
    $table.columns.add("ScreenTimeout") | Out-Null
    $table.columns.add("PreviousPasswordBlock") | Out-Null
    $table.columns.add("PasswordRequired") | Out-Null
    $table.columns.add("PasswordRequiredType") | Out-Null

    $isActive = Get-ComplianceIsActive | Get-MSGraphAllPages
    $policyAssigned = Get-CompliancePolicyAssigned | Get-MSGraphAllPages
    $userExistence = Get-ComplianceUserExistence | Get-MSGraphAllPages
    $iOSOsVersionBuild = Get-ComplianceOsVersionBuild | Get-MSGraphAllPages
    $iOSOsVersion = Get-ComplianceOsVersion | Get-MSGraphAllPages
    $PasswordLength = Get-CompliancePasswordLength | Get-MSGraphAllPages
    $PreviousPasswordBlock = Get-CompliancePreviousPasswordBlock | Get-MSGraphAllPages
    $PasswordRequired = Get-CompliancePasswordRequired | Get-MSGraphAllPages
    $PasswordType = Get-CompliancePasswordType | Get-MSGraphAllPages
    $InactivityLock = Get-ComplianceInactivityLock | Get-MSGraphAllPages
    $ScreenTimeout = Get-ComplianceScreenTimeout | Get-MSGraphAllPages

    $counter = 0

    Foreach ($Device in $Devices) {

        $counter++
        $counterString = $counter.ToString()
        $devicetoString = ($devices.Count).ToString()
        $operation = "$counterString/$devicetoString Devices"

        Write-Progress -Activity 'Processing iOS Compliance' -CurrentOperation $operation -PercentComplete (($counter / $Devices.count) * 100)

        #Creating new row
        $row = $table.NewRow()

        # User Info
        $row.Email = $Device.userPrincipalName
        $row.FullDisplayName = $device.userDisplayName

        # Device State
        $row.ObjectID = $Device.id
        $row.DeviceName = $Device.deviceName
        $row.Enrolled = $Device.enrolledDateTime
        $row.LastSync = $Device.lastSyncDateTime
        $row.Jailbroken = $Device.jailBroken
        $row.OverallCompliance = $Device.complianceState

        if ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PolicyArray = $policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PolicyArray.Count; $i++) {
                    if ($PolicyArray[$i].state -ne $PolicyArray[$i + 1].state) {
                        if (($PolicyArray[$i].state -eq "NonCompliant") -or ($PolicyArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PolicyArray[$i].state -eq "Error") -or ($PolicyArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PolicyArray[$i].state -eq "Not Applicable") -or ($PolicyArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.CompliancePolicyAssigned = $state
            }

            elseif (($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.CompliancePolicyAssigned = ($policyAssigned | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.CompliancePolicyAssigned = "NotConfigured"
        }



        if ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $UserArray = $userExistence | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $UserArray.Count; $i++) {
                    if ($UserArray[$i].state -ne $UserArray[$i + 1].state) {
                        if (($UserArray[$i].state -eq "NonCompliant") -or ($UserArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($UserArray[$i].state -eq "Error") -or ($UserArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($UserArray[$i].state -eq "Not Applicable") -or ($UserArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.UserExistence = $state
            }

            elseif (($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.UserExistence = ($userExistence | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.UserExistence = "NotConfigured"
        }


        if ($isActive | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $isActiveArray = $isActive | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $isActiveArray.Count; $i++) {
                    if ($isActiveArray[$i].state -ne $isActiveArray[$i + 1].state) {
                        if (($isActiveArray[$i].state -eq "NonCompliant") -or ($isActiveArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($isActiveArray[$i].state -eq "Error") -or ($isActiveArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($isActiveArray[$i].state -eq "Not Applicable") -or ($isActiveArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.IsActive = $state
            }

            elseif (($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.IsActive = ($isActive | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.IsActive = "NotConfigured"
        }

        if ($iOSOsVersionBuild | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($iOSOsVersionBuild | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $iOSOsVersionBuildArray = $iOSOsVersionBuild | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $iOSOsVersionBuildArray.Count; $i++) {
                    if ($iOSOsVersionBuildArray[$i].state -ne $iOSOsVersionBuildArray[$i + 1].state) {
                        if (($iOSOsVersionBuildArray[$i].state -eq "NonCompliant") -or ($iOSOsVersionBuildArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($iOSOsVersionBuildArray[$i].state -eq "Error") -or ($iOSOsVersionBuildArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($iOSOsVersionBuildArray[$i].state -eq "Not Applicable") -or ($iOSOsVersionBuildArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.OsMinimumBuildVersion = $state
            }

            elseif (($iOSOsVersionBuild | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.OsMinimumBuildVersion = ($iOSOsVersionBuild | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.OsMinimumBuildVersion = "NotConfigured"
        }

        if ($iOSOsVersion | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($iOSOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $iOSOsVersionArray = $iOSOsVersion | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $iOSOsVersionArray.Count; $i++) {
                    if ($iOSOsVersionArray[$i].state -ne $iOSOsVersionArray[$i + 1].state) {
                        if (($iOSOsVersionArray[$i].state -eq "NonCompliant") -or ($iOSOsVersionArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($iOSOsVersionArray[$i].state -eq "Error") -or ($iOSOsVersionArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($iOSOsVersionArray[$i].state -eq "Not Applicable") -or ($iOSOsVersionArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.OsMinimumVersion = $state
            }

            elseif (($iOSOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.OsMinimumVersion = ($iOSOsVersion | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.OsMinimumVersion = "NotConfigured"
        }


        if ($PasswordLength | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PasswordLength | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PasswordLengthArray = $PasswordLength | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PasswordLengthArray.Count; $i++) {
                    if ($PasswordLengthArray[$i].state -ne $PasswordLengthArray[$i + 1].state) {
                        if (($PasswordLengthArray[$i].state -eq "NonCompliant") -or ($PasswordLengthArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PasswordLengthArray[$i].state -eq "Error") -or ($PasswordLengthArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PasswordLengthArray[$i].state -eq "Not Applicable") -or ($PasswordLengthArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PasswordMinimumLength = $state
            }

            elseif (($PasswordLength | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PasswordMinimumLength = ($PasswordLength | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PasswordMinimumLength = "NotConfigured"
        }


        if ($PreviousPasswordBlock | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PreviousPasswordBlock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PreviousPasswordBlockArray = $PreviousPasswordBlock | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PreviousPasswordBlockArray.Count; $i++) {
                    if ($PreviousPasswordBlockArray[$i].state -ne $PreviousPasswordBlockArray[$i + 1].state) {
                        if (($PreviousPasswordBlockArray[$i].state -eq "NonCompliant") -or ($PreviousPasswordBlockArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PreviousPasswordBlockArray[$i].state -eq "Error") -or ($PreviousPasswordBlockArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PreviousPasswordBlockArray[$i].state -eq "Not Applicable") -or ($PreviousPasswordBlockArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PreviousPasswordBlock = $state
            }

            elseif (($PreviousPasswordBlock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PreviousPasswordBlock = ($PreviousPasswordBlock | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PreviousPasswordBlock = "NotConfigured"
        }


        if ($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PasswordRequiredArray = $PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PasswordRequiredArray.Count; $i++) {
                    if ($PasswordRequiredArray[$i].state -ne $PasswordRequiredArray[$i + 1].state) {
                        if (($PasswordRequiredArray[$i].state -eq "NonCompliant") -or ($PasswordRequiredArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PasswordRequiredArray[$i].state -eq "Error") -or ($PasswordRequiredArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PasswordRequiredArray[$i].state -eq "Not Applicable") -or ($PasswordRequiredArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PasswordRequired = $state
            }

            elseif (($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PasswordRequired = ($PasswordRequired | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PasswordRequired = "NotConfigured"
        }


        if ($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $PasswordTypeArray = $PasswordType | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $PasswordTypeArray.Count; $i++) {
                    if ($PasswordTypeArray[$i].state -ne $PasswordTypeArray[$i + 1].state) {
                        if (($PasswordTypeArray[$i].state -eq "NonCompliant") -or ($PasswordTypeArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($PasswordTypeArray[$i].state -eq "Error") -or ($PasswordTypeArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($PasswordTypeArray[$i].state -eq "Not Applicable") -or ($PasswordTypeArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.PasswordRequiredType = $state
            }

            elseif (($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.PasswordRequiredType = ($PasswordType | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.PasswordRequiredType = "NotConfigured"
        }


        if ($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $InactivityLockArray = $InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $InactivityLockArray.Count; $i++) {
                    if ($InactivityLockArray[$i].state -ne $InactivityLockArray[$i + 1].state) {
                        if (($InactivityLockArray[$i].state -eq "NonCompliant") -or ($InactivityLockArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($InactivityLockArray[$i].state -eq "Error") -or ($InactivityLockArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($InactivityLockArray[$i].state -eq "Not Applicable") -or ($InactivityLockArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.InactivityLock = $state
            }

            elseif (($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.InactivityLock = ($InactivityLock | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.InactivityLock = "NotConfigured"
        }

        if ($ScreenTimeout | Where-Object { ($_.deviceid -eq $device.id) }) {
            If (($ScreenTimeout | Where-Object { ($_.deviceid -eq $device.id) }).state.count -gt 1) {
                $ScreenTimeoutArray = $ScreenTimeout | Where-Object { ($_.deviceid -eq $device.id) }

                For ($i = 0; $i -lt $ScreenTimeoutArray.Count; $i++) {
                    if ($ScreenTimeoutArray[$i].state -ne $ScreenTimeoutArray[$i + 1].state) {
                        if (($ScreenTimeoutArray[$i].state -eq "NonCompliant") -or ($ScreenTimeoutArray[$i + 1].state -eq "NonCompliant")) {
                            $state = "NonCompliant"
                        }
                        elseif (($ScreenTimeoutArray[$i].state -eq "Error") -or ($ScreenTimeoutArray[$i + 1].state -eq "Error")) {
                            $state = "Error"
                        }
                    
                        elseif (($ScreenTimeoutArray[$i].state -eq "Not Applicable") -or ($ScreenTimeoutArray[$i + 1].state -eq "Not Applicable")) {
                            $state = "NotApplicable"
                        }
                    }
                    else {
                        $state = "Compliant"
                    }
                }
                $row.ScreenTimeout = $state
            }

            elseif (($ScreenTimeout | Where-Object { ($_.deviceid -eq $device.id) }).state.count -eq 1) {
                $row.ScreenTimeout = ($ScreenTimeout | Where-Object { ($_.deviceid -eq $device.id) }).state
            }

        }

        else {
            $row.ScreenTimeout = "NotConfigured"
        }


    $table.Rows.Add($row) | Out-Null

}

    $table | Select * -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors | Export-Excel $OutputFile -NoNumberConversion Mobile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -ConditionalText $(
        New-ConditionalText error white red
        New-ConditionalText -Text "noncompliant" -ConditionalTextColor black -BackgroundColor orangered -Range "H2:H50000"
        New-ConditionalText -Text "compliant" -ConditionalTextColor black -BackgroundColor lightgreen -Range "H2:H50000"
        New-ConditionalText -Text "unknown" -ConditionalTextColor black -BackgroundColor cyan -Range "H2:H50000"
        New-ConditionalText nonCompliant black yellow
        New-ConditionalText compliant wheat green
        New-ConditionalText 'unknown' yellow black
        New-ConditionalText notApplicable white orange
        New-ConditionalText inGracePeriod white orange
        New-ConditionalText NotConfigured white blue  
    )


    $ptdefCompliance = New-PivotTableDefinition -PivotTableName "Compliance Overview" -PivotColumns "OverallCompliance" -PivotData @{"OverallCompliance" = "count" } -IncludePivotChart -ChartTitle "OverallCompliance Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefCompliance
 
    $ptdefPolicy = New-PivotTableDefinition -PivotTableName "PolicyAssigned Overview" -PivotColumns "CompliancePolicyAssigned" -PivotData @{"CompliancePolicyAssigned" = "count" } -IncludePivotChart -ChartTitle "PolicyAssigned Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPolicy

    $ptdefUserExistence = New-PivotTableDefinition -PivotTableName "UserExistence Overview" -PivotColumns "UserExistence" -PivotData @{"UserExistence" = "count" } -IncludePivotChart -ChartTitle "UserExistence Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefUserExistence

    $ptdefIsActive = New-PivotTableDefinition -PivotTableName "IsActive Overview" -PivotColumns "IsActive" -PivotData @{"IsActive" = "count" } -IncludePivotChart -ChartTitle "IsActive Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefIsActive

    $ptdefiOSOsVersionBuild = New-PivotTableDefinition -PivotTableName "OsMinimumBuildVersion Overview" -PivotColumns "OsMinimumBuildVersion" -PivotData @{"OsMinimumBuildVersion" = "count" } -IncludePivotChart -ChartTitle "OsMinimumBuildVersion Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefiOSOsVersionBuild

    $ptdefiOSOsVersion = New-PivotTableDefinition -PivotTableName "OsMinimumVersion Overview" -PivotColumns "OsMinimumVersion" -PivotData @{"OsMinimumVersion" = "count" } -IncludePivotChart -ChartTitle "OsMinimumVersion Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefiOSOsVersion

    $ptdefPasswordRequired = New-PivotTableDefinition -PivotTableName "PasswordRequired Overview" -PivotColumns "PasswordRequired" -PivotData @{"PasswordRequired" = "count" } -IncludePivotChart -ChartTitle "PasswordRequired Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPasswordRequired

    $ptdefPasswordType = New-PivotTableDefinition -PivotTableName "PasswordRequiredType Overview" -PivotColumns "PasswordRequiredType" -PivotData @{"PasswordRequiredType" = "count" } -IncludePivotChart -ChartTitle "PasswordRequiredType Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPasswordType

    $ptdefPasswordMinimumLength = New-PivotTableDefinition -PivotTableName "PasswordMinimumLength Overview" -PivotColumns "PasswordMinimumLength" -PivotData @{"PasswordMinimumLength" = "count" } -IncludePivotChart -ChartTitle "PasswordMinimumLength Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPasswordMinimumLength

    $ptdefPreviousPasswordBlock = New-PivotTableDefinition -PivotTableName "PreviousPasswordBlock Overview" -PivotColumns "PreviousPasswordBlock" -PivotData @{"PreviousPasswordBlock" = "count" } -IncludePivotChart -ChartTitle "PreviousPasswordBlock Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefPreviousPasswordBlock

    $ptdefInactivityLock = New-PivotTableDefinition -PivotTableName "InactivityLock Overview" -PivotColumns "InactivityLock" -PivotData @{"InactivityLock" = "count" } -IncludePivotChart -ChartTitle "InactivityLock Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefInactivityLock

    $ptdefScreenTimeout = New-PivotTableDefinition -PivotTableName "ScreenTimeout Overview" -PivotColumns "ScreenTimeout" -PivotData @{"ScreenTimeout" = "count" } -IncludePivotChart -ChartTitle "ScreenTimeout Overview" -ChartType ColumnClustered -ChartColumn 6
    Export-Excel $OutputFile -AutoSize -AutoFilter -FreezeTopRow -TitleBold -WorksheetName "Compliance Information" -PivotTableDefinition $ptdefScreenTimeout -Show

}


#Creating dropdown menu with a choice between the different operating systems
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PowerShell Repository'
$form.Size = New-Object System.Drawing.Size(300, 500)
$form.Font = New-Object System.Drawing.Font("Calibri",13,[System.Drawing.FontStyle]::Regular)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75, 400)
$okButton.Size = New-Object System.Drawing.Size(75, 23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton 
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150, 400)
$cancelButton.Size = New-Object System.Drawing.Size(75, 23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 15)
$label.Size = New-Object System.Drawing.Size(280, 20)
$label.Font = New-Object System.Drawing.Font("Calibri",13,[System.Drawing.FontStyle]::Regular)
$label.Text = 'Choose operating system:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.CheckedListBox
$listBox.Location = New-Object System.Drawing.Point(10, 40)
$listBox.Size = New-Object System.Drawing.Size(260, 40)
$listBox.Height = 350
$listBox.Font = New-Object System.Drawing.Font("Calibri",13,[System.Drawing.FontStyle]::Regular)
$listBox.CheckOnClick=$true
$listBox.DisplayMember='Caption'

#Darkmode colors
$form.BackColor = "DarkSlateGray"
$label.ForeColor = "WhiteSmoke"
$listBox.ForeColor = "WhiteSmoke"
$listBox.BackColor = "DarkSlateGray"
$cancelButton.ForeColor = "WhiteSmoke"
$okButton.ForeColor = "WhiteSmoke"

[void] $listBox.Items.Add('Windows')
[void] $listBox.Items.Add('Android')
[void] $listBox.Items.Add('iOS')

$form.Controls.Add($listBox)

$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $x = $listBox.CheckedItems

    #Connecting to customer tenant and checking token
    $Connect = Connect-AzureAD
    $User = $Connect.Account

    Connect-MSGraph

    Test-AuthToken
}

if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
    Exit
}

if ("Windows" -in $x) {
    Get-WindowsCompliance
}

if ("Android" -in $x) {
    Get-AndroidCompliance
}

if ("iOS" -in $x) {
    Get-iOSCompliance
}



