# ------------------------------------------------------------
# Logging / Transcript Setup
# ------------------------------------------------------------
$LogFolder = Join-Path -Path $PSScriptRoot -ChildPath "Logs"

if (-not (Test-Path -Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

$TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = Join-Path -Path $LogFolder -ChildPath "KnowBe4_Setup_$TimeStamp.log"

Start-Transcript -Path $LogFile -Append

try {
    # ------------------------------------------------------------
    # Input Function with Confirmation
    # ------------------------------------------------------------
    function Get-KnowBe4Input {
        do {
            $ScimSecretToken = Read-Host "Please insert the SCIM Secret Token"
            $TenantID = Read-Host "Please insert your Entra Tenant ID"
            $SAMLID = Read-Host "Please insert your SAML ID"

            Write-Host "`nPlease confirm the details:"
            Write-Host "Entra ID Tenant ID: $TenantID"
            Write-Host "KnowBe4 SAML ID: $SAMLID"
            Write-Host "SCIM Secret Token: $ScimSecretToken"

            $confirmation = Read-Host "Are these details correct? (Y/N)"
        } while ($confirmation -notin @("Y","y"))

        return @{
            ScimSecretToken = $ScimSecretToken
            TenantID        = $TenantID
            SAMLID          = $SAMLID
        }
    }

    # ------------------------------------------------------------
    # Collect Inputs
    # ------------------------------------------------------------
    $userInput = Get-KnowBe4Input

    $ScimSecretToken = $userInput.ScimSecretToken
    $TenantID        = $userInput.TenantID
    $SAMLID          = $userInput.SAMLID

    $ScimTenantUrl = "https://eu.scim.knowbe4.com/v2"
    $SAMLUrl = "https://eu.knowbe4.com/auth/saml/$SAMLID"

    $NameIdSource = "userprincipalname"
    
    Write-Host "Transcript log: $LogFile"

    # ------------------------------------------------------------
    # Module Checks
    # ------------------------------------------------------------
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }

    Import-Module Microsoft.Graph.Applications
    Import-Module Microsoft.Graph.Groups
    Import-Module Microsoft.Graph.Identity.SignIns

    Write-Host "Step 1: Connecting to Exchange Online"
    Connect-ExchangeOnline -Organization $TenantID

    # ------------------------------------------------------------
    # Mail Whitelisting
    # ------------------------------------------------------------
    $ruleName = "Check Point - Protect"
    $rule = Get-TransportRule -Identity $ruleName -ErrorAction SilentlyContinue

    if ($rule) {
        $header = Get-TransportRule -Identity $ruleName | Select-Object -ExpandProperty SetHeaderValue
        New-TransportRule -Name "KnowBe4 Whitelisting" -SenderIpRanges "147.160.167.0/26","23.21.109.197","23.21.109.212","52.49.201.246","52.49.235.189" -SetHeaderName "X-CLOUD-SEC-AV-Info" -SetHeaderValue "$header" -Priority 0 -StopRuleProcessing $true
    } else {
        New-TransportRule -Name "KnowBe4 Whitelisting" -SenderIpRanges "147.160.167.0/26","23.21.109.197","23.21.109.212","52.49.201.246","52.49.235.189" -Priority 0 -StopRuleProcessing $true
    }

    # ------------------------------------------------------------
    # PhishSim Override
    # ------------------------------------------------------------
    $policy = Get-PhishSimOverridePolicy

    if ($policy -ne $null) {
        Write-Output "PhishSimOverridePolicy exists. Executing commands..."
        $PhishSimRule = Get-ExoPhishSimOverrideRule -Policy $policy.Identity
        Set-ExoPhishSimOverrideRule -Identity $PhishSimRule -AddDomains "psm.knowbe4.com" -AddSenderIpRanges "147.160.167.0/26", "23.21.109.197", "23.21.109.212", "52.49.201.246", "52.49.235.189"
    } else {
        Write-Output "PhishSimOverridePolicy does not exist. Executing alternative commands..."
        New-PhishSimOverridePolicy -Name PhishSimOverridePolicy
        New-ExoPhishSimOverrideRule -Name "KnowBe4 Overrides" -Policy PhishSimOverridePolicy -Domains "psm.knowbe4.com" -SenderIpRanges "147.160.167.0/26", "23.21.109.197", "23.21.109.212", "52.49.201.246", "52.49.235.189"
    }
    
    Write-Host "Step 2: Disconnecting Exchange Online"
    Disconnect-ExchangeOnline -Confirm:$false

    # ------------------------------------------------------------
    # Connect Graph
    # ------------------------------------------------------------
    Write-Host "Step 3: Connecting to Microsoft Graph"
    Connect-MgGraph -TenantId $TenantID -Scopes `
    "Application.ReadWrite.All", `
    "Directory.ReadWrite.All", `
    "Group.ReadWrite.All", `
    "AppRoleAssignment.ReadWrite.All", `
    "Policy.Read.All", `
    "Policy.ReadWrite.ApplicationConfiguration", `
    "Synchronization.ReadWrite.All" `
    -NoWelcome

    # ------------------------------------------------------------
    # App Creation
    # ------------------------------------------------------------
    $templateId = "47e7ec33-5716-44a2-972b-cd0de38f8352"
    $appDisplayName = "KnowBe4 Security Awareness Training"

    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applicationTemplates/$templateId/instantiate" -Body @{
        displayName = $appDisplayName
    }

    Start-Sleep -Seconds 20

    $appId = (Get-MgApplication | Where-Object { $_.DisplayName -eq $appDisplayName } | Select-Object -First 1 -ExpandProperty Id)

    if (-not $appId) {
        throw "Failed to locate application ID for $appDisplayName"
    }

    # ------------------------------------------------------------
    # Group Creation
    # ------------------------------------------------------------
    $groupName = $appDisplayName
    $groupDescription = $appDisplayName
    $mailNickname = "DynamicSec"
    $membershipRule = '((user.accountEnabled -eq true) and (user.assignedPlans -any assignedPlan.servicePlanId -eq "9aaf7827-d63c-4b61-89c3-182f06f82e5c" -and assignedPlan.capabilityStatus -eq "Enabled") and (user.surname -ne null)) or ((user.accountEnabled -eq true) and (user.assignedPlans -any assignedPlan.servicePlanId -eq "efb87545-963c-4e0d-99df-69c6916d9eb0" -and assignedPlan.capabilityStatus -eq "Enabled") and (user.surname -ne null))'

    $group = Get-MgGroup -Filter "displayName eq '$groupName'" | Select-Object -First 1

    if (-not $group) {
        New-MgGroup -DisplayName $groupName `
            -Description $groupDescription `
            -MailEnabled:$false `
            -MailNickname $mailNickname `
            -SecurityEnabled:$true `
            -GroupTypes "DynamicMembership" `
            -MembershipRule $membershipRule `
            -MembershipRuleProcessingState "On"

        Start-Sleep -Seconds 20
    }

    $servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$appDisplayName'" | Select-Object -First 1
    $group = Get-MgGroup -Filter "displayName eq '$groupName'" | Select-Object -First 1

    if (-not $servicePrincipal) {
        throw "Service principal not found for $appDisplayName"
    }

    if (-not $group) {
        throw "Group not found: $groupName"
    }

    # ------------------------------------------------------------
    # Assign Group
    # ------------------------------------------------------------
    $roleId = ($servicePrincipal.AppRoles | Where-Object { $_.DisplayName -eq "user" } | Select-Object -First 1 -ExpandProperty Id)

    if (-not $roleId) {
        throw "App role 'user' not found on service principal"
    }

    $existingAssignment = Get-MgGroupAppRoleAssignment -GroupId $group.Id -All | Where-Object {
        $_.ResourceId -eq $servicePrincipal.Id -and $_.AppRoleId -eq $roleId
    } | Select-Object -First 1

    if (-not $existingAssignment) {
        New-MgGroupAppRoleAssignment -GroupId $group.Id -BodyParameter @{
            principalId = $group.Id
            resourceId  = $servicePrincipal.Id
            appRoleId   = $roleId
        }
    }

    # ------------------------------------------------------------
    # SAML Config
    # ------------------------------------------------------------

    # 1) Mark the enterprise app as SAML first
    Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -BodyParameter @{
        PreferredSingleSignOnMode = "saml"
    }

    Start-Sleep -Seconds 5

    # 2) Now update the app object with the SAML values
    Update-MgApplication -ApplicationId $appId -BodyParameter @{
        IdentifierUris = @("KnowBe4")
        Web = @{
            RedirectUris = @("$SAMLUrl/callback")
            LogoutUrl    = "$SAMLUrl/logout"
        }
    }

    # 3) Then set the remaining SP-side SAML values
    Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -BodyParameter @{
        LoginUrl  = "$SAMLUrl"
        LogoutUrl = "$SAMLUrl/logout"
    }

    # ------------------------------------------------------------
    # SAML Signing Certificate
    # ------------------------------------------------------------
    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id

    if (-not $servicePrincipal.PreferredTokenSigningKeyThumbprint) {
        $cert = Add-MgServicePrincipalTokenSigningCertificate `
            -ServicePrincipalId $servicePrincipal.Id `
            -BodyParameter @{
                displayName = "CN=KnowBe4SAML"
            }

        if (-not $cert -or -not $cert.Thumbprint) {
            throw "Token signing certificate was not created successfully."
        }

        Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -BodyParameter @{
            preferredTokenSigningKeyThumbprint = $cert.Thumbprint
        }

        $activeThumbprint = $cert.Thumbprint
    }
    else {
        $activeThumbprint = $servicePrincipal.PreferredTokenSigningKeyThumbprint
    }

    # ------------------------------------------------------------
    # SAML Claims
    # ------------------------------------------------------------
    $claimsDefinition = @"
{
 "ClaimsMappingPolicy": {
  "Version": 1,
  "IncludeBasicClaimSet": "false",
  "ClaimsSchema": [
   {
    "Source": "user",
    "ID": "$NameIdSource",
    "SamlClaimType": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
   }
  ]
 }
}
"@

    $policy = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies" `
        -Body (@{
            definition  = @($claimsDefinition)
            displayName = "KnowBe4-Claims"
        } | ConvertTo-Json -Depth 10) `
        -ContentType "application/json"

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.Id)/claimsMappingPolicies/`$ref" `
        -Body (@{
            "@odata.id" = "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$($policy.id)"
        } | ConvertTo-Json) `
        -ContentType "application/json"

    # ------------------------------------------------------------
    # SCIM Provisioning
    # ------------------------------------------------------------
    $job = Get-MgServicePrincipalSynchronizationJob -ServicePrincipalId $servicePrincipal.Id -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $job) {
        $template = (Get-MgServicePrincipalSynchronizationTemplate -ServicePrincipalId $servicePrincipal.Id | Select-Object -First 1)
        $job = New-MgServicePrincipalSynchronizationJob -ServicePrincipalId $servicePrincipal.Id -TemplateId $template.Id
    }

    Set-MgServicePrincipalSynchronizationSecret -ServicePrincipalId $servicePrincipal.Id -BodyParameter @{
        value = @(
            @{ key = "BaseAddress"; value = $ScimTenantUrl },
            @{ key = "SecretToken"; value = $ScimSecretToken },
            @{ key = "SyncAll"; value = "false" }
        )
    }

    Start-MgServicePrincipalSynchronizationJob -ServicePrincipalId $servicePrincipal.Id -SynchronizationJobId $job.Id

    Write-Host "SCIM Provisioning configured and started."
    Write-Host "Script completed successfully."
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    throw
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Host "Record the following values to add into KnowBe4 Console"
    Write-Host "Certificate Thumbprint (SHA256): $activeThumbprint"
    Write-Host "IdP SSO Target URL: https://login.microsoftonline.com/$TenantID/saml2"
    Stop-Transcript | Out-Null
}