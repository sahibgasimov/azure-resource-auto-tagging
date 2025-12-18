<# 
.SYNOPSIS
    Auto-tag Azure resources and resource groups with creation and modification metadata by analyzing Azure Activity Logs.
    
.DESCRIPTION
    This script tags resources with CreatedBy, Created-Date, LastModifiedBy, and LastModifiedDate tags.
    
    To  distinguish between resource creation and modification events, this script:
    1. Attempts to get the resource's actual creation time from Azure Resource Manager API or Azure Resource Graph
    2. Compares the first write event timestamp with the resource's creation time
    3. Only tags as "creation" if the first write event matches the resource creation time (within a configurable window)
    4. For resources without creation time info, uses conservative heuristics (only tags very recent resources with single write events)
    
    This prevents incorrectly tagging old resources when they are modified (e.g., adding a subnet to an existing VNet).
    
.NOTES
    - Requires Az.Accounts, Az.Resources modules (Az.ResourceGraph is optional but recommended)
    - Activity Logs only retain 90 days of data
    - Resources older than 90 days may not have creation events available
    - IMPORTANT: The automation account's managed identity needs Directory.Read.All permission in Microsoft Graph
      to resolve service principal Object IDs to display names
#>

<# Ensures you do not inherit an AzContext in your runbook #>
Disable-AzContextAutosave -Scope Process | Out-Null;
#Toggle to stop warnings with regard to Breaking Changes in Azure PowerShell
Set-Item -Path Env:\SuppressAzurePowerShellBreakingChangeWarnings -Value $true

Import-Module Az.Accounts
Import-Module Az.Resources
# Az.ResourceGraph is imported conditionally in Get-ResourceCreationTime function if available

# ============================================
# CONFIGURATION - Update these as needed
# ============================================

# Define the tag names as variables
$createdByTagName = "CreatedBy"
$dateCreatedTagName = "CreationDate"
$lastModifiedByTagName = "LastModifiedBy"
$lastModifiedDateTagName = "LastModifiedDate"

# Subscription IDs - the subscriptions that the script will run against
# Can be a single subscription ID (string) or multiple subscription IDs (array)
$SubscriptionIDs = @(
    'subscription-id-1'
    'subscription-id-2'  
    # '11111111-1111-1111-1111-111111111111'  # Add more subscription IDs as needed
)

# Maximum age (in days) for creation events - resources older than this will be skipped
$MaxCreationAgeDays = 30

# Time window (in minutes) to match first write event with resource creation time
$CreationTimeMatchWindowMinutes = 10

# Heuristic window (in days) for identifying creation events when resource creation time is not available
$HeuristicCreationWindowDays = 14

# Additional identities to exclude from LastModified tracking (automation accounts, service principals, etc.)
$ExcludedIdentities = @(
    # Examples (remove or replace with your actual values):
    # "myapp-service-principal@tenant.com"
    ""  # Automation account managed identity object ID (manually specified)
)

# ============================================
# END CONFIGURATION
# ============================================

# Initialize script-level variable for automation identity
$script:automationIdentity = $null
$script:automationIdentityObjectId = $null
$script:excludedIdentitiesList = $ExcludedIdentities

# Connect using a Managed Service Identity
try {
    $connection = Connect-AzAccount -Identity -ErrorAction Stop
    Write-Output "Successfully connected using Managed Identity"
    
    # Get the automation account's identity information to exclude from LastModified tracking
    $context = Get-AzContext
    $script:automationIdentity = $context.Account.Id
    Write-Output "Automation Identity (Account.Id): $script:automationIdentity"
    
    # Also try to get the managed identity's object ID (principal ID) which might appear differently in activity logs
    try {
        # Try to get the automation account's managed identity object ID from the resource itself
        $subscriptionId = $context.Subscription.Id
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        
        foreach ($aa in $automationAccounts) {
            if ([string]::IsNullOrEmpty($aa.Id)) {
                continue
            }
            $aaResource = Get-AzResource -ResourceId $aa.Id -ErrorAction SilentlyContinue
            if ($null -ne $aaResource -and $null -ne $aaResource.Identity) {
                if ($null -ne $aaResource.Identity.PrincipalId) {
                    $script:automationIdentityObjectId = $aaResource.Identity.PrincipalId
                    Write-Output "Automation Identity Object ID (from resource): $script:automationIdentityObjectId"
                    
                    if ($script:excludedIdentitiesList -notcontains $script:automationIdentityObjectId) {
                        $script:excludedIdentitiesList += $script:automationIdentityObjectId
                        Write-Output "Added automation identity object ID to exclusion list"
                    }
                    break
                }
                if ($null -ne $aaResource.Identity.UserAssignedIdentities) {
                    foreach ($userIdentity in $aaResource.Identity.UserAssignedIdentities.PSObject.Properties) {
                        if ($null -ne $userIdentity.Value.PrincipalId) {
                            $script:automationIdentityObjectId = $userIdentity.Value.PrincipalId
                            Write-Output "Automation Identity Object ID (user-assigned): $script:automationIdentityObjectId"
                            
                            if ($script:excludedIdentitiesList -notcontains $script:automationIdentityObjectId) {
                                $script:excludedIdentitiesList += $script:automationIdentityObjectId
                                Write-Output "Added automation identity object ID to exclusion list"
                            }
                            break
                        }
                    }
                }
            }
        }
        
        if ([string]::IsNullOrEmpty($script:automationIdentityObjectId)) {
            try {
                Import-Module Az.Accounts -ErrorAction SilentlyContinue
                Import-Module Az.Resources -ErrorAction SilentlyContinue
                $sp = Get-AzADServicePrincipal -Filter "servicePrincipalNames/any(x:x eq '$($context.Account.Id)')" -ErrorAction SilentlyContinue
                if ($null -ne $sp -and $null -ne $sp.Id) {
                    $script:automationIdentityObjectId = $sp.Id
                    Write-Output "Automation Identity Object ID (from service principal): $script:automationIdentityObjectId"
                    
                    if ($script:excludedIdentitiesList -notcontains $script:automationIdentityObjectId) {
                        $script:excludedIdentitiesList += $script:automationIdentityObjectId
                        Write-Output "Added automation identity object ID to exclusion list"
                    }
                }
            } catch {
                Write-Warning "Could not retrieve service principal: $_"
            }
        }
        
        if ([string]::IsNullOrEmpty($script:automationIdentityObjectId)) {
            foreach ($excludedId in $ExcludedIdentities) {
                if ($excludedId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                    $script:automationIdentityObjectId = $excludedId
                    Write-Output "Using manually specified automation identity object ID: $script:automationIdentityObjectId"
                    break
                }
            }
        }
        
        Write-Output "Final excluded identities list: $($script:excludedIdentitiesList -join ', ')"
        Write-Output "Automation identity object ID: $script:automationIdentityObjectId"
    } catch {
        Write-Warning "Could not retrieve automation identity object ID: $_"
    }
}
catch {
    Write-Error "Failed to connect: $_"
    throw
}

# Helper function to check if tag exists (case-insensitive)
function Test-TagExists {
    param(
        [hashtable]$Tags,
        [string]$TagName
    )
    
    if ($null -eq $Tags -or $Tags.Count -eq 0) {
        return $false
    }
    
    foreach ($key in $Tags.Keys) {
        if ($key -ieq $TagName) {
            return $true
        }
    }
    
    return $false
}

# Helper function to check if an identity should be excluded
function Test-IsExcludedIdentity {
    param(
        [string]$Caller
    )
    
    if ([string]::IsNullOrEmpty($Caller)) {
        return $false
    }
    
    $callerLower = $Caller.ToLower()
    
    if (-not [string]::IsNullOrEmpty($script:automationIdentity)) {
        $automationIdentityLower = $script:automationIdentity.ToLower()
        if ($callerLower -eq $automationIdentityLower) {
            return $true
        }
        if ($callerLower -like "*$automationIdentityLower*") {
            return $true
        }
        if ($script:automationIdentity -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            if ($callerLower -eq $automationIdentityLower) {
                return $true
            }
        }
    }
    
    if (-not [string]::IsNullOrEmpty($script:automationIdentityObjectId)) {
        $objectIdLower = $script:automationIdentityObjectId.ToLower()
        if ($callerLower -eq $objectIdLower) {
            return $true
        }
        if ($callerLower -like "*$objectIdLower*") {
            return $true
        }
    }
    
    foreach ($excludedId in $script:excludedIdentitiesList) {
        if (-not [string]::IsNullOrEmpty($excludedId)) {
            $excludedIdLower = $excludedId.ToLower()
            if ($callerLower -eq $excludedIdLower) {
                return $true
            }
            if ($callerLower -like "*$excludedIdLower*") {
                return $true
            }
        }
    }
    
    return $false
}

# Helper function to resolve Object ID (GUID) to display name
# This requires the managed identity to have Directory.Read.All permission in Microsoft Graph
function Get-DisplayNameFromObjectId {
    param(
        [string]$ObjectId
    )
    
    # If it's already an email or doesn't look like a GUID, return as-is
    if ($ObjectId -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
        return $ObjectId
    }
    
    # Check if it's a GUID format
    if ($ObjectId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        try {
            # Try to get service principal first (most common for automation)
            $sp = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction SilentlyContinue
            if ($null -ne $sp -and -not [string]::IsNullOrEmpty($sp.DisplayName)) {
                Write-Verbose "Resolved Object ID $ObjectId to Service Principal: $($sp.DisplayName)" -Verbose
                return $sp.DisplayName
            }
            
            # Try to get user
            $user = Get-AzADUser -ObjectId $ObjectId -ErrorAction SilentlyContinue
            if ($null -ne $user -and -not [string]::IsNullOrEmpty($user.DisplayName)) {
                Write-Verbose "Resolved Object ID $ObjectId to User: $($user.DisplayName)" -Verbose
                return $user.DisplayName
            }
            
            # If neither worked, log it
            Write-Verbose "Could not resolve Object ID $ObjectId - no matching service principal or user found" -Verbose
        } catch {
            # If we can't resolve, fall back to the GUID
            Write-Verbose "Could not resolve Object ID $ObjectId to display name: $_" -Verbose
        }
    }
    
    # Fallback to original value if we can't resolve it
    return $ObjectId
}

# Helper function to get resource creation time from Azure Resource Manager
function Get-ResourceCreationTime {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceId,
        [Parameter(Mandatory=$true)]
        [string]$ObjectType
    )
    
    try {
        if ($ObjectType -eq "ResourceGroup") {
            if ($ResourceId -match "/subscriptions/[^/]+/resourceGroups/([^/]+)") {
                $rgName = $matches[1]
                $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
                return $null
            }
        } else {
            $resource = $null
            try {
                $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
            } catch {
                return $null
            }
            
            if ($null -ne $resource) {
                $properties = $null
                try {
                    $properties = $resource.Properties
                } catch {
                    return $null
                }
                
                if ($null -ne $properties) {
                    $creationTimeProps = @('creationTime', 'timeCreated', 'createdTime', 'createdDate', 'provisioningTime')
                    
                    foreach ($prop in $creationTimeProps) {
                        try {
                            if ($properties.PSObject.Properties.Name -contains $prop) {
                                $timeValue = $null
                                try {
                                    $timeValue = $properties.$prop
                                } catch {
                                    continue
                                }
                                
                                if ($null -ne $timeValue) {
                                    if ($timeValue -is [string]) {
                                        $timeValueStr = $timeValue.Trim()
                                        if ([string]::IsNullOrEmpty($timeValueStr) -or 
                                            $timeValueStr -eq "-" -or 
                                            $timeValueStr -eq "N/A" -or
                                            $timeValueStr -eq "null") {
                                            continue
                                        }
                                    }
                                    
                                    try {
                                        if ($timeValue -is [DateTime]) {
                                            return $timeValue
                                        } elseif ($timeValue -is [string]) {
                                            return [DateTime]::Parse($timeValue)
                                        }
                                    } catch {
                                    }
                                }
                            }
                        } catch {
                            continue
                        }
                    }
                }
                
                try {
                    Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue
                    if (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
                        $query = "Resources | where id == '$ResourceId' | project id, properties"
                        $results = Search-AzGraph -Query $query -ErrorAction SilentlyContinue
                        
                        if ($null -ne $results -and $results.Count -gt 0) {
                            $props = $results[0].properties
                            if ($null -ne $props) {
                                foreach ($prop in $creationTimeProps) {
                                    if ($props.PSObject.Properties.Name -contains $prop) {
                                        $timeValue = $props.$prop
                                        if ($null -ne $timeValue) {
                                            if ($timeValue -is [string]) {
                                                $timeValueStr = $timeValue.Trim()
                                                if ([string]::IsNullOrEmpty($timeValueStr) -or 
                                                    $timeValueStr -eq "-" -or 
                                                    $timeValueStr -eq "N/A" -or
                                                    $timeValueStr -eq "null") {
                                                    continue
                                                }
                                            }
                                            
                                            try {
                                                if ($timeValue -is [DateTime]) {
                                                    return $timeValue
                                                } elseif ($timeValue -is [string]) {
                                                    return [DateTime]::Parse($timeValue)
                                                }
                                            } catch {
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                }
            }
        }
    } catch {
    }
    
    return $null
}

# Function to add tags to an object (resource or resource group)
function Add-CreationTags {
    param(
        [Parameter(Mandatory=$true)]
        $Object,
        [Parameter(Mandatory=$true)]
        [string]$ObjectType,
        [Parameter(Mandatory=$true)]
        [string]$ObjectId
    )
    
    $tags = $null
    $hasCreatedBy = $false
    $hasDateCreated = $false
    $needsCreationTags = $true
    
    try {
        if ($ObjectType -eq "Resource") {
            $resourceDirect = Get-AzResource -ResourceId $ObjectId -ErrorAction SilentlyContinue
            if ($null -ne $resourceDirect) {
                try {
                    $tags = $resourceDirect.Tags
                } catch {
                    Write-Output "    [DEBUG] Could not access Tags property from Get-AzResource result: $_"
                    $tags = $null
                }
            }
        } else {
            if ($ObjectId -match "/subscriptions/[^/]+/resourceGroups/([^/]+)") {
                $rgName = $matches[1]
                $rgDirect = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
                if ($null -ne $rgDirect) {
                    try {
                        $tags = $rgDirect.Tags
                    } catch {
                        Write-Output "    [DEBUG] Could not access Tags property from Get-AzResourceGroup result: $_"
                        $tags = $null
                    }
                }
            }
        }
    } catch {
        Write-Output "    [DEBUG] Error retrieving resource directly: $_"
    }
    
    if ($null -eq $tags) {
        try {
            $tags = $Object.Tags
        } catch {
            Write-Output "    [DEBUG] Could not access resource object Tags property: $_"
        }
    }
    
    if ($null -ne $tags) {
        $hasCreatedBy = Test-TagExists -Tags $tags -TagName $createdByTagName
        $hasDateCreated = Test-TagExists -Tags $tags -TagName $dateCreatedTagName
        $needsCreationTags = (-not $hasCreatedBy) -or (-not $hasDateCreated)
    } else {
        $needsCreationTags = $true
    }
    
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-90)
    
    if ($null -eq $startTime -or $null -eq $endTime) {
        Write-Warning "    Invalid date parameters for activity log query"
        return $false
    }
    
    try {
        $allEventsRaw = Get-AzLog -ResourceId $ObjectId `
            -StartTime $startTime `
            -EndTime $endTime `
            -WarningAction SilentlyContinue `
            -ErrorAction SilentlyContinue
        
        $allEvents = $allEventsRaw | Where-Object { 
            ($null -ne $_.Authorization.Action -and (
                $_.Authorization.Action -like "*/write*" -or 
                $_.Authorization.Action -like "*write*" -or
                $_.Authorization.Action -eq "Microsoft.Resources/tags/write"
            )) -or
            ($null -ne $_.OperationName.Value -and (
                $_.OperationName.Value -like "*/write" -or
                $_.OperationName.Value -like "*/write*" -or
                $_.OperationName.Value -like "*write*"
            ))
        } | Sort-Object EventTimestamp
        
        $firstWriteEvent = $allEvents | Select-Object -First 1
        
        if ($null -ne $allEvents -and $allEvents.Count -gt 0) {
            Write-Output "    [DEBUG] Found $($allEvents.Count) write event(s) in activity logs"
            if ($null -ne $firstWriteEvent) {
                Write-Output "    [DEBUG] First write event: $($firstWriteEvent.EventTimestamp) by $($firstWriteEvent.Caller), Operation: $($firstWriteEvent.OperationName.Value)"
            }
        } else {
            Write-Output "    [DEBUG] No write events found in activity logs"
        }
        
        $creationEvent = $null
        
        if ($null -ne $firstWriteEvent) {
            $resourceCreationTime = Get-ResourceCreationTime -ResourceId $ObjectId -ObjectType $ObjectType
            
            if ($null -ne $resourceCreationTime) {
                $timeDifference = [Math]::Abs(($firstWriteEvent.EventTimestamp - $resourceCreationTime).TotalMinutes)
                
                if ($timeDifference -le $CreationTimeMatchWindowMinutes) {
                    $daysSinceCreation = (Get-Date) - $firstWriteEvent.EventTimestamp
                    if ($daysSinceCreation.TotalDays -le $MaxCreationAgeDays) {
                        $creationEvent = $firstWriteEvent
                        Write-Output "    [DEBUG] Found creation event: $($creationEvent.EventTimestamp) by $($creationEvent.Caller)"
                    } else {
                        Write-Output "    [DEBUG] Creation event too old: $([math]::Round($daysSinceCreation.TotalDays, 2)) days (max: $MaxCreationAgeDays)"
                    }
                } else {
                    $creationEvent = $null
                    Write-Output "    [DEBUG] First write event ($($firstWriteEvent.EventTimestamp)) is $([math]::Round($timeDifference, 2)) minutes after resource creation time - treating as modification"
                }
            } else {
                if (($null -eq $tags -or $tags.Count -eq 0)) {
                    $daysSinceFirstEvent = (Get-Date) - $firstWriteEvent.EventTimestamp
                    $eventCount = ($allEvents | Measure-Object).Count
                    
                    $allActivityEvents = $null
                    try {
                        $allActivityEvents = Get-AzLog -ResourceId $ObjectId `
                            -StartTime $startTime `
                            -EndTime $endTime `
                            -WarningAction SilentlyContinue `
                            -ErrorAction SilentlyContinue |
                            Sort-Object EventTimestamp
                    } catch {
                    }
                    
                    $hasOlderEvents = $false
                    if ($null -ne $allActivityEvents -and $allActivityEvents.Count -gt 0) {
                        $firstWriteTimestamp = $firstWriteEvent.EventTimestamp
                        $olderEvents = $allActivityEvents | Where-Object { 
                            $_.EventTimestamp -lt $firstWriteTimestamp -and 
                            $_.EventTimestamp -ne $firstWriteTimestamp 
                        }
                        $hasOlderEvents = ($olderEvents | Measure-Object).Count -gt 0
                    }
                    
                    $isLikelyCreation = $false
                    $reason = ""
                    
                    if ($daysSinceFirstEvent.TotalDays -le $MaxCreationAgeDays) {
                        if ($daysSinceFirstEvent.TotalHours -le 6) {
                            if (-not $hasOlderEvents) {
                                $isLikelyCreation = $true
                                $reason = "Very recent (within 6 hours) and no older events"
                            }
                            elseif ($eventCount -eq 1) {
                                $isLikelyCreation = $true
                                $reason = "Very recent (within 6 hours) and only one write event"
                            }
                            elseif ($null -ne $allActivityEvents -and $allActivityEvents.Count -gt 0) {
                                $earliestEvent = $allActivityEvents | Select-Object -First 1
                                if ($earliestEvent.EventTimestamp -eq $firstWriteEvent.EventTimestamp) {
                                    $isLikelyCreation = $true
                                    $reason = "Very recent (within 6 hours) and first write event is the earliest event"
                                }
                            }
                        }
                        
                        if (-not $isLikelyCreation -and -not $hasOlderEvents -and $daysSinceFirstEvent.TotalDays -le $HeuristicCreationWindowDays) {
                            if ($eventCount -eq 1 -and $daysSinceFirstEvent.TotalHours -gt 6) {
                                Write-Output "    [DEBUG] Skipping: Only one write event and more than 6 hours old - likely modification of old resource (creation event outside 90-day window)"
                            } else {
                                $isLikelyCreation = $true
                                $reason = "No older events and within $HeuristicCreationWindowDays days (heuristic window)"
                            }
                        }
                    } else {
                        Write-Output "    [DEBUG] First write event is too old: $([math]::Round($daysSinceFirstEvent.TotalDays, 2)) days (max: $MaxCreationAgeDays)"
                    }
                    
                    if ($isLikelyCreation) {
                        $creationEvent = $firstWriteEvent
                        Write-Output "    [DEBUG] Found creation event (heuristic - $reason): $($creationEvent.EventTimestamp) by $($creationEvent.Caller)"
                    } else {
                        Write-Output "    [DEBUG] Skipping creation event (heuristic failed): hasOlderEvents=$hasOlderEvents, days=$([math]::Round($daysSinceFirstEvent.TotalDays, 2)), hours=$([math]::Round($daysSinceFirstEvent.TotalHours, 2)), eventCount=$eventCount"
                        Write-Output "    [DEBUG] First write event: $($firstWriteEvent.EventTimestamp) by $($firstWriteEvent.Caller), Operation: $($firstWriteEvent.OperationName.Value)"
                    }
                }
            }
        }
        
        $modificationEvents = $allEvents | Where-Object { 
            $isTagOperation = ($_.OperationName.Value -like "*/tags/write" -or
                              $_.OperationName.Value -like "Microsoft.Resources/tags/write" -or
                              $_.OperationName.Value -like "Microsoft.Resources/tags/*" -or
                              $_.Authorization.Action -like "Microsoft.Resources/tags/*" -or
                              $_.Authorization.Action -like "*/tags/*")
            
            $shouldExcludeTagOp = $false
            if ($isTagOperation) {
                $shouldExcludeTagOp = Test-IsExcludedIdentity -Caller $_.Caller
            }
            
            (-not $isTagOperation -or -not $shouldExcludeTagOp) -and
            (-not (Test-IsExcludedIdentity -Caller $_.Caller)) -and
            ($_.Caller -notlike "*Windows Azure*" -and
             $_.Caller -notlike "*Microsoft.Insights*" -and
             $_.Caller -notlike "*autoscale*") -and
            ($_.OperationName.Value -notlike "*autoscaleSettings*" -and
             $_.OperationName.Value -notlike "Microsoft.Insights/autoscaleSettings/*")
        }
        
        $lastModificationEvent = $modificationEvents | Select-Object -Last 1
        
        if ($null -ne $modificationEvents) {
            Write-Output "    [DEBUG] Found $($modificationEvents.Count) modification event(s) after filtering"
            if ($null -ne $lastModificationEvent) {
                Write-Output "    [DEBUG] Last modification event: $($lastModificationEvent.EventTimestamp) by $($lastModificationEvent.Caller), Operation: $($lastModificationEvent.OperationName.Value)"
            }
        } else {
            Write-Output "    [DEBUG] No modification events found after filtering"
        }
    }
    catch {
        Write-Output "    [DEBUG] Error in activity log processing: $_"
        return $false
    }
    
    if ($null -eq $creationEvent -and $needsCreationTags) {
        Write-Output "    [DEBUG] No creation event found for resource (needs creation tags)"
        if ($null -ne $firstWriteEvent) {
            $hoursSinceFirst = [math]::Round((Get-Date - $firstWriteEvent.EventTimestamp).TotalHours, 2)
            Write-Output "    [DEBUG] First write event exists but was not identified as creation: $($firstWriteEvent.EventTimestamp) ($hoursSinceFirst hours ago) by $($firstWriteEvent.Caller)"
            Write-Output "    [DEBUG] Event details - Operation: $($firstWriteEvent.OperationName.Value), EventCount: $eventCount, hasOlderEvents: $hasOlderEvents"
        } else {
            Write-Output "    [DEBUG] No write events found in activity logs"
        }
        if ($null -eq $lastModificationEvent) {
            Write-Output "    [DEBUG] No modification events found - cannot proceed with tagging"
            return $false
        }
    } elseif (-not $needsCreationTags) {
        Write-Output "    [DEBUG] Resource already has creation tags (Created-By: $hasCreatedBy, Created-Date: $hasDateCreated)"
        if ($null -eq $lastModificationEvent) {
            Write-Output "    [DEBUG] No modification events found - skipping LastModified tag update"
        } else {
            Write-Output "    [DEBUG] Found modification events - will update LastModified tags"
        }
    }
    
    $modifiedTags = @{}
    
    # Add Created-By tag ONLY if missing (never update once set)
    if (-not $hasCreatedBy -and $null -ne $creationEvent) {
        $caller = $creationEvent.Caller
        # Resolve Object ID to display name
        $owner = Get-DisplayNameFromObjectId -ObjectId $caller
        $modifiedTags[$createdByTagName] = $owner
        Write-Output "    [DEBUG] Adding Created-By: $owner"
    }
    
    # Add DateCreated tag ONLY if missing (never update once set)
    if (-not $hasDateCreated -and $null -ne $creationEvent) {
        $creationDate = $creationEvent.EventTimestamp.ToString("yyyy-MM-dd")
        $modifiedTags[$dateCreatedTagName] = $creationDate
        Write-Output "    [DEBUG] Adding Created-Date: $creationDate"
    }
    
    # Update LastModifiedBy and LastModifiedDate tags if we found valid modification events
    if ($null -ne $lastModificationEvent) {
        $lastModifier = $lastModificationEvent.Caller
        # Resolve Object ID to display name
        $lastModifiedByValue = Get-DisplayNameFromObjectId -ObjectId $lastModifier
        $modifiedTags[$lastModifiedByTagName] = $lastModifiedByValue
        Write-Output "    [DEBUG] Updating LastModifiedBy: $lastModifiedByValue"
        
        $lastModifiedDate = $lastModificationEvent.EventTimestamp.ToString("yyyy-MM-dd HH:mm:ss")
        $modifiedTags[$lastModifiedDateTagName] = $lastModifiedDate
        Write-Output "    [DEBUG] Updating LastModifiedDate: $lastModifiedDate"
    }
    
    # Apply tags
    if ($modifiedTags.Count -gt 0) {
        $existingTags = if ($null -eq $tags) { @{} } else { $tags }
        
        $allTags = @{}
        
        foreach ($key in $existingTags.Keys) {
            $isOurManagedTag = ($key -ieq $createdByTagName) -or 
                              ($key -ieq $dateCreatedTagName) -or 
                              ($key -ieq $lastModifiedByTagName) -or 
                              ($key -ieq $lastModifiedDateTagName)
            
            if (-not $isOurManagedTag) {
                $allTags[$key] = $existingTags[$key]
            }
        }
        
        if (-not $modifiedTags.ContainsKey($createdByTagName)) {
            foreach ($key in $existingTags.Keys) {
                if ($key -ieq $createdByTagName) {
                    $allTags[$createdByTagName] = $existingTags[$key]
                    break
                }
            }
        }
        
        if (-not $modifiedTags.ContainsKey($dateCreatedTagName)) {
            foreach ($key in $existingTags.Keys) {
                if ($key -ieq $dateCreatedTagName) {
                    $allTags[$dateCreatedTagName] = $existingTags[$key]
                    break
                }
            }
        }
        
        foreach ($key in $modifiedTags.Keys) {
            $allTags[$key] = $modifiedTags[$key]
        }
        
        try {
            if ($ObjectType -eq "Resource") {
                try {
                    Update-AzTag -ResourceId $ObjectId -Tag $allTags -Operation Replace -ErrorAction Stop | Out-Null
                } catch {
                    Set-AzResource -ResourceId $ObjectId -Tag $allTags -Force -ErrorAction Stop | Out-Null
                }
            } else {
                Set-AzResourceGroup -Name $Object.ResourceGroupName -Tag $allTags -ErrorAction Stop | Out-Null
            }
            
            Start-Sleep -Milliseconds 1000
            $verifyTags = if ($ObjectType -eq "Resource") {
                (Get-AzResource -ResourceId $ObjectId -ErrorAction SilentlyContinue).Tags
            } else {
                (Get-AzResourceGroup -Name $Object.ResourceGroupName -ErrorAction SilentlyContinue).Tags
            }
            
            $tagsApplied = $true
            $missingTags = @()
            foreach ($key in $modifiedTags.Keys) {
                if ($null -eq $verifyTags -or -not $verifyTags.ContainsKey($key)) {
                    $tagsApplied = $false
                    $missingTags += $key
                } elseif ($verifyTags[$key] -ne $modifiedTags[$key]) {
                    $tagsApplied = $false
                    $missingTags += "$key (value mismatch: expected '$($modifiedTags[$key])', got '$($verifyTags[$key])')"
                }
            }
            
            if (-not $tagsApplied) {
                Write-Warning "Tags were not properly applied to $ObjectId. Missing or incorrect: $($missingTags -join ', ')"
                try {
                    if ($ObjectType -eq "Resource") {
                        Write-Output "    [DEBUG] Retrying tag application with Set-AzResource..."
                        Set-AzResource -ResourceId $ObjectId -Tag $allTags -Force -ErrorAction Stop | Out-Null
                        Start-Sleep -Milliseconds 1000
                        $verifyTags = (Get-AzResource -ResourceId $ObjectId -ErrorAction SilentlyContinue).Tags
                        $tagsApplied = $true
                        foreach ($key in $modifiedTags.Keys) {
                            if ($null -eq $verifyTags -or -not $verifyTags.ContainsKey($key) -or $verifyTags[$key] -ne $modifiedTags[$key]) {
                                $tagsApplied = $false
                                break
                            }
                        }
                        if ($tagsApplied) {
                            Write-Output "    [DEBUG] Tags successfully applied on retry"
                        }
                    }
                } catch {
                    Write-Warning "Retry also failed: $_"
                }
            } else {
                Write-Output "    [DEBUG] Tags verified successfully: $($modifiedTags.Keys -join ', ')"
            }
            
            return $tagsApplied
        }
        catch {
            Write-Warning "Failed to apply tags to $ObjectId : $_"
            return $false
        }
    }
    
    return $false
}

Write-Output "=========================================="
Write-Output "Starting Auto-Tagging Process"
Write-Output "=========================================="
Write-Output "Configuration:"
Write-Output "  - Subscription IDs: $($SubscriptionIDs.Count) subscription(s)"
Write-Output "  - Max creation age: $MaxCreationAgeDays days"
Write-Output "  - Heuristic creation window: $HeuristicCreationWindowDays days (for resources without creation time metadata)"
Write-Output "  - Excluded identities: $($script:excludedIdentitiesList.Count + 1) (including automation account)"
Write-Output ""

if ($SubscriptionIDs -is [string]) {
    $SubscriptionIDs = @($SubscriptionIDs)
}

$totalResourceGroupsProcessed = 0
$totalResourceGroupsTagged = 0
$totalResourcesProcessed = 0
$totalResourcesTagged = 0
$totalSkipped = 0

foreach ($SubscriptionID in $SubscriptionIDs) {
    Write-Output "=========================================="
    Write-Output "Subscription ID: $SubscriptionID"
    Write-Output "=========================================="
    
    Write-Output "Setting context to subscription '$SubscriptionID'..."
    
    try {
        Set-AzContext -Subscription $SubscriptionID -ErrorAction Stop | Out-Null
        $subscription = Get-AzSubscription -SubscriptionId $SubscriptionID -ErrorAction Stop
        Write-Output "Successfully set context to subscription: $($subscription.Name)"
        Write-Output ""
    } catch {
        Write-Warning "Failed to set context to subscription '$SubscriptionID': $_"
        Write-Warning "  Skipping subscription..."
        continue
    }
    
    Write-Output ""
    Write-Output "--- Processing Resource Groups ---"
    Write-Output "Resource groups are excluded from tagging - skipping..."
    Write-Output ""
    
    Write-Output ""
    Write-Output "--- Processing Resources ---"
    try {
        $resources = @()
        try {
            $allResources = Get-AzResource -ErrorAction Stop
            foreach ($res in $allResources) {
                if ($null -ne $res -and $null -ne $res.ResourceId -and -not [string]::IsNullOrEmpty($res.ResourceId)) {
                    $resources += $res
                }
            }
        } catch {
            Write-Warning "Error retrieving resources: $_"
            Write-Warning "This might be due to a problematic resource. Attempting to continue with available resources..."
            try {
                $resourceTypes = @('Microsoft.Network/networkSecurityGroups', 'Microsoft.Network/applicationSecurityGroups', 'Microsoft.Automation/automationAccounts')
                foreach ($type in $resourceTypes) {
                    try {
                        $typeResources = Get-AzResource -ResourceType $type -ErrorAction SilentlyContinue
                        foreach ($res in $typeResources) {
                            if ($null -ne $res -and $null -ne $res.ResourceId) {
                                $resources += $res
                            }
                        }
                    } catch {
                        Write-Warning "  Skipping resource type $type due to error: $_"
                    }
                }
            } catch {
                Write-Warning "Failed to retrieve resources by type: $_"
            }
        }
        
        Write-Output "Found $($resources.Count) resource(s)"
        Write-Output ""
        
        foreach ($resource in $resources) {
            if ($null -eq $resource) {
                Write-Warning "  Skipping null resource"
                continue
            }
            
            if ($null -eq $resource.ResourceId -or [string]::IsNullOrEmpty($resource.ResourceId)) {
                Write-Warning "  Skipping resource '$($resource.Name)' with null or empty ResourceId"
                continue
            }
            
            if ($null -ne $resource.ResourceType -and 
                ($resource.ResourceType -like "Microsoft.Compute/*/extensions" -or 
                 $resource.ResourceType -like "Microsoft.ClassicCompute/*/extensions" -or
                 $resource.ResourceType -eq "Microsoft.Compute/virtualMachines/extensions" -or
                 $resource.ResourceType -eq "Microsoft.Compute/virtualMachineScaleSets/extensions")) {
                Write-Output "  - Skipped (VM extension - excluded from tagging)"
                continue
            }
            
            $totalResourcesProcessed++
            Write-Output "[R-$totalResourcesProcessed] $($resource.Name) [$($resource.ResourceType)]"
            
            try {
                $tagged = Add-CreationTags -Object $resource -ObjectType "Resource" -ObjectId $resource.ResourceId
            } catch {
                if ($_.Exception.Message -match "Cannot bind parameter.*Date|Cannot convert.*DateTime|was not recognized as a valid DateTime") {
                    Write-Output "  - Skipped (error accessing resource properties - may have invalid date fields)"
                    Write-Output "    Note: This can occur with certain resource types. The script attempted to process the resource but encountered an error."
                } else {
                    Write-Warning "  Error processing resource $($resource.Name): $_"
                    Write-Warning "  Error details: $($_.Exception.Message)"
                    if ($_.Exception.InnerException) {
                        Write-Warning "  Inner exception: $($_.Exception.InnerException.Message)"
                    }
                }
                continue
            }
            
            if ($tagged) {
                $totalResourcesTagged++
                Write-Output "  + Tagged"
                
                try {
                    $verifyResource = Get-AzResource -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
                    if ($null -ne $verifyResource -and $null -ne $verifyResource.Tags) {
                        $appliedTags = @()
                        if ($verifyResource.Tags.ContainsKey($createdByTagName)) {
                            $appliedTags += "$createdByTagName=$($verifyResource.Tags[$createdByTagName])"
                        }
                        if ($verifyResource.Tags.ContainsKey($dateCreatedTagName)) {
                            $appliedTags += "$dateCreatedTagName=$($verifyResource.Tags[$dateCreatedTagName])"
                        }
                        if ($verifyResource.Tags.ContainsKey($lastModifiedByTagName)) {
                            $appliedTags += "$lastModifiedByTagName=$($verifyResource.Tags[$lastModifiedByTagName])"
                        }
                        if ($verifyResource.Tags.ContainsKey($lastModifiedDateTagName)) {
                            $appliedTags += "$lastModifiedDateTagName=$($verifyResource.Tags[$lastModifiedDateTagName])"
                        }
                        if ($appliedTags.Count -gt 0) {
                            Write-Output "    Applied tags: $($appliedTags -join ', ')"
                        } else {
                            Write-Warning "    WARNING: Function returned success but no tags found on resource!"
                        }
                    } else {
                        Write-Warning "    WARNING: Could not verify tags - resource or tags are null"
                    }
                } catch {
                    Write-Warning "    WARNING: Error verifying tags: $_"
                }
            } else {
                $hasCreatedBy = Test-TagExists -Tags $resource.Tags -TagName $createdByTagName
                $hasDateCreated = Test-TagExists -Tags $resource.Tags -TagName $dateCreatedTagName
                
                if (-not $hasCreatedBy -or -not $hasDateCreated) {
                    $totalSkipped++
                    Write-Output "  - Skipped (no creation event found within $MaxCreationAgeDays days or no activity log data)"
                } else {
                    Write-Output "  - Skipped (already has creation tags, no new modifications to track)"
                }
            }
        }
    } catch {
        Write-Warning "Failed to retrieve resources: $_"
    }
    
    Write-Output ""
}

Write-Output "=========================================="
Write-Output "Auto-Tagging Process Complete"
Write-Output "=========================================="
Write-Output "Total subscriptions processed: $($SubscriptionIDs.Count)"
Write-Output ""

Write-Output "Resource Groups:"
Write-Output "  - Processed: $totalResourceGroupsProcessed"
Write-Output "  - Tagged: $totalResourceGroupsTagged"
Write-Output ""

Write-Output "Resources:"
Write-Output "  - Processed: $totalResourcesProcessed"
Write-Output "  - Tagged: $totalResourcesTagged"
Write-Output "  - Skipped: $totalSkipped"
Write-Output "=========================================="
