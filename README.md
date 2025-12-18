# Tag Azure Resources with Creation and Modification Metadata using Azure Automation

This PowerShell runbook automatically tags Azure resources with creation and modification metadata by analyzing Azure Activity Logs. It's designed to run as a scheduled runbook in Azure Automation to maintain accurate ownership and change tracking across your Azure environment.

<img width="1915" height="400" alt="image" src="https://github.com/user-attachments/assets/fbf023e7-32d2-4706-80ca-af265b11a58a" />


This runbook uses a **System Managed Identity** from the Azure Automation account, so ensure it has **Contributor** rights to the subscriptions you want to tag resources in, plus **Directory.Read.All** permission in Microsoft Graph.

## Overview

This PowerShell script is designed to tag Azure resources with creation and modification metadata by analyzing Azure Activity Logs. It's particularly useful for tracking who created resources and who last modified them in your Azure environment. 

Here's a step-by-step breakdown of what the script does:

1. **Disable AzContext Autosave**: The script starts by disabling the autosave feature for the Azure context to ensure it doesn't inherit any Azure context from previous sessions.

2. **Suppress Warnings**: Suppresses warnings related to breaking changes in Azure PowerShell to keep output clean.

3. **Import Modules**: Imports the `Az.Accounts`, `Az.Resources`, and optionally `Az.ResourceGraph` modules needed to interact with Azure.

4. **Define Variables**: Configures tag names, subscription IDs, and various thresholds for creation event detection.

5. **Connect to Azure**: Uses a Managed Service Identity to authenticate with Azure.

6. **Get Automation Identity**: Identifies the automation account's managed identity to exclude it from LastModified tracking.

7. **Process Each Subscription**: Iterates through specified subscriptions and retrieves all resources.

8. **Process Each Resource**: For each resource, the script:
   - Checks if creation tags (`CreatedBy`, `CreationDate`) already exist
   - Retrieves Azure Activity Logs for the past 90 days
   - Distinguishes between creation and modification events by:
     - Comparing first write event with actual resource creation time from Azure Resource Manager
     - Using conservative heuristics for resources without creation metadata
     - Only tagging as "creation" if events match within a configurable time window

9. **Add Tags**: 
   - **Creation tags** are added only if missing (never overwritten once set)
   - **LastModified tags** are always updated with the latest modification information
   - Excludes automation account's own actions from LastModified tracking

10. **Resolve Identities**: Converts Object IDs (GUIDs) to display names for better readability.

This script is designed to be run on a schedule (e.g., daily) to ensure all resources are tagged with accurate creation and modification metadata.

## Tags Applied

The script adds the following tags to your Azure resources:

- **CreatedBy** - Email or display name of who created the resource
- **CreationDate** - Date when the resource was created (YYYY-MM-DD)
- **LastModifiedBy** - Email or display name of who last modified the resource
- **LastModifiedDate** - Date and time of last modification (YYYY-MM-DD HH:mm:ss)

## Configuration

Edit these variables at the top of the script to match your environment:

```powershell
# Define the tag names as variables
$createdByTagName = "CreatedBy"
$dateCreatedTagName = "CreationDate"
$lastModifiedByTagName = "LastModifiedBy"
$lastModifiedDateTagName = "LastModifiedDate"

# Subscription IDs - the subscriptions that the script will run against
$SubscriptionIDs = @(
    'subscription-id-1',
    'subscription-id-2'
)

# Maximum age (in days) for creation events - resources older than this will be skipped
$MaxCreationAgeDays = 30

# Time window (in minutes) to match first write event with resource creation time
$CreationTimeMatchWindowMinutes = 10

# Heuristic window (in days) for identifying creation events when resource creation time is not available
$HeuristicCreationWindowDays = 14

# Additional identities to exclude from LastModified tracking
$ExcludedIdentities = @(
    "automation-account-object-id"
)
```

## Key Features

-  **Smart Creation Detection**: Distinguishes between creation and modification events by comparing with actual resource creation time
-  **Preserves Creation Tags**: Never overwrites existing `CreatedBy` or `CreationDate` tags once set
-  **Always Updates LastModified**: Keeps `LastModifiedBy` and `LastModifiedDate` tags current
-  **Excludes Automation Actions**: Filters out the automation account's own tagging operations from LastModified tracking
-  **Resolves Object IDs**: Converts service principal GUIDs to display names for better readability
-  **Multi-Subscription Support**: Processes multiple subscriptions in a single run
-  **Excludes VM Extensions**: Automatically skips VM extensions to avoid tagging issues
-  **Conservative Heuristics**: Uses multiple validation methods to prevent incorrectly tagging old resources

## Requirements

- **Azure Automation Account** with Managed Identity enabled
- **PowerShell Modules**:
  - `Az.Accounts`
  - `Az.Resources`
  - `Az.ResourceGraph` (optional, but recommended for better creation time detection)
- **Permissions**:
  - **Contributor** role on target subscriptions or management groups
  - **Directory.Read.All** permission in Microsoft Graph (to resolve service principal Object IDs to display names)

> **Note:** Objects created by a Service Principal will be tagged with a GUID instead of a name by default unless the Managed Identity has the Application Developer role in Entra ID or Directory.Read.All permission in Microsoft Graph.

## Limitations

- **Activity Log Retention**: Azure Activity Logs only retain 90 days of data. Resources older than 90 days may not have creation events available in the logs.
- **Creation Event Detection**: For resources without accessible creation time metadata, the script uses conservative heuristics that may skip some resources to avoid false positives.
- **Resource Groups**: Currently excluded from tagging in this version.
- **Rate Limiting**: The script includes delays between operations to avoid Azure API throttling.

## Usage

### Deploy to Azure Automation

1. Navigate to your Azure Automation Account
2. Go to **Runbooks** → **Create a runbook**
3. Set runbook type to **PowerShell**
4. Paste the script content
5. Update the configuration variables (subscription IDs, tag names, etc.)
6. Save and publish the runbook

### Configure Managed Identity Permissions

```powershell
# Grant Contributor access to subscription(s)
# Grant Directory.Read.All in Microsoft Graph (use Azure Portal or Microsoft Graph PowerShell)
```

### Schedule the Runbook

1. In the runbook, select **Schedules** → **Add a schedule**
2. Create a new schedule (e.g., daily at midnight)
3. Link the schedule to the runbook

### Manual Execution

You can also run the script manually from your local machine (ensure you're authenticated with `Connect-AzAccount`):

```powershell
.\Auto-Tag-Resources.ps1
```

## Sample Output

```
==========================================
Starting Auto-Tagging Process
==========================================
Configuration:
  - Subscription IDs: 2 subscription(s)
  - Max creation age: 30 days
  - Heuristic creation window: 14 days

==========================================
Subscription ID: 12345678-1234-1234-1234-123456789abc
==========================================

--- Processing Resources ---
Found 25 resource(s)

[R-1] my-storage-account [Microsoft.Storage/storageAccounts]
    [DEBUG] Found creation event: 2024-12-15 by user@contoso.com
    [DEBUG] Adding Created-By: user@contoso.com
    [DEBUG] Adding Created-Date: 2024-12-15
    [DEBUG] Updating LastModifiedBy: user@contoso.com
    [DEBUG] Updating LastModifiedDate: 2024-12-15 10:30:45
    + Tagged

[R-2] my-vm [Microsoft.Compute/virtualMachines]
    [DEBUG] Resource already has creation tags
    [DEBUG] Found modification events - will update LastModified tags
    [DEBUG] Updating LastModifiedBy: admin@contoso.com
    [DEBUG] Updating LastModifiedDate: 2024-12-18 14:22:10
    + Tagged

==========================================
Auto-Tagging Process Complete
==========================================
Total subscriptions processed: 2

Resources:
  - Processed: 25
  - Tagged: 18
  - Skipped: 7
==========================================
```

## Troubleshooting

### Tags Not Applied

- Verify the Managed Identity has Contributor permissions
- Check that the resource type supports tagging
- Review the runbook output for specific error messages

### Object IDs Instead of Names

- Ensure the Managed Identity has `Directory.Read.All` permission in Microsoft Graph
- Wait a few minutes after granting permissions for them to propagate

### Creation Tags Not Found

- Resources older than 90 days won't have activity log data
- Resources created before the activity log retention period won't have creation events
- The script uses conservative heuristics to avoid false positives

## Contributing

Feel free to raise an issue or pull request if you have improvements or encounter any problems.

## Tags

`Azure` `Automation` `PowerShell` `Tagging` `Governance` `Azure-Resources`
