# Azure Storage Compliance Checker Function App (py-defender-storage-compliance-checker)

## Description

This Azure Function App, written in Python, automates the compliance checking of specified Azure Storage Accounts against a defined baseline. It focuses on validating Microsoft Defender for Storage configurations and associated logging settings. The function can be triggered on a schedule (Timer Trigger) or on-demand (HTTP Trigger for testing/manual runs) and uses Managed Identity for secure authentication to Azure resources. It also includes optional remediation capabilities to bring non-compliant resources into the desired state.

This project serves as a practical example of using Azure SDKs with Python for cloud security automation and governance within an Azure Functions serverless environment.

## Features

* **Scheduled Compliance Checks:** Runs automatically via an Azure Functions Timer Trigger.
* **On-Demand Trigger:** Includes an HTTP trigger for manual execution during testing or specific needs.
* **Targeted Scanning:** Checks only specific storage accounts listed in configuration within a defined resource group [cite: azure_defender_tool/main.py].
* **Compliance Baseline Checks:**
    * Verifies if the Microsoft Defender for Storage plan is enabled [cite: azure_defender_tool/compliance.py].
    * Verifies if subscription-level settings override is enabled [cite: azure_defender_tool/compliance.py].
    * Verifies if Malware Scanning on upload is enabled [cite: azure_defender_tool/compliance.py].
    * Verifies if diagnostic settings associated with Defender for Storage are sending logs (specifically the `ScanResults` category [cite: azure_defender_tool/config.py]) to the expected Log Analytics Workspace [cite: azure_defender_tool/compliance.py]. (Checks the nested diagnostic setting named "service" [cite: azure_defender_tool/config.py, azure_defender_tool/compliance.py]).
* **Optional Remediation:** If enabled via configuration, attempts to automatically remediate non-compliant settings [cite: azure_defender_tool/remediation.py]:
    * Enables Defender plan, override settings, and enable malware scanning via defender_for_storage.create [cite: azure_defender_tool/remediation.py].
    * Configures the diagnostic setting via diagnostic_settings.create_or_update [cite: azure_defender_tool/remediation.py].
* **Secure Authentication:** Uses `DefaultAzureCredential` which leverages Managed Identity when deployed in Azure for passwordless access [cite: azure_defender_tool/main.py].
* **Structured Logging:** Uses standard Python logging configured to integrate with Azure Functions monitoring / Application Insights [cite: azure_defender_tool/logger_config.py, azure_defender_tool/main.py].

## Technology Stack

* **Azure Functions:** Python v2 programming model (Timer & HTTP Triggers).
* **Python:** 3.7-3.12 (Check Azure Functions Python support for exact versions).
* **Azure SDK for Python:**
    * `azure-identity` (Authentication via `DefaultAzureCredential`) [cite: azure_defender_tool/main.py]
    * `azure-mgmt-resource` (Listing resources) [cite: azure_defender_tool/main.py]
    * `azure-mgmt-security` (Getting/Updating Defender for Storage settings) [cite: azure_defender_tool/compliance.py, azure_defender_tool/remediation.py]
    * `azure-mgmt-monitor` (Getting/Updating Diagnostic Settings) [cite: azure_defender_tool/compliance.py, azure_defender_tool/remediation.py]
* **Azure Services:**
    * Azure Storage Accounts (Target Resource)
    * Microsoft Defender for Storage
    * Azure Monitor (Log Analytics Workspace, Diagnostic Settings)
    * Azure Active Directory (Managed Identity)
* **Local Development:**
    * Azure Functions Core Tools
    * Azurite Storage Emulator
    * `python-dotenv` (For managing local `.env` file if running script directly, not needed for `local.settings.json`) [cite: azure_defender_tool/main.py]

## Project Structure

```
defender-for-storage-compliance/
│
├── .venv/                       # Python Virtual Environment (ignored by Git)
├── azure_defender_tool/         # Main Python package for the tool's logic
│   ├── __init__.py              # Package marker [cite: azure_defender_tool/__init__.py]
│   ├── config.py                # Stores constants (setting names, etc.) [cite: azure_defender_tool/config.py]
│   ├── logger_config.py         # Configures the application logger [cite: azure_defender_tool/logger_config.py]
│   ├── azure_utils.py           # Utility for getting subscription ID [cite: azure_defender_tool/azure_utils.py]
│   ├── compliance.py            # Contains check_compliance function [cite: azure_defender_tool/compliance.py]
│   └── remediation.py           # Contains remediation_orchestrator function [cite: azure_defender_tool/remediation.py]
│   └── main.py                  # Contains main() function orchestrating the core logic [cite: azure_defender_tool/main.py]
├── function_app.py              # Azure Functions v2 entry point (triggers)
├── requirements.txt             # Python package dependencies
├── host.json                    # Azure Functions host configuration
├── local.settings.json          # Local development configuration (ignored by Git)
├── local.settings.example.json  # Example configuration file (safe to commit)
└── .gitignore                   # Files/directories ignored by Git
└── README.md                    # This file
```

## Configuration

Configuration is handled via environment variables. For local development using the Azure Functions Core Tools, use the `local.settings.json` file. When deployed to Azure, configure these as **Application Settings** in the Function App.

**Required Settings:**

Create a `local.settings.json` file in the project root (or copy from `local.settings.example.json`) with the following structure in the `"Values"` section:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_SUBSCRIPTION_ID": "YOUR_AZURE_SUBSCRIPTION_ID_HERE",
    "AZURE_RESOURCE_GROUP": "YOUR_TARGET_RESOURCE_GROUP_NAME_HERE",
    "TARGET_STORAGE_ACCOUNTS": "your_target_sa_name1,your_target_sa_name2",
    "WORKSPACE_ID": "YOUR_EXPECTED_LAW_RESOURCE_ID_HERE",
    "REMEDIATON_ENABLED": "false",
    "SECURITY_API_VERSION": ""
  }
}
```

* **`AzureWebJobsStorage`**: Connection string for Azure Storage. Use `"UseDevelopmentStorage=true"` for local development with the Azurite emulator. For Azure deployment, set this to the connection string of a general-purpose storage account.
* **`FUNCTIONS_WORKER_RUNTIME`**: Should be `"python"`.
* **`AZURE_SUBSCRIPTION_ID`**: Your Azure Subscription ID (acts as fallback if automatic detection fails in Azure). *Required for local testing.* [cite: azure_defender_tool/main.py]
* **`AZURE_RESOURCE_GROUP`**: The name of the Azure Resource Group containing the storage accounts you want to scan [cite: azure_defender_tool/main.py].
* **`TARGET_STORAGE_ACCOUNTS`**: A comma-separated string of the exact storage account names to check within the specified resource group [cite: azure_defender_tool/main.py].
* **`WORKSPACE_ID`**: The full Azure Resource ID of the target Log Analytics Workspace for the diagnostic setting check and remediation [cite: azure_defender_tool/main.py].
* **`REMEDIATON_ENABLED`**: Set to `"true"` to enable automatic remediation actions; set to `"false"` (recommended default) to run in audit-only mode. **Use `"true"` with extreme caution.** [cite: azure_defender_tool/main.py]
* **`SECURITY_API_VERSION`**: (Optional) Specify a specific API version for the `SecurityCenter` client if needed (e.g., `"2022-12-01-preview"`). Leave blank or omit to use the SDK's default [cite: azure_defender_tool/main.py].

## Prerequisites

* Python (Version compatible with Azure Functions - e.g., 3.9, 3.10, 3.11, 3.12)
* Azure Functions Core Tools
* Azurite Storage Emulator (for local development, installable via VS Code extension or npm)
* Azure CLI (logged in via `az login` for local development credential)
* Git

## Setup & Local Execution

1.  **Clone Repository:**
    `git clone <your-repo-url>`
    `cd <repo-name>`
2.  **Create Virtual Environment:**
    `python -m venv .venv` (Use the command for your specific supported Python version, e.g., `py -3.11` or `python3.11`)
3.  **Activate Virtual Environment:**
    * Windows: `.\.venv\Scripts\activate`
    * macOS/Linux: `source .venv/bin/activate`
4.  **Install Dependencies:**
    `pip install -r requirements.txt`
5.  **Configure Local Settings:** Create `local.settings.json` in the project root (as described in Configuration) and fill in your Azure details.
6.  **Start Azurite:** Use the VS Code command palette (`Ctrl+Shift+P`) -> `Azurite: Start`. Verify Blob and Queue services start.
7.  **Login to Azure:**
    `az login`
8.  **Run Locally (VS Code):**
    * Open the project folder in VS Code.
    * Go to the "Run and Debug" view (`Ctrl+Shift+D`).
    * Select the "Attach to Python Functions" configuration.
    * Press F5 to start the debugger and the Functions host.
    * Wait for the host to start and display the HTTP trigger URL.
9.  **Trigger (HTTP for Testing):**
    * Find the URL for `runComplianceCheck` in the terminal output (e.g., `http://localhost:7071/api/runComplianceCheck`).
    * Open this URL in your web browser or use `curl`.
10. **Observe Logs:** Check the VS Code terminal output for logs generated by the function.

## Deployment

1.  Deploy to your Azure Function App using the Azure Functions extension in VS Code (Right-click deploy or use the Azure view) or via Azure Functions Core Tools (`func azure functionapp publish <YourFunctionAppName>`).
2.  Configure **Application Settings** in the deployed Function App in the Azure Portal with the same keys and values used in `local.settings.json` (except `AzureWebJobsStorage`, which should point to a real storage account).
3.  Ensure the Function App's **Managed Identity** has the necessary **RBAC roles** assigned (`Reader` for checks, write permissions like `Security Admin` or custom roles for `Microsoft.Security/defenderForStorageSettings/write` and `Microsoft.Insights/diagnosticSettings/write` if remediation is enabled).
4.  Monitor execution via the Azure Portal (Monitor tab, Application Insights).

## Remediation

* Remediation actions (enabling Defender, configuring logging) are only performed if the `REMEDIATON_ENABLED` setting is set to `"true"` [cite: azure_defender_tool/main.py].
* **Use caution when enabling remediation.** Ensure the script is thoroughly tested and the Managed Identity has the minimum required write permissions.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
