**Azure Storage Compliance Checker Function App**

**Description**

The Azure Storage Compliance Checker Function App is an automated solution to validate and optionally remediate security configurations for Azure Storage Accounts. Built on the Azure Functions Python v2 programming model, it performs scheduled and on-demand checks of Microsoft Defender for Storage and diagnostic logging settings against a defined security baseline. Authentication is handled securely through Azure Managed Identity.

---

## Table of Contents

1. [Core Features](#core-features)
2. [Technology Stack](#technology-stack)
3. [Prerequisites](#prerequisites)
4. [Project Structure](#project-structure)
5. [Configuration](#configuration)
6. [Setup & Local Execution](#setup--local-execution)
7. [Deployment](#deployment)
8. [Remediation Note](#remediation-note)
9. [License](#license)

---

## Core Features

- **Scheduled & On-Demand Checks**: Uses a Timer trigger for periodic compliance scans and an HTTP trigger for manual execution.
- **Targeted Storage Accounts**: Validates only those accounts listed in configuration.
- **Compliance Validations**:
  - Defender for Storage enabled
  - Subscription Override enabled
  - Malware Scanning on Upload enabled
  - Diagnostic settings forwarding "ScanResults" logs to a specified Log Analytics Workspace
- **Optional Remediation**: Automatically applies fixes (enabling Defender settings or configuring diagnostics) if non-compliant and remediation is enabled.
- **Secure Authentication**: Leverages Azure Managed Identity via `DefaultAzureCredential` from `azure-identity`.
- **Integrated Logging**: Standard Python `logging` integrated with Azure Functions and Application Insights.

---

## Technology Stack

- **Azure Functions**: Python v2 programming model
- **Python**: Versions 3.7–3.12 compatible
- **Azure SDKs**: `azure-identity`, `azure-mgmt-resource`, `azure-mgmt-security`, `azure-mgmt-monitor`
- **Azure Services**: Storage Accounts, Defender for Storage, Log Analytics, Managed Identity, Application Insights
- **Local Development**: Azure Functions Core Tools, Azurite

---

## Prerequisites

- Python 3.7–3.12
- Azure Functions Core Tools
- Azurite (emulator for Azure Storage)
- Azure CLI (`az login`)
- Git

---

## Project Structure

```bash
├── .gitignore
├── host.json
├── local.settings.json       # (gitignored; see example below)
├── local.settings.example.json
├── requirements.txt
├── function_app.py           # Function entry point (Timer + HTTP triggers)
└── azure_defender_tool/      # Core library package
    ├── __init__.py
    ├── config.py            # Configuration loader
    ├── logger_config.py     # Logging setup
    ├── azure_utils.py       # Azure SDK helper functions
    ├── compliance.py        # Compliance check logic
    ├── remediation.py       # Remediation logic
    └── main.py              # Orchestrator for triggers
```

---

## Configuration

Configuration is managed via environment variables. For local testing, set these in `local.settings.json` (gitignored). In Azure, configure via Function App Application Settings.

### Required Settings

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "<Storage Account connection string>",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_SUBSCRIPTION_ID": "<subscription-id>",
    "AZURE_RESOURCE_GROUP": "<resource-group-name>",
    "TARGET_STORAGE_ACCOUNTS": "acct1,acct2,acct3",  
    "WORKSPACE_ID": "/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/...",
    "REMEDIATION_ENABLED": "true"
  }
}
```

### Optional Settings

- `SECURITY_API_VERSION`: Override default API version for security calls (e.g., `2023-01-01`).

---

## Setup & Local Execution

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/azure-storage-compliance-checker.git
   cd azure-storage-compliance-checker
   ```

2. **Create and activate a Python virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate    # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure local settings**
   ```bash
   cp local.settings.example.json local.settings.json
   # Update values in local.settings.json
   ```

5. **Start Azurite storage emulator**
   ```bash
   func azure storage start    # Or use Azurite CLI
   ```

6. **Authenticate with Azure**
   ```bash
   az login
   ```

7. **Run the Function App locally**
   - **VS Code**: Press F5 and select "Attach to Python Functions".
   - **CLI**:
     ```bash
     func start
     ```

8. **Trigger the HTTP function**
   - Open your browser or use `curl`:
     ```bash
     curl http://localhost:7071/api/runComplianceCheck
     ```

9. **View logs**
   Logs are printed to the terminal and are forwarded to Application Insights if configured.

---

## Deployment

1. **Publish to Azure**
   ```bash
   func azure functionapp publish <FunctionAppName>
   ```
   Or use the [Azure Functions VS Code extension]

2. **Configure Application Settings** in the Azure Portal
   - Ensure `AzureWebJobsStorage` is a valid connection string
   - Set other required environment variables (see Configuration)

3. **Assign Managed Identity Permissions**
   - **Reader** on the target Storage Accounts
   - If `REMEDIATION_ENABLED=true`, grant additional write permissions (e.g., `Storage Account Contributor`, `Monitoring Metrics Publisher`)

---

## Remediation Note

Enabling remediation (`REMEDIATION_ENABLED=true`) allows the Function App to modify storage account settings. Ensure the Managed Identity has appropriate permissions, and use with caution in production environments.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

