# Standard Library Imports
import logging
import os
import sys

# Third-Party Imports
from dotenv import load_dotenv
# Corrected: Import ResourceNotFoundError specifically if needed, otherwise just HttpResponseError
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
# --- Constraint: This import is kept exactly as requested ---
from azure.mgmt.security.models import DefenderForStorageSetting # Keep for type hints/payload
# --- End Constraint ---

# --- Constants ---
DEFENDER_SETTING_NAME = "current"
DIAGNOSTIC_SETTING_NAME = "service"
STORAGE_ACCOUNT_TYPE = "Microsoft.Storage/storageAccounts"
LOG_CATEGORY_SCAN_RESULTS = "ScanResults"

# --- Logger Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    console_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)s [%(name)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.propagate = False

# --- Helper Functions ---

def get_current_subscription_id():
    """Retrieves the Azure Subscription ID for the execution environment."""
    # ... (function remains the same as previous version) ...
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if subscription_id:
        logger.info("Using Azure Subscription ID from AZURE_SUBSCRIPTION_ID.")
        if len(subscription_id) == 36:
            return subscription_id
        else:
            logger.warning(f"AZURE_SUBSCRIPTION_ID value is not 36 characters: '{subscription_id}'. Attempting fallback.")

    website_owner = os.environ.get("WEBSITE_OWNER_NAME")
    if website_owner:
        logger.info("Attempting to parse Subscription ID from WEBSITE_OWNER_NAME.")
        try:
            parsed_id = website_owner.split('+')[0]
            if len(parsed_id) == 36:
                logger.info("Successfully parsed Subscription ID from WEBSITE_OWNER_NAME.")
                return parsed_id
            else:
                logger.error(f"Parsed ID from WEBSITE_OWNER_NAME is not 36 characters: '{parsed_id}'")
                return None
        except Exception as e:
            logger.error(f'Could not parse subscription ID from WEBSITE_OWNER_NAME ({website_owner}). Error: {e}')
            return None
    else:
        if not subscription_id: # Only log error if both methods failed
             logger.error("Unable to determine valid Subscription ID using AZURE_SUBSCRIPTION_ID or WEBSITE_OWNER_NAME.")
        return None

# --- Core Logic Functions ---

# --- check_compliance using EXACT attribute names from user's working code ---
def check_compliance(security_client: SecurityCenter, monitor_client: MonitorManagementClient, resource, expected_workspace_id: str):
    """Checks compliance using specific attribute names confirmed by user."""
    check_results = {
        "Defender_for_storage_enabled": None, # Start as None, set based on retrieved value
        "Override_enabled": None,
        "Malware_scanning_on_upload": None,
        "WorkspaceID": None
    }
    resource_name = resource.name
    resource_id = resource.id
    logger.info(f" -> Checking compliance for target account: {resource_name}")
    defender_setting = None
    diagnostic_setting = None

    try:
        # 1. Fetch Defender for Storage settings
        defender_setting = security_client.defender_for_storage.get(
            resource_id=resource.id,
            setting_name=DEFENDER_SETTING_NAME
        )

        # 2. Check settings using the exact attribute names provided by the user
        #    Using getattr for safety in case an attribute is unexpectedly missing
        check_results["Defender_for_storage_enabled"] = getattr(defender_setting, 'is_enabled_properties_is_enabled', False)
        check_results["Override_enabled"] = getattr(defender_setting, 'override_subscription_level_settings', False)
        check_results["Malware_scanning_on_upload"] = getattr(defender_setting, 'is_enabled_properties_malware_scanning_on_upload_is_enabled', False)

        # 3. Fetch associated Diagnostic settings
        defender_setting_resource_id = f"{resource.id}/providers/Microsoft.Security/DefenderForStorageSettings/current"
        diagnostic_setting_name = DIAGNOSTIC_SETTING_NAME
        try:
            diagnostic_setting = monitor_client.diagnostic_settings.get(
                resource_uri=defender_setting_resource_id,
                name=diagnostic_setting_name
            )
            # Using getattr for safety, comparing case-insensitively
            current_workspace_id = getattr(diagnostic_setting, 'workspace_id', None)
            check_results["WorkspaceID"] = (current_workspace_id is not None and current_workspace_id.lower() == expected_workspace_id.lower())

        except ResourceNotFoundError:
             # Changed log level to INFO as missing setting might be expected before remediation
             logger.info(f"Diagnostic setting '{diagnostic_setting_name}' not found for Defender for Storage on {resource_name}.")
             check_results["WorkspaceID"] = False
             diagnostic_setting = None # Ensure it's None if not found
        except Exception as e:
            logger.error(f"Error retrieving diagnostic setting for {resource_name}: {e}")
            check_results["WorkspaceID"] = False
            diagnostic_setting = None # Ensure it's None on error

        # If all checks were successful, return the retrieved objects
        return check_results, diagnostic_setting, defender_setting

    except AttributeError as e:
         # Catch if the specific attributes the user confirmed are missing
         logger.error(f"Attribute error accessing expected Defender settings for {resource_name}: {e}. Please double-check the attribute names in the script vs. the object returned by the SDK.", exc_info=True)
         check_results = {key: False for key in check_results} # Mark all as failed
         return check_results, None, defender_setting # Return potentially incomplete object
    except HttpResponseError as e:
        logger.error(f"Azure API error retrieving Defender settings for {resource_name}: {e.message}")
        check_results = {key: False for key in check_results}
        return check_results, None, None
    except Exception as e:
        logger.error(f"Unexpected error retrieving Defender settings for {resource_name} (ID: {resource_id}): {e}", exc_info=True)
        check_results = {key: False for key in check_results}
        return check_results, None, None


# --- remediation_orchestrator using EXACT attribute names from user's working code ---
def remediation_orchestrator(security_client: SecurityCenter, defender_settings: DefenderForStorageSetting, monitor_client: MonitorManagementClient, resource, check_results: dict, expected_workspace_id: str):
    """Remediates settings using specific attribute names confirmed by user."""
    storage_account_name = resource.name
    resource_id = resource.id

    # Check if Defender settings need update
    if not check_results.get("Defender_for_storage_enabled", True) or \
       not check_results.get("Override_enabled", True) or \
       not check_results.get("Malware_scanning_on_upload", True):

        logger.info(f" -> Remediating Defender for Storage plan settings for {storage_account_name}...")
        setting_name = DEFENDER_SETTING_NAME # Use constant

        try:
            # Set attributes using the exact names provided by the user
            defender_settings.is_enabled_properties_is_enabled = True
            defender_settings.override_subscription_level_settings = True
            defender_settings.is_enabled_properties_malware_scanning_on_upload_is_enabled = True

            # Attempt the update call
            security_client.defender_for_storage.create(
                resource_id=resource_id,
                setting_name=setting_name,
                defender_for_storage_setting=defender_settings
            )
            logger.info(f"    -> Remediated Defender for Storage settings for {storage_account_name}.")

        except AttributeError as e:
             # Catch if the specific attributes the user confirmed are missing during assignment
             logger.error(f"    -> Attribute error setting expected Defender attributes for {storage_account_name}: {e}. Update failed.", exc_info=True)
        except Exception as e:
            logger.error(f"    -> FAILED to update Defender for Storage settings for {storage_account_name}. Error: {e}", exc_info=True)

    # Check if Diagnostic settings need update
    if not check_results.get("WorkspaceID", True):
        logger.info(f" -> Remediating Diagnostic Setting for {storage_account_name}...")
        defender_setting_resource_id = f"{resource_id}/providers/Microsoft.Security/DefenderForStorageSettings/{DEFENDER_SETTING_NAME}" # Use constant
        diagnostic_setting_name = DIAGNOSTIC_SETTING_NAME # Use constant
        logs_to_send = [
            # Ensure category name is correct - using constant
            LogSettings(category=LOG_CATEGORY_SCAN_RESULTS, enabled=True)
            # If ScanResults is a category group, use:
            # LogSettings(category_group=LOG_CATEGORY_SCAN_RESULTS, enabled=True)
        ]
        desired_setting_payload = DiagnosticSettingsResource(
            workspace_id=expected_workspace_id,
            logs=logs_to_send,
            metrics=[] # Explicitly empty
        )
        try:
            monitor_client.diagnostic_settings.create_or_update(
                resource_uri=defender_setting_resource_id,
                name=diagnostic_setting_name,
                parameters=desired_setting_payload
            )
            # Changed level to INFO for successful remediation
            logger.info(f"    -> Remediated Diagnostic Setting for {storage_account_name} to use workspace.")
        except Exception as e:
            logger.error(f"    -> FAILED to update Diagnostic Setting for {storage_account_name}. Error: {e}", exc_info=True)


# --- Main Execution ---

def main():
    """Main execution function: Loads config, initializes clients, processes resources."""
    logger.info("Script starting.")
    load_dotenv()

    # --- Configuration Loading and Validation ---
    logger.info("Loading configuration from environment variables...")
    subscription_id = get_current_subscription_id()
    resource_group_name = os.environ.get("AZURE_RESOURCE_GROUP")
    remediation_enabled_str = os.environ.get("REMEDIATION_ENABLED", "false") # Default to false
    storage_accounts_str = os.environ.get("TARGET_STORAGE_ACCOUNTS")
    expected_workspace_id = os.environ.get("WORKSPACE_ID")
    # Optional: Allow specifying API version via environment variable if needed
    security_api_version = os.environ.get("SECURITY_API_VERSION") # No default, let SDK decide unless specified

    missing_vars = []
    if not subscription_id: missing_vars.append("AZURE_SUBSCRIPTION_ID (or WEBSITE_OWNER_NAME)")
    if not resource_group_name: missing_vars.append("AZURE_RESOURCE_GROUP")
    if not storage_accounts_str: missing_vars.append("TARGET_STORAGE_ACCOUNTS")
    if not expected_workspace_id: missing_vars.append("WORKSPACE_ID")
    # REMEDIATION_ENABLED has a default, no need to check if missing

    if missing_vars:
        logger.critical(f"Missing required configuration: {', '.join(missing_vars)}. Exiting.")
        sys.exit(1)

    try:
        set_storage_accounts = set(name.strip() for name in storage_accounts_str.split(',') if name.strip())
        if not set_storage_accounts:
            raise ValueError("TARGET_STORAGE_ACCOUNTS cannot be empty.")
    except Exception as e:
        logger.critical(f"Invalid TARGET_STORAGE_ACCOUNTS format: {e}. Exiting.")
        sys.exit(1)

    remediation_enabled = remediation_enabled_str.lower() == "true"

    logger.info(f"Subscription ID determined: {'*' * (len(subscription_id) - 4)}{subscription_id[-4:]}")
    logger.info(f"Resource Group: {resource_group_name}")
    logger.info(f"Target Storage Accounts: {', '.join(sorted(list(set_storage_accounts)))}")
    logger.info(f"Expected Workspace ID: {expected_workspace_id}")
    logger.info(f"Remediation Enabled: {remediation_enabled}")
    if security_api_version:
        logger.info(f"Using Security API Version (optional): {security_api_version}")
    logger.info("Configuration loaded successfully.")

    # --- Azure Client Initialization ---
    logger.info("Initializing Azure clients...")
    try:
        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)
        # Initialize SecurityCenter client - optionally with specified API version
        if security_api_version:
             security_client = SecurityCenter(credential, subscription_id, api_version=security_api_version)
        else:
             security_client = SecurityCenter(credential, subscription_id) # Use SDK default
        monitor_client = MonitorManagementClient(credential, subscription_id)
        logger.info("Azure clients initialized successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize Azure clients: {e}. Exiting.")
        sys.exit(1)

    # --- Process Storage Accounts ---
    processed_accounts_count = 0
    target_accounts_found_count = 0
    logger.info(f"Starting processing for storage accounts in resource group '{resource_group_name}'...")
    try:
        resources_iterator = resource_client.resources.list_by_resource_group(
            resource_group_name,
            filter=f"resourceType eq '{STORAGE_ACCOUNT_TYPE}'"
        )

        for resource in resources_iterator:
            if resource.name in set_storage_accounts:
                target_accounts_found_count += 1
                logger.info(f"Processing target account: {resource.name} (ID: {resource.id})...")

                # Use the check_compliance function which now uses the user-confirmed attributes
                check_results, _, defender_setting = check_compliance(
                    security_client, monitor_client, resource, expected_workspace_id
                )

                # If defender_setting is None, indicates a critical failure during check_compliance get call
                if defender_setting is None and not any(check_results.values()):
                    logger.warning(f" -> Skipping {resource.name} due to critical errors during compliance check (API/Auth issue?).")
                    continue

                # Check if any compliance checks actually returned None (indicating an issue reading attributes)
                if None in check_results.values():
                     logger.warning(f" -> Skipping {resource.name} due to inability to read all compliance attributes (Attribute Error?).")
                     continue


                is_compliant = all(value is True for value in check_results.values()) # Explicitly check for True

                if is_compliant:
                    logger.info(f" -> {resource.name} is Compliant.")
                else:
                    logger.warning(f" -> {resource.name} is NOT Compliant.")
                    for check_item, status in check_results.items():
                        # Log failed or indeterminate checks
                        if status is not True:
                            logger.warning(f"    - {check_item}: {status}") # Log the actual status (False or None)

                    if remediation_enabled:
                         # Ensure defender_setting object exists before passing to remediation
                         if defender_setting:
                            remediation_orchestrator(
                                security_client, defender_setting, monitor_client,
                                resource, check_results, expected_workspace_id
                            )
                         else:
                              logger.error(f" -> Cannot remediate {resource.name}: Defender Settings object is missing or invalid.")
                    else:
                        logger.info(f" -> Remediation is disabled. No changes made for {resource.name}.")
                processed_accounts_count += 1

    except HttpResponseError as e:
         logger.error(f"Azure API error during resource listing or processing in RG '{resource_group_name}': {e.message}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during main processing loop: {e}", exc_info=True)

    # --- Final Summary ---
    logger.info("Processing finished.")
    if target_accounts_found_count < len(set_storage_accounts):
         logger.warning(f"Found {target_accounts_found_count} of the {len(set_storage_accounts)} target storage account(s) in resource group '{resource_group_name}'.")
    elif target_accounts_found_count == 0 and set_storage_accounts:
         logger.warning(f"No storage accounts matching the target list were found in resource group '{resource_group_name}'.")

    logger.info(f"Successfully attempted processing for {processed_accounts_count} target storage account(s).") # Changed phrasing slightly
    logger.info("Script finished.")


# --- Script Entry Point ---
if __name__ == "__main__":
    main()