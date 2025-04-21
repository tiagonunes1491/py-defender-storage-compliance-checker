# Standard Library Imports
import logging
import os
import sys

# Third-Party Imports
from dotenv import load_dotenv
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings
from azure.mgmt.resource import ResourceManagementClient
# Import Resource type for type hinting if desired
# from azure.mgmt.resource.resources.v2022_09_01.models import GenericResourceExpanded as Resource
from azure.mgmt.security import SecurityCenter
# Import specific models needed for payload construction and type hints
from azure.mgmt.security.models import (
    DefenderForStorageSetting,
    MalwareScanningProperties,
    MalwareScanningOnUploadProperties
)

# --- Constants ---
DEFENDER_SETTING_NAME = "current"
DIAGNOSTIC_SETTING_NAME = "service"
STORAGE_ACCOUNT_TYPE = "Microsoft.Storage/storageAccounts"
LOG_CATEGORY_SCAN_RESULTS = "ScanResults"
# ---------------

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
# --- End Logger Setup ---


def get_current_subscription_id():
    """Retrieves the Azure Subscription ID for the execution environment.

    Primarily checks the 'AZURE_SUBSCRIPTION_ID' environment variable.
    As a fallback for Azure Function App environments, attempts to parse
    the ID from the 'WEBSITE_OWNER_NAME' environment variable.

    Returns:
        str | None: The 36-character Azure Subscription ID if found and valid,
                    otherwise None.
    """
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if subscription_id:
        logger.info("Using Azure Subscription ID from AZURE_SUBSCRIPTION_ID variable (recommended).")
        if len(subscription_id) == 36:
            return subscription_id
        else:
            logger.warning(f"AZURE_SUBSCRIPTION_ID value found but is not 36 characters long: '{subscription_id}'. Will attempt fallback.")
            # Fallthrough intended

    website_owner = os.environ.get("WEBSITE_OWNER_NAME")
    if website_owner:
        logger.info("Attempting to parse Subscription ID from WEBSITE_OWNER_NAME.")
        try:
            parsed_id = website_owner.split('+')[0]
            if len(parsed_id) == 36:
                logger.info("Successfully parsed Subscription ID from WEBSITE_OWNER_NAME.")
                return parsed_id
            else:
                logger.error(f"Parsed ID from WEBSITE_OWNER_NAME is not 36 characters long: '{parsed_id}'")
                return None
        except Exception as e:
             logger.error(f'Could not parse subscription ID from WEBSITE_OWNER_NAME ({website_owner}). Error: {e}')
             return None
    else:
        # Only log error if AZURE_SUBSCRIPTION_ID was also missing/invalid
        if not subscription_id:
             logger.error("Unable to determine valid Subscription ID using AZURE_SUBSCRIPTION_ID or WEBSITE_OWNER_NAME.")
        return None


def check_compliance(security_client: SecurityCenter, monitor_client: MonitorManagementClient, resource, expected_workspace_id: str) -> tuple[dict, DiagnosticSettingsResource | None, DefenderForStorageSetting | None]:
    """Checks Defender for Storage and Diagnostic settings compliance for a storage account.

    Retrieves the current Defender for Storage settings and its associated
    diagnostic settings, comparing them against expected states (enabled, override,
    malware scan, specific workspace ID). Uses safe attribute access.

    Args:
        security_client: An authenticated SecurityCenter client.
        monitor_client: An authenticated MonitorManagementClient.
        resource: The storage account resource object.
        expected_workspace_id: The resource ID of the expected Log Analytics workspace.

    Returns:
        tuple: A tuple containing:
            - dict: Compliance results (check_results) with boolean status per check.
            - DiagnosticSettingsResource | None: The retrieved diagnostic setting object,
              or None if retrieval failed or not applicable.
            - DefenderForStorageSetting | None: The retrieved defender setting object,
              or None if the initial retrieval failed critically.
              Returns (dict_all_false, None, None) on critical failure retrieving defender settings.
    """
    check_results = {
        "Defender_for_storage_enabled": False, # Default to False
        "Override_enabled": False,
        "Malware_scanning_on_upload": False,
        "WorkspaceID": False
    }
    logger.info(f"  -> Checking compliance for target account: {resource.name}")
    diagnostic_setting: DiagnosticSettingsResource | None = None
    defender_setting: DefenderForStorageSetting | None = None

    try:
        defender_setting = security_client.defender_for_storage.get(
            resource_id=resource.id,
            setting_name=DEFENDER_SETTING_NAME
        )

        # Use getattr for safe access to potentially missing attributes/nested objects
        check_results["Defender_for_storage_enabled"] = getattr(defender_setting, 'is_enabled', False)
        check_results["Override_enabled"] = getattr(defender_setting, 'override_subscription_level_settings', False)

        malware_scanning = getattr(defender_setting, 'malware_scanning', None)
        on_upload = getattr(malware_scanning, 'on_upload', None) if malware_scanning else None
        check_results["Malware_scanning_on_upload"] = getattr(on_upload, 'is_enabled', False) if on_upload else False

        # Nested try for diagnostic settings
        # Construct ID using the retrieved defender_setting ID for robustness if available
        defender_setting_resource_id = f"{getattr(defender_setting, 'id', resource.id + '/providers/Microsoft.Security/DefenderForStorageSettings/current')}"

        try:
            diagnostic_setting = monitor_client.diagnostic_settings.get(
                resource_uri=defender_setting_resource_id,
                name=DIAGNOSTIC_SETTING_NAME
            )
            retrieved_workspace_id = getattr(diagnostic_setting, 'workspace_id', None)
            check_results["WorkspaceID"] = (retrieved_workspace_id is not None and retrieved_workspace_id.lower() == expected_workspace_id.lower())

        except HttpResponseError as hre:
            if hre.status_code == 404:
                logger.warning(f"      -> Diagnostic setting '{DIAGNOSTIC_SETTING_NAME}' not found for Defender for Storage on {resource.name}.")
                # WorkspaceID remains False
            else:
                 logger.error(f"      -> Error retrieving monitoring details for {resource.name} (HTTP {hre.status_code}). {hre.message}")
            diagnostic_setting = None # Ensure None on error
            check_results["WorkspaceID"] = False # Explicitly False on error
        except Exception as e:
            logger.error(f"      -> Unexpected error retrieving monitoring details for {resource.name}. {e}")
            diagnostic_setting = None # Ensure None on error
            check_results["WorkspaceID"] = False # Explicitly False on error

        return check_results, diagnostic_setting, defender_setting

    except HttpResponseError as hre:
        if hre.status_code == 404:
            logger.warning(f"   -> Defender for Storage setting '{DEFENDER_SETTING_NAME}' not found for {resource.name}. Treating as non-compliant. {hre.message}")
        elif hre.status_code == 403:
             logger.error(f"   -> PERMISSION ERROR retrieving security details for {resource.name}. Check identity permissions. {hre.message}")
        else:
             logger.error(f"   -> HTTP ERROR {hre.status_code} retrieving security details for {resource.name}. {hre.message}")
        # Mark all checks as failed/indeterminate (already defaulted to False)
        return check_results, None, None # Return predictable tuple

    except Exception as e:
        logger.error(f"   -> UNEXPECTED ERROR retrieving security details for {resource.name}. Error: {e}")
        # Mark all checks as failed/indeterminate (already defaulted to False)
        return check_results, None, None # Return predictable tuple


def remediation_orchestrator(security_client: SecurityCenter, defender_setting: DefenderForStorageSetting, monitor_client: MonitorManagementClient, resource, check_results: dict, expected_workspace_id: str) -> None:
    """Remediates non-compliant Defender for Storage and Diagnostic settings.

    Enables Defender for Storage, malware scanning, overrides subscription settings,
    and configures diagnostic settings to send scan results to the specified workspace
    if the corresponding checks in 'check_results' are False. Uses modern SDK models.

    Args:
        security_client: An authenticated SecurityCenter client.
        defender_setting: The current defender setting object retrieved earlier.
        monitor_client: An authenticated MonitorManagementClient.
        resource: The storage account resource object.
        check_results: A dictionary containing the boolean compliance results.
        expected_workspace_id: The resource ID of the target Log Analytics workspace.

    Returns:
        None: This function performs actions and logs results/errors.
    """
    # Part 1: Remediate Defender for Storage base settings if needed
    if not check_results["Defender_for_storage_enabled"] or \
       not check_results["Override_enabled"] or \
       not check_results["Malware_scanning_on_upload"]:

        logger.info(f"   -> Remediating Defender for Storage base settings for {resource.name}...")

        # --- Define the desired state explicitly using SDK models ---
        # Ensure MalwareScanning structure exists before setting nested property
        malware_scanning_config = MalwareScanningProperties(
            on_upload=MalwareScanningOnUploadProperties(is_enabled=True),
            scan_results_event_grid_topic_resource_id=getattr(getattr(defender_setting, 'malware_scanning', None), 'scan_results_event_grid_topic_resource_id', None) # Preserve existing Event Grid topic if set
        )

        desired_defender_settings = DefenderForStorageSetting(
            is_enabled=True,
            override_subscription_level_settings=True,
            malware_scanning=malware_scanning_config
            # Note: Other properties from defender_setting are not included here
            # unless explicitly needed for the update/create operation.
            # If the API requires the full object, merge with defender_setting first.
            # Assuming create only needs these core properties for update.
        )

        try:
            # Use create_or_update if available, otherwise create should work for update
            updated_setting = security_client.defender_for_storage.create(
                resource_id=resource.id,
                setting_name=DEFENDER_SETTING_NAME,
                defender_for_storage_setting=desired_defender_settings # Pass the desired payload
            )
            logger.info(f"      -> Remediated Defender for Storage base settings. New state enabled: {getattr(updated_setting, 'is_enabled', 'N/A')}")
        except HttpResponseError as hre:
             logger.error(f"      -> Update for Defender for Storage base settings failed (HTTP {hre.status_code}). {hre.message}")
        except Exception as e:
            logger.error(f"      -> Update for Defender for Storage base settings failed. {e}")

    # Part 2: Remediate Diagnostic Settings if needed
    if not check_results["WorkspaceID"]:
        logger.info(f"   -> Remediating Defender for Storage diagnostic settings for {resource.name}...")
        # Use the ID from the actual defender setting object if possible
        defender_setting_resource_id = getattr(defender_setting, 'id', f"{resource.id}/providers/Microsoft.Security/DefenderForStorageSettings/{DEFENDER_SETTING_NAME}")

        logs_to_send = [
            LogSettings(category=LOG_CATEGORY_SCAN_RESULTS, enabled=True)
        ]
        desired_diagnostic_payload = DiagnosticSettingsResource(
            workspace_id=expected_workspace_id,
            logs=logs_to_send,
            metrics=[] # Assuming no metrics needed
        )
        try:
            updated_diag = monitor_client.diagnostic_settings.create_or_update(
                resource_uri=defender_setting_resource_id,
                name=DIAGNOSTIC_SETTING_NAME,
                parameters=desired_diagnostic_payload
            )
            logger.info(f"      -> Remediated Defender for Storage diagnostic settings. Workspace ID: {getattr(updated_diag, 'workspace_id', 'N/A')}")
        except HttpResponseError as hre:
             logger.error(f"      -> Update for Defender for Storage diagnostic settings failed (HTTP {hre.status_code}). {hre.message}")
        except Exception as e:
            logger.error(f"      -> Update for Defender for Storage diagnostic settings failed. {e}")


def main():
    """Main execution function.

    Initializes Azure clients, reads configuration from environment variables,
    iterates through specified storage accounts in a target resource group,
    checks their Defender for Storage compliance, and triggers remediation
    if enabled and necessary.
    """
    load_dotenv() # Load .env file first if present
    logger.info("Function starting.")

    # --- Get Subscription ID ---
    subscription_id = get_current_subscription_id()
    if not subscription_id:
        logger.critical("Azure Subscription ID could not be determined. Exiting.")
        sys.exit(1)
    logger.info(f"Using Subscription ID: {subscription_id}")

    # --- Get Configuration from Environment ---
    logger.info("Loading configuration from environment variables...")
    resource_group_name = os.environ.get("AZURE_RESOURCE_GROUP")
    remediation_enabled_str = os.environ.get("REMEDIATON_ENABLED", "false") # Default to false
    storage_accounts_str = os.environ.get("TARGET_STORAGE_ACCOUNTS")
    expected_workspace_id = os.environ.get("WORKSPACE_ID")

    # --- Validate Essential Configuration ---
    missing_vars = []
    if not resource_group_name: missing_vars.append("AZURE_RESOURCE_GROUP")
    if not storage_accounts_str: missing_vars.append("TARGET_STORAGE_ACCOUNTS")
    if not expected_workspace_id: missing_vars.append("WORKSPACE_ID")
    if missing_vars:
         logger.critical(f"Required environment variables missing: {', '.join(missing_vars)}. Exiting.")
         sys.exit(1)

    try:
        set_storage_accounts = set(name.strip().lower() for name in storage_accounts_str.split(',') if name.strip()) # Normalize to lower case
        remediation_enabled = remediation_enabled_str.lower() == "true"
    except Exception as e:
        logger.critical(f"Error processing configuration strings (TARGET_STORAGE_ACCOUNTS / REMEDIATON_ENABLED): {e}. Exiting.")
        sys.exit(1)

    logger.info(f"Target Resource Group: {resource_group_name}")
    logger.info(f"Target Storage Accounts (lower case): {', '.join(set_storage_accounts)}")
    logger.info(f"Remediation Enabled: {remediation_enabled}")
    logger.info(f"Expected Workspace ID: {expected_workspace_id}")

    # --- Initialize Azure Clients ---
    try:
        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)
        security_client = SecurityCenter(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        logger.info("Azure clients initialized successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize Azure clients. Check credentials/permissions. Error: {e}")
        sys.exit(1)

    # --- List Resources ---
    resources_iterator = [] # Initialize to prevent potential UnboundLocalError
    try:
        logger.info(f"Listing storage accounts in resource group '{resource_group_name}'...")
        resources_iterator = resource_client.resources.list_by_resource_group(
            resource_group_name,
            filter=f"resourceType eq '{STORAGE_ACCOUNT_TYPE}'"
        )
    except HttpResponseError as hre:
         logger.critical(f"CRITICAL ERROR: Failed to list resources (HTTP {hre.status_code}). Check permissions for RG '{resource_group_name}'. {hre.message}")
         sys.exit(1)
    except Exception as e:
        logger.critical(f"CRITICAL ERROR: Failed to list resources. Error: {e}")
        sys.exit(1)

    # --- Process Resources ---
    logger.info("Starting compliance check and remediation loop...")
    processed_count = 0
    target_found_count = 0

    for resource in resources_iterator:
        # Normalize resource name to lower case for comparison
        resource_name_lower = resource.name.lower()
        if resource_name_lower in set_storage_accounts:
            target_found_count += 1
            logger.info(f"Processing target account: {resource.name} (ID: {resource.id})")
            check_results, diagnostic_setting, defender_setting = check_compliance(
                security_client, monitor_client, resource, expected_workspace_id
            )

            # Check if base settings could be retrieved
            if defender_setting is None:
                logger.warning(f"   -> Skipping further checks and remediation for {resource.name} due to errors retrieving its settings.")
                continue

            # Log compliance status and details
            if all(check_results.values()):
                logger.info("   -> Compliant.")
            else:
                logger.warning("   -> Not Compliant.")
                # Use standard loop for logging details
                for key, value in check_results.items():
                    if not value:
                        logger.warning(f"        -> {key}: {value}")

                # Trigger remediation if enabled and not compliant
                if remediation_enabled:
                    remediation_orchestrator(
                        security_client,
                        defender_setting, # Pass original object
                        monitor_client,
                        resource,
                        check_results,
                        expected_workspace_id
                    )
            processed_count += 1 # Count successful checks/remediations

    # --- Summary Logging ---
    logger.info(f"Finished processing loop.")
    logger.info(f"Found and processed {target_found_count} out of {len(set_storage_accounts)} target account(s) in the resource group.")
    if target_found_count < len(set_storage_accounts):
        logger.warning(f"Could not find all target accounts in resource group '{resource_group_name}'. Verify TARGET_STORAGE_ACCOUNTS and resource group.")
    logger.info(f"Script finished.")


if __name__ == "__main__":
    main()