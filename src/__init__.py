# Standard Library Imports
import logging
import os
import sys

# Third-Party Imports 
from dotenv import load_dotenv
from azure.core.exceptions import HttpResponseError # Example for specific exceptions
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import DefenderForStorageSetting # If used for type hints/payload

# Local Imports 
# from . import my_local_module

# --- Constants ---
DEFENDER_SETTING_NAME = "current"
DIAGNOSTIC_SETTING_NAME = "service"
STORAGE_ACCOUNT_TYPE = "Microsoft.Storage/storageAccounts"
LOG_CATEGORY_SCAN_RESULTS = "ScanResults"

#Script handler

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
        logger.error("Unable to determine valid Subscription ID using AZURE_SUBSCRIPTION_ID or WEBSITE_OWNER_NAME.")
        return None
       
def remediation_orchestrator(security_client, defender_settings, monitor_client, resource, check_results, expected_workspace_id):
    """Remediates non-compliant Defender for Storage and Diagnostic settings.

    Enables Defender for Storage, malware scanning, overrides subscription settings,
    and configures diagnostic settings to send scan results to the specified workspace
    if the corresponding checks in 'check_results' are False.

    Args:
        security_client (SecurityCenter): An authenticated SecurityCenter client.
        defender_setting (DefenderForStorageSetting): The current defender setting
            object retrieved earlier (will be modified in place).
        monitor_client (MonitorManagementClient): An authenticated MonitorManagementClient.
        resource (Resource): The storage account resource object.
        check_results (dict): A dictionary containing the boolean compliance results.
        expected_workspace_id (str): The resource ID of the target Log Analytics workspace.

    Returns:
        None: This function performs actions and logs results/errors; it doesn't
              return a value.
    """
    if not check_results["Defender_for_storage_enabled"] or not check_results["Override_enabled"] or not check_results["Malware_scanning_on_upload"]:
        setting_name = DEFENDER_SETTING_NAME
              
        defender_settings.is_enabled_properties_is_enabled = True
        defender_settings.override_subscription_level_settings = True
        defender_settings.is_enabled_properties_malware_scanning_on_upload_is_enabled = True

        try: 
            security_client.defender_for_storage.create(
                resource_id=resource.id, 
                setting_name=setting_name,
                defender_for_storage_setting=defender_settings
            )
            logger.info(f"  -> Remediated for Defender for Storage settings to override, enable plan and enable malware scan.")
        except Exception as e:
            logger.error(f"  -> Update for Defender for Storage settings failed. {e}")
        
    if not check_results["WorkspaceID"]:
        defender_setting_resource_id = f"{resource.id}/providers/Microsoft.Security/DefenderForStorageSettings/current"
        logs_to_send = [
            LogSettings(category=LOG_CATEGORY_SCAN_RESULTS, enabled=True)
        ]

        desired_setting_payload = DiagnosticSettingsResource(
            workspace_id=expected_workspace_id,
            logs=logs_to_send,
            metrics=[] 
        )
        diagnostic_setting_name = DIAGNOSTIC_SETTING_NAME
        try:
            monitor_client.diagnostic_settings.create_or_update(
                    resource_uri=defender_setting_resource_id,
                    name=diagnostic_setting_name,            
                    parameters=desired_setting_payload       

            )
            logger.warning(f"  -> Remediated for Defender for Storage settings to enable workspace.")
        except Exception as e:
            logger.error(f"  -> Update for Defender for Storage diagnostic settings failed. {e}")

def check_compliance(security_client, monitor_client, resource, expected_workspace_id):
    """Checks Defender for Storage and Diagnostic settings compliance for a storage account.

    Retrieves the current Defender for Storage settings and its associated
    diagnostic settings, comparing them against expected states (enabled, override,
    malware scan, specific workspace ID).

    Args:
        security_client (SecurityCenter): An authenticated SecurityCenter client.
        monitor_client (MonitorManagementClient): An authenticated MonitorManagementClient.
        resource (Resource): The storage account resource object.
        expected_workspace_id (str): The resource ID of the expected Log Analytics workspace.

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
        "Defender_for_storage_enabled": None,
        "Override_enabled": None,
        "Malware_scanning_on_upload": None,
        "WorkspaceID": None
    }
    logger.info(f"  -> Checking compliance for target account: {resource.name}")

    try:
        defender_setting = security_client.defender_for_storage.get(resource_id=resource.id,
                                                                setting_name=DEFENDER_SETTING_NAME)
        
        check_results["Defender_for_storage_enabled"] = defender_setting.is_enabled_properties_is_enabled
        check_results["Override_enabled"] = defender_setting.override_subscription_level_settings
        check_results["Malware_scanning_on_upload"] = defender_setting.is_enabled_properties_malware_scanning_on_upload_is_enabled
        
        defender_setting_resource_id = f"{resource.id}/providers/Microsoft.Security/DefenderForStorageSettings/current"
        diagnostic_setting_name = DIAGNOSTIC_SETTING_NAME

        try:
            diagnostic_setting = monitor_client.diagnostic_settings.get(
                resource_uri=defender_setting_resource_id,
                name=diagnostic_setting_name
            )

            check_results["WorkspaceID"] = getattr(diagnostic_setting, 'workspace_id', False) if getattr(diagnostic_setting, 'workspace_id', False) == expected_workspace_id else False

        except Exception as e:
            logger.error(f"An error occured while retrieving monitoring details for defender for storage at storage Account {resource.name} (ID: {resource.id}). {e} ")
            diagnostic_setting = None
            check_results["WorkspaceID"] = False

        return check_results, diagnostic_setting, defender_setting
    except Exception as e:
            logger.error(f"An error occured while retrieving security details for storage Account {resource.name} (ID: {resource.id}). {e} ")
            # Mark all checks as failed/indeterminate
            check_results = {key: False for key in check_results}
            return check_results, None, None # Return predictable tuple

          


def main():
    """Main execution function.

    Initializes Azure clients, reads configuration from environment variables,
    iterates through specified storage accounts in a target resource group,
    checks their Defender for Storage compliance, and triggers remediation
    if enabled and necessary.
    """
    logger.info("Function starting.")
    credential = DefaultAzureCredential()
    load_dotenv()
    subscription_id = get_current_subscription_id()
    if not subscription_id:
        logger.critical("Azure Subscription ID could not be determined. Exiting.") # Use critical for fatal errors
        sys.exit(1) # Exit the script
    resource_client = ResourceManagementClient(credential, subscription_id)
    security_client = SecurityCenter(credential, subscription_id)
    monitor_client = MonitorManagementClient(credential, subscription_id)
    resource_group_name = os.environ.get("AZURE_RESOURCE_GROUP")
    remediation_enabled_str = os.environ.get("REMEDIATON_ENABLED")
    storage_accounts_str = os.environ.get("TARGET_STORAGE_ACCOUNTS")
    expected_workspace_id = os.environ.get("WORKSPACE_ID") 
    set_storage_accounts = set(name.strip() for name in storage_accounts_str.split(',') if name.strip())
    remediation_enabled = remediation_enabled_str.lower() == "true"
    logger.info(f"Remediation Enabled: {remediation_enabled}")
    logger.info(f"Resource Group: {resource_group_name}")

    try:     
        resources_iterator = resource_client.resources.list_by_resource_group(
            resource_group_name, 
            filter=f"resourceType eq '{STORAGE_ACCOUNT_TYPE}'"
        )

    except Exception as e:
      logger.error(f"Error: Failed to retrieve Storage accounts. {e}")

    for resource in resources_iterator:
        if resource.name in set_storage_accounts:
            check_results, diagnostic_setting, defender_setting  = check_compliance(security_client, monitor_client, resource, expected_workspace_id)
            # If defender_setting is None, it implies the main try block in check_compliance failed.
            if defender_setting is None:
                logger.warning(f"   -> Skipping further checks and remediation for {resource.name} due to errors retrieving its basic settings.")
                continue # Skip to the next resource in the loop
            if  all(check_results.values()):
                logger.info("  -> Compliant.")
            else:
                logger.warning("  -> Not Compliant.")
                [logger.warning(f"      -> {key}: {value}") for key, value in check_results.items() if not value ]
                if remediation_enabled:
                    remediation_orchestrator(security_client, defender_setting, monitor_client, resource, check_results, expected_workspace_id)
            
if __name__ == "__main__":
    main()