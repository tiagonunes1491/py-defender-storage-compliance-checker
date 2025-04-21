# azure_defender_tool/main.py
"""Main script execution and orchestration."""

# Standard Library Imports
import logging
import os
import sys

# Third-Party Imports
from dotenv import load_dotenv
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient

# Local Imports from the 'azure_defender_tool' package
from .config import STORAGE_ACCOUNT_TYPE # Import necessary constants
from .logger_config import setup_logger
from .azure_utils import get_current_subscription_id
from .compliance import check_compliance
from .remediation import remediation_orchestrator

# Setup logger for this main module
# Note: Call setup_logger early, before other modules might try to log.
logger = setup_logger("AzureDefenderTool") # Use a root name for the tool

def main():
    """Main execution function: Loads config, initializes clients, processes resources."""
    logger.info("Script starting.")
    if os.environ.get("FUNCTIONS_WORKER_RUNTIME") is None:
        from dotenv import load_dotenv
        logger.info("Not in Azure Functions environment, loading .env file.")
        load_dotenv()

    # --- Configuration Loading and Validation ---
    logger.info("Loading configuration from environment variables...")
    subscription_id = get_current_subscription_id() # From azure_utils
    resource_group_name = os.environ.get("AZURE_RESOURCE_GROUP")
    remediation_enabled_str = os.environ.get("REMEDIATION_ENABLED", "false") # Default to false
    storage_accounts_str = os.environ.get("TARGET_STORAGE_ACCOUNTS")
    expected_workspace_id = os.environ.get("WORKSPACE_ID")
    security_api_version = os.environ.get("SECURITY_API_VERSION") # Optional API version

    missing_vars = []
    if not subscription_id: missing_vars.append("AZURE_SUBSCRIPTION_ID (or WEBSITE_OWNER_NAME)")
    if not resource_group_name: missing_vars.append("AZURE_RESOURCE_GROUP")
    if not storage_accounts_str: missing_vars.append("TARGET_STORAGE_ACCOUNTS")
    if not expected_workspace_id: missing_vars.append("WORKSPACE_ID")

    if missing_vars:
        logger.critical(f"Missing required configuration: {', '.join(missing_vars)}. Exiting.")
        return False

    try:
        set_storage_accounts = set(name.strip() for name in storage_accounts_str.split(',') if name.strip())
        if not set_storage_accounts:
            raise ValueError("TARGET_STORAGE_ACCOUNTS cannot be empty.")
    except Exception as e:
        logger.critical(f"Invalid TARGET_STORAGE_ACCOUNTS format: {e}. Exiting.")
        return False

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
        # Use constant from config
        resources_iterator = resource_client.resources.list_by_resource_group(
            resource_group_name,
            filter=f"resourceType eq '{STORAGE_ACCOUNT_TYPE}'"
        )

        for resource in resources_iterator:
            if resource.name in set_storage_accounts:
                target_accounts_found_count += 1
                logger.info(f"Processing target account: {resource.name} (ID: {resource.id})...")

                # Call imported functions
                check_results, _, defender_setting = check_compliance(
                    security_client, monitor_client, resource, expected_workspace_id
                )

                if defender_setting is None and not any(check_results.values()):
                    logger.warning(f" -> Skipping {resource.name} due to critical errors during compliance check (API/Auth issue?).")
                    continue
                if None in check_results.values():
                    logger.warning(f" -> Skipping {resource.name} due to inability to read all compliance attributes (Attribute Error?).")
                    continue

                is_compliant = all(value is True for value in check_results.values())

                if is_compliant:
                    logger.info(f" -> {resource.name} is Compliant.")
                else:
                    logger.warning(f" -> {resource.name} is NOT Compliant.")
                    for check_item, status in check_results.items():
                        if status is not True:
                            logger.warning(f"    - {check_item}: {status}")

                    if remediation_enabled:
                         if defender_setting:
                            # Call imported function
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

    logger.info(f"Successfully attempted processing for {processed_accounts_count} target storage account(s).")
    logger.info("Script finished.")
    return True