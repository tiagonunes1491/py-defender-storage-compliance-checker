# azure_defender_tool/compliance.py
"""Handles compliance checks for Azure Defender for Storage settings."""

import logging
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient
# Assuming these specific exception types are needed here
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
# Import constants using relative path
from .config import DEFENDER_SETTING_NAME, DIAGNOSTIC_SETTING_NAME

# Get a logger specific to this module
logger = logging.getLogger(__name__)

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
        # --- प्रिजर्व्ड ऐट्रिब्यूट ऐक्सेस ---
        check_results["Defender_for_storage_enabled"] = getattr(defender_setting, 'is_enabled_properties_is_enabled', False)
        check_results["Override_enabled"] = getattr(defender_setting, 'override_subscription_level_settings', False)
        check_results["Malware_scanning_on_upload"] = getattr(defender_setting, 'is_enabled_properties_malware_scanning_on_upload_is_enabled', False)
        # --- End Preserved Attribute Access ---

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
             logger.info(f"Diagnostic setting '{diagnostic_setting_name}' not found for Defender for Storage on {resource_name}.")
             check_results["WorkspaceID"] = False
             diagnostic_setting = None # Ensure it's None if not found
        except Exception as e:
            logger.error(f"Error retrieving diagnostic setting for {resource_name}: {e}")
            check_results["WorkspaceID"] = False
            diagnostic_setting = None # Ensure it's None on error

        return check_results, diagnostic_setting, defender_setting

    except AttributeError as e:
         logger.error(f"Attribute error accessing expected Defender settings for {resource_name}: {e}. Please double-check the attribute names in the script vs. the object returned by the SDK.", exc_info=True)
         check_results = {key: False for key in check_results}
         return check_results, None, defender_setting
    except HttpResponseError as e:
        logger.error(f"Azure API error retrieving Defender settings for {resource_name}: {e.message}")
        check_results = {key: False for key in check_results}
        return check_results, None, None
    except Exception as e:
        logger.error(f"Unexpected error retrieving Defender settings for {resource_name} (ID: {resource_id}): {e}", exc_info=True)
        check_results = {key: False for key in check_results}
        return check_results, None, None