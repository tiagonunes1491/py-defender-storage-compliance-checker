# azure_defender_tool/remediation.py
"""Handles remediation of non-compliant Azure Defender for Storage settings."""

import logging
from azure.mgmt.security import SecurityCenter
# Import specific models needed for payload creation/type hints
from azure.mgmt.security.models import DefenderForStorageSetting
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings
# Import constants using relative path
from .config import DEFENDER_SETTING_NAME, DIAGNOSTIC_SETTING_NAME, LOG_CATEGORY_SCAN_RESULTS

# Get a logger specific to this module
logger = logging.getLogger("AzureDefenderTool")

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
            # --- End Preserved Attribute Access ---

            # Attempt the update call
            security_client.defender_for_storage.create(
                resource_id=resource_id,
                setting_name=setting_name,
                defender_for_storage_setting=defender_settings
            )
            logger.info(f"    -> Remediated Defender for Storage settings for {storage_account_name}.")

        except AttributeError as e:
             logger.error(f"    -> Attribute error setting expected Defender attributes for {storage_account_name}: {e}. Update failed.", exc_info=True)
        except Exception as e:
            logger.error(f"    -> FAILED to update Defender for Storage settings for {storage_account_name}. Error: {e}", exc_info=True)

    # Check if Diagnostic settings need update
    if not check_results.get("WorkspaceID", True):
        logger.info(f" -> Remediating Diagnostic Setting for {storage_account_name}...")
        # Use constants for resource IDs/names
        defender_setting_resource_id = f"{resource_id}/providers/Microsoft.Security/DefenderForStorageSettings/{DEFENDER_SETTING_NAME}"
        diagnostic_setting_name = DIAGNOSTIC_SETTING_NAME
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
            logger.info(f"    -> Remediated Diagnostic Setting for {storage_account_name} to use workspace.")
        except Exception as e:
            logger.error(f"    -> FAILED to update Diagnostic Setting for {storage_account_name}. Error: {e}", exc_info=True)