import os
import sys
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from dotenv import load_dotenv
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings


#Script handler

logging.basicConfig(level=logging.ERROR, format='[%(levelname)s] %(name)s: %(message)s')

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
    # Ues WEBSITE_OWNER_ID to try and retrieve azure subscription, format : {SubscriptionID}+{AppServicePlanResourceGroupName}-{RegionName}
    # Correct AZ SUB ID is expected to be 36 digits.
    # Tries to retrive subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID") in first place to allow override.
    subscription_id = None
    if os.environ.get("AZURE_SUBSCRIPTION_ID"):
        subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        logger.info("Retrieving Azure Subscription ID from AZURE_SUBSCRIPTION_ID variable")
    elif os.environ.get("WEBSITE_OWNER_NAME"):
        try:
            subscription_id = os.environ.get("WEBSITE_OWNER_NAME").split('+')[0]
            logger.info("Trying to retrieve Azure Subscription ID from WEBSITE_OWNER_NAME variable")
        except Exception as e:
            logger.error(f'There was an issue while parsing subscription ID from WEBSITE_OWNER_NAME variable. {e}')

    if subscription_id and len(subscription_id) == 36:
        return subscription_id
    else:
        logger.error(f"Not a valid subscription ID. {subscription_id}")
        return None
       
def remediation_orchestrator(security_client, defender_settings, monitor_client, resource, check_results, expected_workspace_id):
    if not check_results["Defender_for_storage_enabled"] or not check_results["Override_enabled"] or not check_results["Malware_scanning_on_upload"]:
        setting_name = "current"
              
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
            LogSettings(category="ScanResults", enabled=True)
        ]

        desired_setting_payload = DiagnosticSettingsResource(
            workspace_id=expected_workspace_id,
            logs=logs_to_send,
            metrics=[] 
        )
        diagnostic_setting_name = "service"
        try:
            monitor_client.diagnostic_settings.create_or_update(
                    resource_uri=defender_setting_resource_id,
                    name=diagnostic_setting_name,            
                    parameters=desired_setting_payload       

            )
            logger.warn(f"  -> Remediated for Defender for Storage settings to enable workspace.")
        except Exception as e:
            logger.error(f"  -> Update for Defender for Storage diagnostic settings failed. {e}")

def check_compliance(security_client, monitor_client, resource, expected_workspace_id):
    check_results = {
        "Defender_for_storage_enabled": None,
        "Override_enabled": None,
        "Malware_scanning_on_upload": None,
        "WorkspaceID": None
    }
    logger.info(f"  -> Checking compliance for target account: {resource.name}")

    try:
        defender_setting = security_client.defender_for_storage.get(resource_id=resource.id,
                                                                setting_name="current")
        
        check_results["Defender_for_storage_enabled"] = defender_setting.is_enabled_properties_is_enabled
        check_results["Override_enabled"] = defender_setting.override_subscription_level_settings
        check_results["Malware_scanning_on_upload"] = defender_setting.is_enabled_properties_malware_scanning_on_upload_is_enabled
        
        defender_setting_resource_id = f"{resource.id}/providers/Microsoft.Security/DefenderForStorageSettings/current"
        diagnostic_setting_name = "service"

        try:
            diagnostic_setting = monitor_client.diagnostic_settings.get(
                resource_uri=defender_setting_resource_id,
                name=diagnostic_setting_name
            )

            check_results["WorkspaceID"] = getattr(diagnostic_setting, 'workspace_id', False) if getattr(diagnostic_setting, 'workspace_id', False) == expected_workspace_id else False

        except Exception as e:
            logger.error(f"An error occured while retrieving monitoring details for defender for storage at storage Account {resource.name} (ID: {resource.id}). {e} ")

        return check_results, diagnostic_setting, defender_setting
    except Exception as e:
            logger.error(f"An error occured while retrieving security details for storage Account {resource.name} (ID: {resource.id}). {e} ")

          


def main():
    logger.info("Function starting.")
    credential = DefaultAzureCredential()
    subscription_id = get_current_subscription_id()
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
            filter="resourceType eq 'Microsoft.Storage/storageAccounts'"
        )

    except Exception as e:
      logger.error(f"Error: Failed to retrieve Storage accounts. {e}")

    for resource in resources_iterator:
        if resource.name in set_storage_accounts:
            check_results, diagnostic_setting, defender_setting,  = check_compliance(security_client, monitor_client, resource, expected_workspace_id)
            if  all(check_results.values()):
                logger.info("  -> Compliant.")
            else:
                logger.warn("  -> Not Compliant.")
                [logger.warn(f"      -> {key}: {value}") for key, value in check_results.items() if not value ]
                if remediation_enabled:
                    remediation_orchestrator(security_client, defender_setting, monitor_client, resource, check_results, expected_workspace_id)
            
if __name__ == "__main__":
    main()