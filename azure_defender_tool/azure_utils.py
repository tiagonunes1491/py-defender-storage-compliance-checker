# azure_defender_tool/azure_utils.py
"""Provides utility functions for Azure interactions."""

import os
import logging

# Get a logger specific to this module
logger = logging.getLogger(__name__)

def get_current_subscription_id():
    """Retrieves the Azure Subscription ID for the execution environment."""
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