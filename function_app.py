# function_app.py
import azure.functions as func
import logging
import os
import datetime

# Import the main function from your existing main module
try:
    # Assuming function_app.py is in the same parent directory as the azure_defender_tool package
    # If function_app.py is in the root and azure_defender_tool is in src/, adjust the import
    from azure_defender_tool.main import main as run_compliance_core_logic
except ImportError as e:
    logging.critical(f"CRITICAL: Failed to import core logic from azure_defender_tool.main. Check structure/path. Error: {e}")
    # Allow host to start but functions will fail until import is fixed
    run_compliance_core_logic = None

# --- Initialize Function App (Module Level) ---
app = func.FunctionApp()

# --- Setup Logger for this file ---
# Get logger named after this module (__main__ when run by host if entry is here)
# Relies on configuration done within run_compliance_core_logic or by Functions Host
logger = logging.getLogger("AzureDefenderTool")
logger.info("Function App definition loading.")
# Optional: Silence noisy SDK loggers here if not done elsewhere
# logging.getLogger("azure.identity").setLevel(logging.WARNING)
# logging.getLogger("azure.core").setLevel(logging.WARNING)

# --- Timer Trigger Definition ---
@app.schedule(schedule="0 0 4 * * *", # Example: 4 AM UTC daily - ADJUST AS NEEDED
              arg_name="myTimer", run_on_startup=False, use_monitor=True)
def timer_trigger_compliance_check(myTimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if myTimer.past_due:
        logger.warning('The timer is past due!') # Use Warning
    logger.info(f'Timer trigger function started at {utc_timestamp}')

    if run_compliance_core_logic:
        try:
            # Call the main logic imported from main.py
            success = run_compliance_core_logic() # Assumes main() returns True/False
            if success:
                 logger.info(f'Core compliance logic finished successfully.')
            else:
                 logger.error(f'Core compliance logic finished with errors.')
        except Exception as e:
            logger.critical(f"Critical error during core logic execution triggered by timer: {e}", exc_info=True)
    else:
        logger.critical("Core logic function not imported correctly. Cannot run.")

    logger.info(f'Timer trigger function finished execution at {datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()}.')

# --- Optional: HTTP Trigger Definition (for testing) ---
@app.route(route="runComplianceCheck", auth_level=func.AuthLevel.FUNCTION) # FUNCTION level is safer
def http_trigger_compliance_check(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('HTTP trigger received request to run compliance check.')

    if run_compliance_core_logic:
        try:
            success = run_compliance_core_logic() # Call the same core logic
            if success:
                return func.HttpResponse(
                    "Compliance check execution finished successfully. Check logs.",
                    status_code=200
                )
            else:
                 return func.HttpResponse(
                    "Compliance check execution finished with errors. Check logs.",
                    status_code=500 # Internal Server Error might be appropriate
                )
        except Exception as e:
            logger.critical(f"HTTP triggered check failed unexpectedly: {e}", exc_info=True)
            return func.HttpResponse(
                 f"Internal server error during execution. Check logs. Error: {e}",
                 status_code=500
            )
    else:
        logger.critical("Core logic function not imported correctly. Cannot run.")
        return func.HttpResponse(
                 "Internal server error: Core logic module failed to import.",
                 status_code=500
            )