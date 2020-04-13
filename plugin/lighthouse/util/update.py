import re
import json
import logging
import threading
import urllib.request

logger = logging.getLogger("Lighthouse.Util.Update")

UPDATE_URL = "https://api.github.com/repos/gaasedelen/lighthouse/releases/latest"
update_checked = False

def check_for_update(current_version, callback):
    """
    Perform a plugin update check.
    """
    global update_checked

    # only ever perform the update check once per session...
    if update_checked:
        return

    update_thread = threading.Thread(
        target=async_update_check,
        args=(current_version, callback,),
        name="UpdateChecker"
    )
    update_thread.start()

    # burn the update checking code
    update_checked = True

def async_update_check(current_version, callback):
    """
    An async worker thread to check for an plugin update.
    """
    logger.debug("Checking for update...")

    try:
        response = urllib.request.urlopen(UPDATE_URL, timeout=5.0)
        html = response.read()
        info = json.loads(html)
        remote_version = info["tag_name"]
    except Exception as e:
        logger.exception(" - Failed to reach GitHub for update check...")
        return

    # convert vesrion #'s to integer for easy compare...
    version_remote = int(re.findall('\d+', remote_version)[0])
    version_local = int(re.findall('\d+', current_version)[0])

    # no updates available...
    logger.debug(" - Local: '%s' vs Remote: '%s'" % (current_version, remote_version))
    if version_remote <= version_local:
        logger.debug(" - No update needed...")
        return

    # notify the user if an update is available
    update_message = "An update is available for Lighthouse!\n\n" \
                     " -  Latest Version: %s\n" % (remote_version) + \
                    " - Current Version: %s\n\n" % (current_version) + \
                    "Please go download the update from GitHub."

    callback(update_message)

