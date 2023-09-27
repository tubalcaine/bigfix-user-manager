"""
bigfix_user_manager.py - A utility to automate notification and 
disabling of BigFix user account for inactivity.
"""
from getpass import getpass
import sys
import os.path
import json
import argparse

# import requests
import keyring


# The following is just for warning suppression
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# end of warning suppression


def main():
    """main() Main routine"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Pathname of configuration file (required)",
        required=True,
    )

    # Parse the arguments
    arg = parser.parse_args()

    if not os.path.exists(arg.config):
        create_config_file(arg.config)

    with open(arg.config, "r", encoding="utf-8") as cfile:
        cdata = cfile.readlines()
        conf = json.loads(cdata)

    print(f"{conf}")


def get_password(prompt):
    """
    get_password(prompt) - Prompt for password which does not echo and
    must be entered the same twice in a row to get a result
    """
    ## We need to 'noecho' prompt for passwords and force double entry
    ## until they match.
    onepass = "not"  # Set to ensure mismatch and avoid fail msg 1st time
    twopass = ""

    print(f"{prompt}")
    print("The password will not display. You must enter the same")
    print("password twice in a row. ")
    while onepass != twopass:
        if onepass != "not":
            print("\nPasswords did not match. Try again.\n")

        onepass = getpass(f"{prompt}: ")
        twopass = getpass("Enter the password again: ")

    return twopass


def create_config_file(config_pathname):
    """
    create_config_file(config_pathname) - Interactively create a config file and store passwords
    """

    # Create your empty conf dictionary
    conf = {}

    print("This will prompt you for all the major configuration settings ")
    print("for this application and we will write the JSON configuration to")
    print(f"the file {config_pathname}")
    print("")
    conf["bfserver"] = input("Please enter the BigFix server host name: ")
    conf["bfport"] = input_int("Enter the BigFix server REST API port: ")
    conf["bfuser"] = input("Enter a BigFix master operator user name: ")
    bfpass = get_password(f"Enter {conf['bfuser']} account password: ")
    conf["email_server"] = input("Enter email server host name: ")
    conf["email_port"] = input_int("Enter email server port (SMTP port)")
    conf["email_user"] = input("Enter SMTP user name: ")
    conf["email_sendto"] = input("Send notification to: ")
    email_pass = get_password(f"Enter email user {conf['email_user']} password: ")
    conf["disable_days"] = input_int(
        "Disable accounts after this many days of inactivity: "
    )
    conf["disable_notify_days_before"] = input_int(
        "Notify this many days before disabling: "
    )

    if conf["disable_notify_days_before"] > conf["disable_days"]:
        print("Notification days cannot be greater than disavle days.")
        sys.exit(1)

    keyring.set_password("bigfixUserManager_MO", conf["bfuser"], bfpass)
    keyring.set_password("bigfixUserManager_email", conf["email_user"], email_pass)

    with open(config_pathname, "w", encoding="utf-8") as cpath:
        cpath.write(json.dumps(conf, indent=4))

    sys.exit(0)


def input_int(prompt):
    """
    input_int(prompt) - Enforce integer result on user input
    """
    try:
        inval = int(input(prompt))
    except ValueError:
        print("Non-numeric input given")
        sys.exit(1)
    return inval


# Convention for possible future module/import
if __name__ == "__main__":
    main()
    sys.exit(0)
