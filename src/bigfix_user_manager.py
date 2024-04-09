"""
bigfix_user_manager.py - A utility to automate notification and 
disabling of BigFix user account for inactivity.
"""
from getpass import getpass
import sys
import os.path
import json
import argparse

import xml.etree.ElementTree as ET
import requests
import keyring


# The following is just for warning suppression
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# end of warning suppression

# Declare some "constants"
KEYRING_BIGFIX = "bigfixUserManager_MO"


def main():
    """main() Main routine"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Pathname of configuration file (required).\n" 
        "First run will interactively create this file.",
        required=True,
    )

    parser.add_argument(
        "-f",
        "--fromuser",
        type=str,
        help="BigFix User to copy from (and optionally delete)",
    )

    parser.add_argument(
        "-t", "--touser", type=str, help="BigFix User to copy to (must already exist)"
    )

    # Parse the arguments
    arg = parser.parse_args()

    if not os.path.exists(arg.config):
        create_config_file(arg.config)

    with open(arg.config, "r", encoding="utf-8") as cfile:
        cdata = cfile.readlines()
        conf = json.loads("".join(cdata))

    # We should have our user info and we should be able to
    # extract passwords from the OS keyring.
    conf["bfpass"] = keyring.get_password(KEYRING_BIGFIX, conf["bfuser"])

    print(f"{conf}")

    operator = get_bigfix_operators(conf)

    # Validate the user input
    if arg.fromuser is not None:
        if arg.fromuser not in operator:
            print(f"User {arg.fromuser} not found in BigFix")
            sys.exit(1)

    if arg.touser is not None:
        if arg.touser not in operator:
            print(f"User {arg.touser} not found in BigFix")
            sys.exit(1)

    if (
        operator[arg.fromuser]["MasterOperator"]
        and not operator[arg.touser]["MasterOperator"]
    ):
        print(
            f"Cannot copy from a master operator {arg.fromuser} "
            f"to a non-master operator {arg.touser}"
        )
        sys.exit(1)

    # Now we have our "to" and "from" users, we can archive the actions,
    # move the content, and optionally delete the "from" user.

    from_user = operator[arg.fromuser]
    to_user = operator[arg.touser]

    content = get_opsite_content(conf, arg.fromuser)
    if content is None:
        print("Actions export failed")
        sys.exit(1)
    else:
        print("Actions exported successfully")

    sys.exit(0)

def get_opsite_content(conf, user):
    """
    export_actions(conf, user) - Export actions for a given user
    """
    # Implement the logic to export actions for the given user
    # Return True if successful, False otherwise
    bf_sess = requests.Session()
    bf_sess.auth = (conf["bfuser"], conf["bfpass"])
    qheader = {"Content-Type": "application/x-www-form-urlencoded"}
    req = requests.Request(
        method="GET",
        url=f"https://{conf['bfserver']}:{conf['bfport']}/api/site/operator/{user}/content",
        headers=qheader,
    )
    prepped = bf_sess.prepare_request(req)
    result = bf_sess.send(prepped, verify=False)
    if not result.ok:
        print(f"\n\nREST API call failed with status {result.status_code}")
        print(f"Reason: {result.text}")
        return None
    else:
        opsite_xml = result.text

    # Implement the logic to export actions for the given user
    # Return True if successful, False otherwise
    return opsite_xml


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
    bfpass = get_password(f"Enter {conf['bfuser']} account password")

    keyring.set_password(KEYRING_BIGFIX, conf["bfuser"], bfpass)

    with open(config_pathname, "w", encoding="utf-8") as cpath:
        cpath.write(json.dumps(conf, indent=4))

    print("Config file written. Passwords saved in OS keystore.")
    print("Testing connectivity to BigFix and email.")

    # We have already written out the config file, so we can "slot in"
    # the passwords for testing here.
    conf["bfpass"] = bfpass

    if not validate_bigfix_connection(conf):
        print("Connection to BigFix using your values failed.")
        print(f"Delete {config_pathname} and try again.")
        sys.exit(1)

    print("No actions taken when config file is created. Run again ")
    print("to copy a user account.")

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


def validate_bigfix_connection(conf):
    """
    validate_bigfix_connection(conf) - Establish a REST API connection to BigFix
    """
    bf_sess = requests.Session()
    bf_sess.auth = (conf["bfuser"], conf["bfpass"])
    qheader = {"Content-Type": "application/x-www-form-urlencoded"}

    req = requests.Request(
        method="GET",
        url=f"https://{conf['bfserver']}:{conf['bfport']}/api/help",
        headers=qheader,
    )

    prepped = bf_sess.prepare_request(req)

    result = bf_sess.send(prepped, verify=False)

    if not result.ok:
        print(f"\n\nREST API call failed with status {result.status_code}")
        print(f"Reason: {result.text}")
        return False
    else:
        print("We got data back for /api/help")
        print(f"  http result [{result.status_code} {result.reason}]")
        return True

    return False


def get_bigfix_operators(conf):
    """
    get_bigfix_operators(conf) - Get a list of BigFix operators
    """

    # First, get all the roles so we can tell when we iterate over operators
    # what kind of user each user is. All we are concerned about is the master
    # operator flag.

    user = {}

    bf_sess = requests.Session()
    bf_sess.auth = (conf["bfuser"], conf["bfpass"])
    qheader = {"Content-Type": "application/x-www-form-urlencoded"}

    req = requests.Request(
        method="GET",
        url=f"https://{conf['bfserver']}:{conf['bfport']}/api/roles",
        headers=qheader,
    )

    prepped = bf_sess.prepare_request(req)

    result = bf_sess.send(prepped, verify=False)

    if not result.ok:
        print(f"\n\nREST API call failed with status {result.status_code}")
        print(f"Reason: {result.text}")
        sys.exit(1)

    # We have a good result, so we can parse the XML

    # Parse the XML into a dictionary
    root = ET.fromstring(result.text)

    for role in root.findall("Role"):
        is_mo = False
        role_name = role.find("Name").text
        if role.find("MasterOperator").text == "1":
            is_mo = True
        else:
            is_mo = False
        for op in role.find("Operators"):
            if op.text not in user:
                user[op.text] = {"MasterOperator": is_mo, "RoleName": []}
                user[op.text]["RoleName"].append(role_name)
            elif user[op.text]["MasterOperator"] is False:
                user[op.text]["RoleName"].append(role_name)
                if is_mo is True:
                    user[op.text]["MasterOperator"] = True

    bf_sess = requests.Session()
    bf_sess.auth = (conf["bfuser"], conf["bfpass"])
    qheader = {"Content-Type": "application/x-www-form-urlencoded"}

    req = requests.Request(
        method="GET",
        url=f"https://{conf['bfserver']}:{conf['bfport']}/api/operators",
        headers=qheader,
    )

    prepped = bf_sess.prepare_request(req)

    result = bf_sess.send(prepped, verify=False)

    if not result.ok:
        print(f"\n\nREST API call failed with status {result.status_code}")
        print(f"Reason: {result.text}")
        sys.exit(1)

    # We have a good result, so we can parse the XML

    # Parse the XML into a dictionary
    root = ET.fromstring(result.text)
    for operator in root.findall("Operator"):
        operator_dict = {}
        operator_dict["Name"] = operator.find("Name").text
        operator_dict["MasterOperator"] = operator.find("MasterOperator").text
        operator_dict["Resource"] = operator.attrib["Resource"]
        if operator_dict["Name"] in user:
            user[operator_dict["Name"]]["Resource"] = operator_dict["Resource"]
        else:
            if operator_dict["MasterOperator"] == "true":
                user[operator_dict["Name"]] = {
                    "MasterOperator": True,
                    "Resource": operator_dict["Resource"],
                    "RoleName": [],
                }
            else:
                user[operator_dict["Name"]] = {
                    "MasterOperator": False,
                    "Resource": operator_dict["Resource"],
                    "RoleName": [],
                }

    return user


# Convention for possible future module/import
if __name__ == "__main__":
    main()
    sys.exit(0)
