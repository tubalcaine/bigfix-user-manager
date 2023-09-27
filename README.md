# bigfix-user-manager
## A python script to automate unused user account deactivation
This python script is designed to be executed periodically. It will send
emails to an admin and optionally to users to notify them when their account
will be disabled for inactivity and can optionally also disable the account.

A JSON configuration file is used to store the settings. Passwords may be
passed on the command line or may be stored in a user keyring (recommneded).
This script may be used on Windows or Linux. It has not been tested in
other OSes.
