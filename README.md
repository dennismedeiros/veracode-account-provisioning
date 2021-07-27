# veracode-account-provisioning
 Script to provision in bulk account roles for specified account types.

## Setup

Install dependencies:

    pip install -r requirements.txt

(optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run the script. Otherwise you will need to set environment variables before running.

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcbulkassign.py (arguments)


## Usage
Usage: vc_account_provisioning [-h] [-D | --debug | --no-debug] [-x | --execute | --no-execute] [-r ROLE] [-t ACCOUNTTYPE]

optional arguments:
  -h, --help                    show this help message and exit
  -D, --debug, --no-debug       set to enable debug logging.
  -x, --execute, --no-execute   set operation mode for script. default operation mode for script will be to perform a simulation.
 
  -t ACCOUNTTYPE, --accountType ACCOUNTTYPE
                                select account type to process: (default) UI, API, or ALL
  -r ROLE, --role ROLE          select role to enable for accuont: (default) IDESCAN


## NOTE

1. To be able to use this script, you must have either an API service account with the Admin API role, or a user account with the Administrator role