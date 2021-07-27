import sys
import requests
import argparse
import logging
import json
import datetime

import anticrlf

from veracode_api_py import VeracodeAPI as vapi

log = logging.getLogger(__name__)

def init_Logger(logLevel = logging.INFO):
    handler = logging.FileHandler('vc_account_provisioning.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logLevel)

def verify_authorization():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials will expire {}'.format(creds['expiration_ts']))
        log.warn('These API credentials will expire {}'.format(creds['expiration_ts']))
            
def retrieveUsersByFilter(filter='all'):
    # TODO: Update APIs to pass by filter. Until then manually filter all users accounts
    userData = []
    allUsers = vapi().get_users()

    if filter == 'api':
        print("Retrieving API Account Types.")
        log.info("Retrieving API Account Types.")

        for user in allUsers:
            if is_Api_User(user) == True:
                userData.append(user)

    elif filter == 'ui':
        print("Retrieving UI Account Types.") 
        log.info("Retrieving UI Account Types.")   

        for user in allUsers:
            if is_Api_User(user) == False:
                userData.append(user)

    else:
        print("Retrieving all Account Types.")
        log.info("Retrieving all Account Types.")
        userData = allUsers

    return userData

def is_Api_User(userdata):
    userguid = userdata['user_id']
    user= vapi().get_user(userguid)
    permissions = user.get("permissions")
    apiuser = any(item for item in permissions if item["permission_name"]=="apiUser")
    return apiuser

def update_user(user, role):
    username = user["user_name"]
    userguid = user["user_id"]

    roles = add_User_Role(user, role)
    
    #vapi().update_user(userguid, roles)
    vapi().update_user_roles(userguid, roles)

    print("Updated user {} ({})".format(username, userguid))
    log.info("Updated user {} ({})".format(username, userguid))

    return 1

def has_User_Role(user, role):
    roles = user["roles"]
    return any(item for item in roles if item["role_name"] == role)

def remove_User_Role():
    return 0

def add_User_Role(user, new_role):
    roles = user["roles"]
    newroles = []
    for role in roles:
        newroles.append(role.get("role_name"))
        #newroles.append({"role_name": role.get("role_name")})
    newroles.append(new_role) # Append Role to List of Roles
    #newroles.append({"role_name": new_role}) # Append Role to List of Roles
    #roles_object = json.dumps({"roles": newroles}) # Convert to Json object format
    #return roles_object
    return newroles

def check_for_teams(userdata):
    teams = userdata.get("teams")
    if teams == None:
        return 0
    return len(teams) 

def display_users_information(users):
    lineCount = 1

    for user in users:
        username = user["user_name"]
        userid = user["user_id"]
        if log.level == logging.DEBUG:
            print(" {}  {} ({})".format(lineCount, username, userid))
            log.debug(" {}  {} ({})".format(lineCount, username, userid))
        lineCount += 1

def main():
    parser = argparse.ArgumentParser(prog="vc_account_provisioning", 
                                     description='This script adds the indicated role to the specified account type.')
    parser.add_argument('-D', '--debug', action=argparse.BooleanOptionalAction, required=False, help='set to enable debug logging.')
    parser.add_argument('-x', '--execute', action=argparse.BooleanOptionalAction, required=False, help='set operation mode for script. default operation mode for script will be to perform a simulation.')
    parser.add_argument('-t', '--accountType', required=False, help='select account type for processing: (default) UI, API, or ALL', default='UI')
    parser.add_argument('-r', '--role', required=False, help='select role to enable for account: (default) IDESCAN', default='IDESCAN')

    #parser.add_argument('-u', '--user', required=False, help='')
    
    args = parser.parse_args()
    if args.role == 'IDESCAN':
        role = 'greenlightideuser'
    else:
        print("Role {} is not supported.".format(args.role))
        return 0

    # Evalution of Account Type
    if args.accountType == 'UI':
        accountFilter = "ui" # api, ui, all
    elif args.accountType == 'API':
        accountFilter = "api" # api, ui, all
    elif args.accountType == 'ALL':
        accountFilter = "all" # api, ui, all
    else:
        accountFilter = "ui" # default to UI Accounts

    # Evaluation Logging Level
    if args.debug == True:
        logLevel = logging.DEBUG
    else:
        logLevel = logging.INFO

    # Evaluation of Operation Mode
    if args.execute == True:
        executeRun = True
    else:
        executeRun = False

    # Perform Main Process
    try:
        # initialization and validate authorization
        init_Logger(logLevel)
        verify_authorization()

        # report operation mode of script
        if executeRun == True:
            print("Running script in Execution Mode.")
            log.info("Running script in Execution Mode.")
        else: 
            print("Running Script in Simulation Mode.")
            log.info("Running Script in Simulation Mode.")

        # search for users
        usersData = retrieveUsersByFilter(accountFilter)

        modUsers = []
        # Gather users needed to be modified.
        print("Reviewing {} total users...".format(len(usersData)))
        log.info("Reviewing {} total users...".format(len(usersData)))
        
        processed_count=0
        for user in usersData:
            userguid = user["user_id"]
            username = user["user_name"]
            # skip deleted users
            #if user["deleted"] == "true":
            #    print("Skipping deleted user {}".userguid)
            #    return 0
            if log.level == logging.DEBUG:
                print("   Assessing {} ({})".format(username, userguid))
                log.debug("   Assessing {} ({})".format(username, userguid))

            userinfo = vapi().get_user(userguid) 
            if has_User_Role(userinfo, role) == True:
                if log.level == logging.DEBUG:
                    print("   Skipping user {} ({}) as role already present".format(username, userguid))
                    log.debug("   Skipping user {} ({}) as role already present".format(username, userguid))
            else:
                if log.level == logging.DEBUG:
                    print("   Including user {} ({}) as role not present".format(username, userguid))
                    log.debug("   Including user {} ({}) as role not present".format(username, userguid))
                modUsers.append(user)
       
            processed_count += 1

        print("{} users reviewed and {} to be modified.".format(processed_count, len(modUsers)))
        log.info("{} users reviewed and {} to be modified.".format(processed_count, len(modUsers)))

        # TDOD: modify for debug logging only
        if log.level == logging.DEBUG:
            print("Users determined to be modified.")
            log.debug("Users determined to be modified.")
            display_users_information(modUsers)
        
        #  Modify List of Users Roles
        if executeRun == True:
            for user in modUsers:
                print("Processing Users.")
                userid = user['user_id']
                userinfo = vapi().get_user(userid) 
                update_user(userinfo, role)
        else:
            print("Runnning Simulation.. Modifications will not be performed on User Accounts.")

        # audit
        print()
        print("Performing Audit")
        log.info("Performing Audit")

        verifiedUsers = []
        failedUsers = []

        for user in modUsers:
            userid = user['user_id']
            username = user['user_name']
            userinfo = vapi().get_user(userid) 
            if has_User_Role(userinfo, role) == True:
                verifiedUsers.append(user)
                if log.level == logging.DEBUG:
                    print("Users {} ({}) verified with role.".format(username, userid))
                    log.debug("Users {} ({}) verified with role.".format(username, userid))
                
            else:
                failedUsers.append(user)
                if log.level == logging.DEBUG:
                    print("Users {} ({}) does not contain role.".format(username, userid))
                    log.debug("Users {} ({}) does not contain role.".format(username, userid))

        print()
        print("Summary")
        log.info("Summary")
        print("{} users verified.".format(len(verifiedUsers)))
        log.info("{} users verified.".format(len(verifiedUsers)))
        display_users_information(verifiedUsers)
        print("{} users failed.".format(len(failedUsers)))
        log.info("{} users failed.".format(len(failedUsers)))
        display_users_information(failedUsers) 
    
    except Exception as e:
        print("An Exception occured. {}".format(e))
        log.error(e)

if __name__ == '__main__':
    main()