import sys
import requests
import argparse
import logging
import json
import datetime

import anticrlf

from veracode_api_py import VeracodeAPI as vapi

log = logging.getLogger(__name__)

submitterRoles = ["extsubmitdynamicscan", "extsubmitdynamicmpscan", 
                        "extsubmitstaticscan", "extsubmitdiscoveryscan", "extsubmitdynamicanalysis"]

def init_Logger(logLevel=logging.INFO):
    handler = logging.FileHandler(
        'vc_account_provisioning.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter(
        '%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logLevel)

def setupCommandLineArgumentsParser():
    parser = argparse.ArgumentParser(prog="vc_account_provisioning",
                                     description='This script adds the indicated role to the specified account type.')
    # Operation Mode Arguments
    parser.add_argument('-D', '--debug', action=argparse.BooleanOptionalAction,
                        required=False, help='set to enable debug logging.')
    parser.add_argument('-x', '--execute', action=argparse.BooleanOptionalAction, required=False,
                        help='set operation mode for script. default operation mode for script will be to perform a simulation.')

    # User Selection Arguments
    parser.add_argument('-t', '--accountType', required=False,
                        help='select account type for processing: (default) UI, API, or ALL', default='UI')
    #parser.add_argument('-u', '--user', required=False, help='')
    #parser.add_argument('-i', '--user_id', required=False, help='')

    # Script Behavior Arguments
    #parser.add_argument('-l', '--list', action=argparse.BooleanOptionalAction, required=False, help='')

    parser.add_argument('-i', '--include', required=False, help='')
    parser.add_argument('-e', '--exclude', required=False, help='')

    return parser

def verify_authorization():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(
        creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    # we get a datetime with timezone...
    delta = exp - datetime.datetime.now().astimezone()
    if (delta.days < 7):
        print('These API credentials will expire {}'.format(
            creds['expiration_ts']))
        log.warn('These API credentials will expire {}'.format(
            creds['expiration_ts']))

def retrieveUsersByFilter(filter='all'):
    # TODO: Update APIs to pass by filter. Until then manually filter all users accounts
    userData = []
    allUsers = vapi().get_users()

    if filter == 'api':
        print("Retrieving API Account Types.")
        log.info("Retrieving API Account Types.")

        for user in allUsers:
            if isApiUser(user) == True:
                userData.append(user)

    elif filter == 'ui':
        print("Retrieving UI Account Types.")
        log.info("Retrieving UI Account Types.")

        for user in allUsers:
            if isApiUser(user) == False:
                userData.append(user)

    else:
        print("Retrieving all Account Types.")
        log.info("Retrieving all Account Types.")
        userData = allUsers

    return userData

def isApiUser(userdata):
    userguid = userdata['user_id']
    user = vapi().get_user(userguid)
    permissions = user.get("permissions")
    apiuser = any(
        item for item in permissions if item["permission_name"] == "apiUser")
    return apiuser

def update_user(user):
    username = user["user_name"]
    userguid = user["user_id"]

    roles = user['roles']

    result = vapi().update_user_roles(userguid, roles)
    return 1

def addUserRoles(currentRoles=[], addRoles=[]):
    # addRoles = [ "", ""]
    applyRoles = []

    for addRole in addRoles:
        if hasUserRole(currentRoles, addRole) == False:
            applyRoles.append(addRole)

    return applyRoles

def removeUserRoles(currentRoles=[], removeRoles=[]):
    #removeRoles = ["", ""]
    applyRoles = []

    for removeRole in removeRoles:
        if hasUserRole(currentRoles, removeRole) == False:
            applyRoles.append(removeRole)

    return applyRoles

def isExactMatchUserRoles(currentRoles, roles):
    if currentRoles == roles:
        return True
    return False

def hasAllUserRoles(currentRoles=[], roles=[]):
    
    if(set(roles).issubset(set(currentRoles))):
        return True
    
    return False

def hasUserRole(currentRoles, hasRole):
    return any(hasRole == currentRole for currentRole in currentRoles)

def hasAnyUserRoles(currentRoles=[], roles=[]):
    for role in roles:
        if hasUserRole(currentRoles, role):
            return True

    return False

def hasSubmitterRoles(currentRoles):
    return hasAnyUserRoles(currentRoles, submitterRoles)

def denormilze_submitter_roles(currentRoles):
    
    deNormalizedRoles = currentRoles
    if hasSubmitterRoles(deNormalizedRoles):
        if hasAllUserRoles(deNormalizedRoles, submitterRoles) == False:
            deNormalizedRoles.append("extsubmitter")
        else:
            deNormalizedRoles.append("extsubmitter")
            deNormalizedRoles.append("extsubmitanyscan")
    return deNormalizedRoles

def normalize_submitter_user_roles(currentRoles):
    
    normailizedRoles = []
    for role in currentRoles:
        if role == "extsubmitanyscan":
            normailizedRoles.append("extsubmitdynamicscan")
            normailizedRoles.append("extsubmitdynamicmpscan")
            normailizedRoles.append("extsubmitstaticscan")
            normailizedRoles.append("extsubmitdiscoveryscan")
            normailizedRoles.append("extsubmitdynamicanalysis")
            #normailizedRoles.append("extsubmitmanualscan") 
        elif role == "extsubmitter":
            continue
        else:
            normailizedRoles.append(role)
            
    return normailizedRoles

def getArrayOfRoleNames(userinfo):
    roles = userinfo['roles']

    currentRoles =[]
    for role in roles:
        currentRoles.append(role['role_name'])

    return currentRoles

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

def isSubmitterTypeRole():
    return 0

def addUserRole(currentRoles, add_role):

    appliedRoles = []
    for role in roles:
        add_role.append(role.get("role_name"))

    # check if submitter type
    newroles.append(add_role)  # Append Role to List of Roles

    return appliedRoles

def removeUserRole(currentRoles, remove_role):
   
    appliedRoles = []
    for role in roles:
        rolename = role.get("role_name")
        if rolename != role_to_remove:
            newroles.append(role.get("role_name"))

    return appliedRoles

def getAppliedUserRoles(currentRoles, includeRoles, excludeRoles):
    appliedRoles = currentRoles.copy()
    if hasAnyUserRoles(currentRoles, excludeRoles) == True:
        for excludeRole in excludeRoles:
            appliedRoles.remove(excludeRole)
       
    if hasAllUserRoles(appliedRoles, includeRoles) == False:
        for includeRole in includeRoles:
            if hasUserRole(appliedRoles, includeRole) == False:
                appliedRoles.append(includeRole)

    return appliedRoles

def verifyConditionsForUserRoles(currentRoles):
    
    appliedRoles = currentRoles.copy()
    for role in currentRoles:
        if role == "extcreator" or role == "extseclead": 
            if hasAnyUserRoles(currentRoles, submitterRoles) == False:
                appliedRoles.remove(role)
       
    return appliedRoles

def resolveModifyUserAccounts(usersList, includeRoles, excludeRoles):

    userModlist = []
    processed_count = 0
    for user in usersList:
        userguid = user["user_id"]
        username = user["user_name"]
        # skip deleted users
        # if user["deleted"] == "true":
        #    print("Skipping deleted user {}".userguid)
        #    return 0
        if log.level == logging.DEBUG:
            print("   Assessing {} ({})".format(username, userguid))
            log.debug("   Assessing {} ({})".format(username, userguid))

        # Retrieve User Account and Evaluate Roles
        userinfo = vapi().get_user(userguid)
        currentRoles = getArrayOfRoleNames(userinfo)
        exitingRoles = normalize_submitter_user_roles(currentRoles)

        if hasAnyUserRoles(exitingRoles, excludeRoles) == True:
            userModlist.append(user)
            if log.level == logging.DEBUG:
                print("   Including user {} ({}) as role(s) not present".format(username, userguid))
                log.debug("   Including user {} ({}) as role(s) not present".format(username, userguid))
        elif len(includeRoles) > 0:
            if hasAnyUserRoles(currentRoles, includeRoles) == False:
                userModlist.append(user)
                if log.level == logging.DEBUG:
                    print("   Including user {} ({}) as role(s) not present".format(username, userguid))
                    log.debug("   Including user {} ({}) as role(s) not present".format(username, userguid))
        else:
            if log.level == logging.DEBUG:
                print("   Skipping user {} ({}) as role(s) already present".format(username, userguid))
                log.debug("   Skipping user {} ({}) as role(s) already present".format(username, userguid))
            
        processed_count += 1

    print("{} users reviewed and {} to be modified.".format(processed_count, len(userModlist)))
    log.info("{} users reviewed and {} to be modified.".format(processed_count, len(userModlist)))

    if log.level == logging.DEBUG:
        print("Users determined to be modified.")
        log.debug("Users determined to be modified.")
        display_users_information(userModlist)

    return userModlist

def modifyUserAccounts(modUserList, includeRoles, excludeRoles, executeRun):
    userAppliedList = []
    
    # Modify List of Users Roles
    
    for user in modUserList:
        username = user['user_name']
        userid = user['user_id']
        
        log.debug("Updating User {} ({})".format(username, userid))
        
        userinfo = vapi().get_user(userid)
        appliedUser = userinfo.copy()

        roles = userinfo['roles']
        currentRoles = []
        for role in roles: 
            currentRoles.append(role['role_name'])

        exitingRoles = normalize_submitter_user_roles(currentRoles)
        
        # assess role modifications to make
        appliedRoles = getAppliedUserRoles(exitingRoles, includeRoles, excludeRoles)
        verifiedRoles = verifyConditionsForUserRoles(appliedRoles)
        starndardRoles = denormilze_submitter_roles(verifiedRoles)
        
        appliedUser['roles'] = starndardRoles
      
        if executeRun == True:
            if update_user(appliedUser) == True:
                userAppliedList.append(appliedUser)
                if log.level == logging.DEBUG:
                    print("Updated user {} ({})".format(username, userid))
                    log.debug("Updated user {} ({})".format(username, userid))

        else:
            userAppliedList.append(appliedUser)
            print("Runnning Simulation.. Modifications will not be performed on User Accounts.")

    return userAppliedList

def auditUserAccounts(userAppliedList):
    # audit
    print()
    print("Performing Audit")
    log.info("Performing Audit")

    verifiedUsers = []
    failedUsers = []

    for appliedUser in userAppliedList:
        userguid = appliedUser['user_id']
        username = appliedUser['user_name']
       
        userinfo = vapi().get_user(userguid)
        existingRoles = getArrayOfRoleNames(userinfo)
        existingRoles.sort()

        appliedRoles = appliedUser['roles']
        appliedRoles.sort()
        if log.level == logging.DEBUG:
            print("   Exising {} ({}) roles: {}".format(username, userguid, ' '.join([str(elem) for elem in existingRoles])))
            print("   Applied {} ({}) roles: {}".format(username, userguid, ' '.join([str(elem) for elem in appliedRoles])))

        if isExactMatchUserRoles(existingRoles, appliedRoles):
            verifiedUsers.append(appliedUser)
            if log.level == logging.DEBUG:
                print("   All roles verified for {} ({}).".format(username, userguid))
                log.debug("   All roles verified for {} ({}).".format(username, userguid))
        else:
            failedUsers.append(appliedUser)
            if log.level == logging.DEBUG:
                print("   All roles don't match for {} ({})".format(username, userguid))
                log.debug("   All roles don't match for {} ({})".format(username, userguid))
                        
    print()
    print("Summary")
    log.info("Summary")

    print("{} users verified.".format(len(verifiedUsers)))
    log.info("{} users verified.".format(len(verifiedUsers)))
    display_users_information(verifiedUsers)

    print("{} users failed.".format(len(failedUsers)))
    log.info("{} users failed.".format(len(failedUsers)))
    display_users_information(failedUsers)

def main():
    # Perform Main Process
    try:
        # Initialize command line parser
        parser = setupCommandLineArgumentsParser()
        args = parser.parse_args()

        # Evaluate account Type to process
        if args.accountType == 'UI':
            accountFilter = "ui"  # api, ui, all
        elif args.accountType == 'API':
            accountFilter = "api"  # api, ui, all
        elif args.accountType == 'ALL':
            accountFilter = "all"  # api, ui, all
        else:
            accountFilter = "ui"  # default to UI Accounts

        # Evaluate Logging Level
        if args.debug == True:
            logLevel = logging.DEBUG
        else:
            logLevel = logging.INFO

        # Evaluate Operation Mode
        if args.execute == True:
            executeRun = True
        else:
            executeRun = False

        # Evaluate include content
        includeRoles = []
        if args.include != None:
            if args.include == 'IDESCAN':
                includeRoles.append("greenlightideuser")
            else:
                print("Role {} is not supported.".format(args.include))
                return 0

        # Evaluate exclude content
        excludeRoles = []
        if args.exclude != None:
            if args.exclude == 'SubmitDS':
                excludeRoles.append("extsubmitdynamicscan")
            else:
                print("Role {} is not supported.".format(args.exclude))
                return 0

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

        # find users with criteria for processing
        usersList = retrieveUsersByFilter(accountFilter)
        # determine user accounts in need of modifications
        userModList = resolveModifyUserAccounts(usersList, includeRoles, excludeRoles)

        # determine modification and apply
        userAppliedList = modifyUserAccounts(userModList, includeRoles, excludeRoles, executeRun)
        
         # Gather users needed to be modified.
        print("Reviewing {} total users...".format(len(userAppliedList)))
        log.info("Reviewing {} total users...".format(len(userAppliedList)))

        # audit and verify modifications to user accounts
        auditUserAccounts(userAppliedList)

    except Exception as e:
        print("An Exception occured. {}".format(e))
        log.error(e)

if __name__ == '__main__':
    main()