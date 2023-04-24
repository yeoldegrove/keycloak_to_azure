#!/usr/bin/env python
# vim: set syn=on ts=4 sw=4 sts=0 et foldmethod=indent:
# purpose: sync users/groups from keycloak to azure AD federated accounts
# - invite keycloak users that are in azure keycloak groups to azure
# - put all the users in the azure keycloak groups into their equivalents in azure
# - remove users from azure groups if they are not in their equivalents in keycloak
# copyright: B1 Systems GmbH <info@b1-systems.de>, 2023.
# license: GPLv3+, http://www.gnu.org/licenses/gpl-3.0.html
# author: Eike Waldt <waldt@b1-systems.de>, 2023.

# the keycloak user needs these roles:
#  - query-clients
#  - query-groups
#  - query-users
#  - view-clients
#  - view-groups
#  - view-users
# To use it set these environment variables:
#  - KEYCLOAK_USER
#  - KEYCLOAK_PASSWORD

# the azure "app registration" can be created at
# https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade
# It needs these API permissions:
#  - Microsoft Graph -> User.*
#  - Microsoft Graph -> Group.*
#  - Microsoft Graph -> GroupMember.*
# To use it set these environment variables:
#  - AZURE_TENANT_ID
#  - AZURE_CLIENT_ID
#  - AZURE_CLIENT_SECRET (max expiry is 24 month!!!)

# Have a look at the defined config file for customization.

import os
import json
import logging
import requests
import keycloak
import yaml
import strictyaml
import path

CONFIGFILE = "keycloak_to_azure.config.yaml"
CONFIG_SCHEMA = strictyaml.Map({
    "logfile": strictyaml.Str(),
    "keycloak_url": strictyaml.Str(),
    "keycloak_realm": strictyaml.Str(),
    "groups": strictyaml.Seq(strictyaml.Map({
        "keycloak": strictyaml.Str(),
        "azure": strictyaml.Str()}
    ))})

# Authenticate to azure graph API
# https://learn.microsoft.com/en-us/graph/?view=graph-rest-1.0
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_HEADERS = {"Content-Type": "application/json"}

# Authenticate to keycloak
# https://python-keycloak.readthedocs.io/en/latest/
# https://github.com/marcospereirampj/python-keycloak/blob/master/src/keycloak/keycloak_admin.py
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_USER")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")

# default azure URLs
AZURE_LOGIN_URL = "https://login.microsoftonline.com"
AZURE_PORTAL_URL = "https://portal.azure.com"
AZURE_GRAPH_HOST = "graph.microsoft.com"
AZURE_GRAPH_API_URL = "https://" + AZURE_GRAPH_HOST + "/v1.0/"

# load config
def load_config():
    config = strictyaml.load(path.Path(CONFIGFILE).text(), CONFIG_SCHEMA).data
    return config

# get azure access token
def get_azure_token():
    url = AZURE_LOGIN_URL + "/" + AZURE_TENANT_ID + "/oauth2/token"
    body = {
        "grant_type": "client_credentials",
        "client_secret": AZURE_CLIENT_SECRET,
        "client_id": AZURE_CLIENT_ID,
        "resource": "https://" + AZURE_GRAPH_HOST
    }
    try:
        response = requests.post(url, data=body)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error("error getting azure access token: error: %s", err)
        raise err
    data = response.json()
    out = data["access_token"]
    return out

# add access token to headers
def get_azure_headers():
    azure_token = get_azure_token()
    #global AZURE_HEADERS
    AZURE_HEADERS["Authorization"] = "Bearer " + azure_token
    return AZURE_HEADERS

# get azure groups
def get_azure_groups():
    url = AZURE_GRAPH_API_URL + "/groups"
    try:
        response = requests.get(url, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error("error getting azure groups: error: %s", err)
        raise err
    data = response.json()['value']
    out = []
    for entry in data:
        out.append(
            {
                "id": entry["id"],
                "name": entry["displayName"] or "",
            }
        )
    return out

# get azure users
def get_azure_users():
    url = AZURE_GRAPH_API_URL + "/users"
    try:
        response = requests.get(url, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error("error getting azure users: error: %s", err)
        raise err
    data = response.json()['value']
    out = []
    for entry in data:
        out.append(
            {
                "id": entry["id"],
                "email": entry["mail"] or "",
                "firstname": entry["givenName"] or "",
                "lastname": entry["surname"] or "",
                "name": entry["displayName"] or "",
            }
        )
    return out

# get azure group members
def get_azure_group_members(id):
    url = AZURE_GRAPH_API_URL + "/groups/" + id + "/members"
    try:
        response = requests.get(url, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error(
            "error getting azure group members: %s, error: %s",
            id,
            err)
        raise err
    data = response.json()['value']
    out = []
    for entry in data:
        out.append(entry["id"])
    return out

# invite keycloak users that are in azure keycloak groups to azure
def invite_user(email):
    logging.debug("inviting azure user: %s", email)
    invite_redirect_url = AZURE_PORTAL_URL + "/" + AZURE_TENANT_ID
    url = AZURE_GRAPH_API_URL + "/invitations"
    body = {"invitedUserEmailAddress": email,
            "inviteRedirectUrl": invite_redirect_url}
    body = json.dumps(body)
    try:
        response = requests.post(url, data=body, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error("error inviting azure user: %s, error: %s", email, err)
        raise err
    data = response.json()
    out = data['invitedUser']['id']
    logging.info("invited azure user: %s", email)
    return out

# update user
def update_user(id, firstname, lastname):
    url = AZURE_GRAPH_API_URL + "/directoryObjects/" + id
    body = {
        "userType": "Member",
        "givenName": firstname,
        "surname": lastname,
        "displayName": firstname + " " + lastname,
    }
    body = json.dumps(body)
    try:
        response = requests.patch(url, data=body, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error(
            "error updating azure user: %s - %s %s, error: %s",
            id,
            firstname,
            lastname,
            err)
        raise err
    logging.info("updated azure user: %s - %s %s", id, firstname, lastname)

# add user to azure group
def groupadd_user(user_id, group_id):
    logging.debug("adding user to group: %s %s", user_id, group_id)
    user_url = AZURE_GRAPH_API_URL + "/directoryObjects/" + user_id
    url = AZURE_GRAPH_API_URL + "/groups/" + group_id + "/members/$ref"
    body = {"@odata.id": user_url}
    body = json.dumps(body)
    try:
        response = requests.post(url, data=body, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error(
            "error adding user to group: %s %s, error: %s",
            user_id,
            group_id,
            err)
        raise err
    logging.info("added user to group: %s %s", user_id, group_id)

# remove user from azure group
def groupremove_user(user_id, group_id):
    logging.debug("removing user from group: %s %s", user_id, group_id)
    url = AZURE_GRAPH_API_URL + "/groups/" + \
        group_id + "/members/" + user_id + "/$ref"
    try:
        response = requests.delete(url, headers=AZURE_HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logging.error(
            "error adding user to group: %s %s, error: %s",
            user_id,
            group_id,
            err)
        raise err
    logging.info("removed user from group: %s %s", user_id, group_id)

def main():
    config = load_config()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(config['logfile']),
            logging.StreamHandler()
        ]
    )
    logging.info("start run")
    
    # authenticate to keycloak
    keycloak_admin = keycloak.KeycloakAdmin(
        server_url=config['keycloak_url'],
        realm_name=config['keycloak_realm'],
        username=KEYCLOAK_ADMIN_USER,
        password=KEYCLOAK_ADMIN_PASSWORD,
        user_realm_name=config['keycloak_realm'],
        client_secret_key=None,
        verify=True,
    )
    # authenticate to azure
    get_azure_headers()

    # cache azure groups
    azure_all_groups = get_azure_groups()

    # loop over all groups from groups variable
    for group in config['groups']:
        keycloak_group = group["keycloak"]
        azure_group = group["azure"]

        # get keycloak group id
        keycloak_group_path = "/" + keycloak_group
        keycloak_group_object = keycloak_admin.get_group_by_path(
            path=keycloak_group_path
        )
        keycloak_group_id = keycloak_group_object["id"]

        # get azure group id
        for azure_group_entry in azure_all_groups:
            if azure_group_entry["name"] == azure_group:
                azure_group_id = azure_group_entry["id"]
                break

        # get keycloak group members
        keycloak_group_members = keycloak_admin.get_group_members(
            keycloak_group_id)
        keycloak_group_members_emails = [
            sub["email"]
            for sub in keycloak_group_members
        ]

        # get current azure group members
        azure_group_member_ids_current = get_azure_group_members(
            azure_group_id)

        # make sure cache is up to date
        azure_all_users = get_azure_users()
        azure_all_user_emails = [sub["email"] for sub in azure_all_users]

        # loop keycloak users
        for keycloak_group_member in keycloak_group_members:
            # get name and email address of user
            keycloak_group_member_firstname = keycloak_group_member["firstName"]
            keycloak_group_member_lastname = keycloak_group_member["lastName"]
            keycloak_group_member_name = (
                keycloak_group_member_firstname + " " + keycloak_group_member_lastname
            )
            keycloak_group_member_email = keycloak_group_member["email"]

            # invite user
            if keycloak_group_member_email not in azure_all_user_emails:
                keycloak_group_member_id = invite_user(
                    keycloak_group_member_email)
                # update initial user data
                update_user(
                    keycloak_group_member_id,
                    keycloak_group_member_firstname,
                    keycloak_group_member_lastname,
                )

                # make sure cache is up to date
                azure_all_users = get_azure_users()
                azure_all_user_ids = [sub["id"] for sub in azure_all_users]
                azure_all_user_emails = [sub["email"]
                                         for sub in azure_all_users]

            # update existing users
            for azure_user_entry in azure_all_users:
                if azure_user_entry["email"] == keycloak_group_member_email:
                    if (
                        azure_user_entry["firstname"] != keycloak_group_member_firstname
                        or azure_user_entry["lastname"]
                        != keycloak_group_member_lastname
                        or azure_user_entry["name"] != keycloak_group_member_name
                    ):
                        logging.info(
                            "user firstname/lastname differs in keycloak vs. azure:"
                            " azure firstname: "
                            + azure_user_entry["firstname"]
                            + ", keycloak firstname: "
                            + keycloak_group_member_firstname
                            + ", azure lastname: "
                            + azure_user_entry["lastname"]
                            + ", keycloak lastname: "
                            + keycloak_group_member_lastname
                            + ", azure fullname: "
                            + azure_user_entry["name"]
                            + ", keycloak fullname: "
                            + keycloak_group_member_name
                        )
                        update_user(
                            azure_user_entry["id"],
                            keycloak_group_member_firstname,
                            keycloak_group_member_lastname,
                        )
                        # make sure cache is up to date
                        azure_all_users = get_azure_users()
                        azure_all_user_ids = [sub["id"]
                                              for sub in azure_all_users]
                        azure_all_user_emails = [
                            sub["email"] for sub in azure_all_users
                        ]
                        break

            # add user to group
            for azure_user_entry in azure_all_users:
                if azure_user_entry["email"] == keycloak_group_member_email:
                    # check if not already a group member
                    if azure_user_entry["id"] not in azure_group_member_ids_current:
                        groupadd_user(azure_user_entry["id"], azure_group_id)
                        # make sure cache is up to date
                        azure_group_member_ids_current = get_azure_group_members(
                            azure_group_id
                        )
                        break

        # remove user from group
        for azure_user_entry in azure_all_users:
            # check if currently a group member
            if azure_user_entry["id"] in azure_group_member_ids_current:
                # check if user does not belong into group
                if (
                    azure_user_entry["email"]
                    and azure_user_entry["email"] not in keycloak_group_members_emails
                ):
                    groupremove_user(azure_user_entry["id"], azure_group_id)
                    # make sure cache is up to date
                    azure_group_member_ids_current = get_azure_group_members(
                        azure_group_id
                    )
                    break

    logging.info("end run")

if __name__ == "__main__":
    main()
