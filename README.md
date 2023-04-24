# keycloak_to_azure.py

A script to sync users/groups from keycloak to azure AD federated accounts.

## What it does ...

- The script loops a configurable map of groups.
- Each element in the map has a keycloak and an azure key value pair.
  - If a user is found in the keycloak group:
    - it is invited as a B2B guest user.
    - it is updated so that the user is of the type Member (not Guest) and placed in the configured azure group.
  - If a member is removed from a keycloak group it is also removed in it's azure equivalent.

## Configuration

To use the script you need to supply it with several environment variables and a configfile.

### Keycloak user

You need a keycloak user with these roles:
- `query-clients`
- `query-groups`
- `query-users`
- `view-clients`
- `view-groups`
- `view-users`

Look at the [Keycloak - Managing users](https://www.keycloak.org/docs/21.1.0/server_admin/#assembly-managing-users_server_administration_guide) documentation to get more information.

The user has to be passed to this script by setting these environment variables:
- `KEYCLOAK_USER`
- `KEYCLOAK_PASSWORD`

### Azure application credentials

An [azure app registration](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade)
with these API permissions is needed:
- `Microsoft Graph -> User.*`
- `Microsoft Graph -> Group.*`
- `Microsoft Graph -> GroupMember.*`

Look at the [Quickstart: Register an application with the Microsoft identity platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) documentation to get more information. Be sure to add a client secret.

The credentials have to be passed as these environment variables:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET` (max expiry is 24 month!!!)

### Script configuration

The script has a self-explanatory config file.

Do a `cp keycloak_to_azure.config.yaml.example keycloak_to_azure.config.yaml` and adapt the config to get started.

Please make sure that all the configured keycloak and azure groups already exist. The script will not take care of that.


Example configuration file:
```
❯ cat keycloak_to_azure.config.yaml.example
logfile: keycloak_to_azure.log
keycloak_url: https://auth.example.com/auth
keycloak_realm: acme
groups:
  - keycloak: group1
    azure: acme-group-1
  - keycloak: group2
    azure: acme-group-2
  - keycloak: group3
    azure: acme-group-3
```

## Running the Script

```
./keycloak_to_azure.py
2023-04-03 07:46:42,250 [INFO] start run
2023-04-03 07:46:47,107 [INFO] end run
```
