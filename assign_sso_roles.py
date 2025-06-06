import boto3
import json
import sys

def assume_role(accountid: str):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{accountid}:role/Test-Role-User-Group-SSO-Script'
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    return assumed_role['Credentials']

def create_session(credentials):
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

def get_instance_id(session: boto3.Session, region: str):
    idclient = session.client('sso-admin', region_name=region)
    response = idclient.list_instances()
    if not response['Instances']:
        raise Exception("No SSO instances found in the account")
    instance_id = response['Instances'][0]['IdentityStoreId']
    return instance_id

def get_instance_arn(session: boto3.Session, region: str):
    idclient = session.client('sso-admin', region_name=region)
    response = idclient.list_instances()
    if not response['Instances']:
        raise Exception("No SSO instances found in the account")
    instance_arn = response['Instances'][0]['InstanceArn']
    return instance_arn


def list_account(org_client):
    paginator = org_client.get_paginator('list_accounts')
    accounts = []
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def list_account_assignment(account_id, instance_arn, sso_admin):
    assignments = []
    permission_sets = sso_admin.list_permission_sets(InstanceArn=instance_arn)['PermissionSets']
    for permission_set_arn in permission_sets:
        paginator = sso_admin.get_paginator("list_account_assignments")
        for page in paginator.paginate(
            AccountId=account_id,
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page["AccountAssignments"]:
                assignment["PermissionSetArn"] = permission_set_arn
                assignments.append(assignment)
    return assignments

def get_permission_set_name(permission_set_arn, instance_arn, sso_admin):
    response = sso_admin.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    )
    return response['PermissionSet']['Name']

def get_all_assignment(accounts, instance_arn, identity_store_id, sso_admin, identitystore_client):
    output = []
    for acc in accounts:
        account_id = acc["Id"]
        account_name = acc["Name"]
        assignments = list_account_assignment(account_id, instance_arn, sso_admin)

        for assign in assignments:
            principal_type = assign['PrincipalType']
            principal_id = assign['PrincipalId']
            permission_set_arn = assign['PermissionSetArn']
            permission_set_name = get_permission_set_name(permission_set_arn, instance_arn, sso_admin)

            name = "Unknown"
            email = None

            if principal_type == "USER":
                try:
                    desc_user = identitystore_client.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=principal_id
                    )
                    name = desc_user.get("UserName", "Unknown")
                    email = desc_user.get("Emails", [{}])[0].get("Value")
                except Exception:
                    pass
            else:
                try:
                    desc_group = identitystore_client.describe_group(
                        IdentityStoreId=identity_store_id,
                        GroupId=principal_id
                    )
                    name = desc_group.get("DisplayName", "Unknown")
                except Exception:
                    pass

            output.append({
                "account_id": account_id,
                "account_name": account_name,
                "principal_type": principal_type,
                "name": name,
                "email": email,
                "principal_id": principal_id,
                "permission_set": permission_set_name
            })
    return output

def group_by_account(assignments):
    grouped = {}

    for item in assignments:
        account_key = item['account_name']

        if account_key not in grouped:
            grouped[account_key] = {
                'account_id': item['account_id'],
                'account_name': item['account_name'],
                'assignments': []
            }

        found = False
        for existing in grouped[account_key]['assignments']:
            if (existing['principal_type'] == item['principal_type']
                and existing['name'] == item['name']):
                existing['permission_sets'].append(item['permission_set'])
                found = True
                break

        if not found:
            grouped[account_key]['assignments'].append({
                'principal_type': item['principal_type'],
                'name': item['name'],
                'email': item['email'],
                'principal_id': item['principal_id'],
                'permission_sets': [item['permission_set']]
            })

    return list(grouped.values())

def list_sso_applications_in_other_account(instance_arn, session, region):
    try:
        sso_admin_assumed = session.client('sso-admin', region_name=region)
        all_applications = []
        paginator = sso_admin_assumed.get_paginator('list_applications')
        for page in paginator.paginate(InstanceArn=instance_arn):
            apps = page.get('Applications', [])
            all_applications.extend(apps)
        return all_applications
    except Exception as e:
        print(f"Error in region {region}: {e}")
        return []

def load_json_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filename} not found. Please run the main script first to generate this file.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {filename}")
        return None

def get_identity_store_id_for_client(sso_admin_client, instance_arn):
    response = sso_admin_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    return None

def get_target_users_and_groups(session, identity_store_id, region):
    identitystore_client_assumed = session.client('identitystore', region_name=region)
    
    users = {}
    try:
        paginator = identitystore_client_assumed.get_paginator("list_users")
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for user in page["Users"]:
                username = user.get("UserName", "")
                user_id = user.get("UserId", "")
                email = ""
                if "Emails" in user and user["Emails"]:
                    email = user["Emails"][0].get("Value", "")
                if username:
                    users[username.lower()] = user_id
                if email:
                    users[email.lower()] = user_id
    except Exception as e:
        print(f"Error fetching users: {e}")
        users = {}
    
    groups = {}
    try:
        paginator = identitystore_client_assumed.get_paginator("list_groups")
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for group in page["Groups"]:
                group_name = group.get("DisplayName", "")
                group_id = group.get("GroupId", "")
                if group_name:
                    groups[group_name.lower()] = group_id
    except Exception as e:
        print(f"Error fetching groups: {e}")
        groups = {}
    
    return users, groups

def find_principal_id_in_target(assignment, target_users, target_groups):
    principal_type = assignment['principal_type']
    principal_name = assignment['name']
    principal_email = assignment.get('email', '')
    
    if principal_type == 'USER':
        user_id = target_users.get(principal_name.lower())
        if not user_id and principal_email:
            user_id = target_users.get(principal_email.lower())
        return user_id
    elif principal_type == 'GROUP':
        return target_groups.get(principal_name.lower())
    return None

def create_application_assignments(session, instance_arn, identity_store_id, region):
    applications = load_json_file("application_arn.json")
    account_assignments = load_json_file("account_assignment-diya.json")
    if not applications or not account_assignments:
        return
    
    sso_admin_client = session.client('sso-admin', region_name=region)
    
    target_users, target_groups = get_target_users_and_groups(session, identity_store_id, region)
    
    assignment_results = []
    
    for app in applications:
        app_name = app['ApplicationName']
        app_arn = app['ApplicationArn']
        
        app_name_lower = app_name.lower()
        
        for account in account_assignments:
            account_name = account['account_name'].lower()
            
            for assignment in account['assignments']:
                for permission_set in assignment['permission_sets']:
                    expected_app_name = f"{account_name}-{permission_set.lower()}"
                    
                    if expected_app_name == app_name_lower:
                        principal_type = assignment['principal_type']
                        principal_name = assignment['name']
                        
                        target_principal_id = find_principal_id_in_target(
                            assignment, target_users, target_groups
                        )
                        
                        if not target_principal_id:
                            assignment_results.append({
                                'status': 'error',
                                'application_name': app_name,
                                'application_arn': app_arn,
                                'principal_type': principal_type,
                                'principal_name': principal_name,
                                'original_principal_id': assignment['principal_id'],
                                'target_principal_id': None,
                                'account_name': account['account_name'],
                                'permission_set': permission_set,
                                'error': f'{principal_type} "{principal_name}" not found in target Identity Store'
                            })
                            print(f" {principal_type} '{principal_name}' not found in target Identity Store")
                            continue
                        
                        try:
                            response = sso_admin_client.create_application_assignment(
                                ApplicationArn=app_arn,
                                PrincipalId=target_principal_id,
                                PrincipalType=principal_type
                            )
                            assignment_results.append({
                                'status': 'success',
                                'application_name': app_name,
                                'application_arn': app_arn,
                                'principal_type': principal_type,
                                'principal_name': principal_name,
                                'original_principal_id': assignment['principal_id'],
                                'target_principal_id': target_principal_id,
                                'account_name': account['account_name'],
                                'permission_set': permission_set
                            })
                            print(f" assignment successfull")
                        except Exception as e:
                            error_msg = str(e)
                            assignment_results.append({
                                'status': 'error',
                                'application_name': app_name,
                                'application_arn': app_arn,
                                'principal_type': principal_type,
                                'principal_name': principal_name,
                                'original_principal_id': assignment['principal_id'],
                                'target_principal_id': target_principal_id,
                                'account_name': account['account_name'],
                                'permission_set': permission_set,
                                'error': error_msg
                            })

    
    with open("assignment_results.json", "w") as f:
        json.dump(assignment_results, f, indent=4)
    
    failed = len([r for r in assignment_results if r['status'] == 'error'])

    if failed > 0:
        print(f"\nFailed assignments:")
        for result in assignment_results:
            if result['status'] == 'error':
                print(f"  - {result['principal_type']} {result['principal_name']} to {result['application_name']}: {result['error']}")

def main():
    # customer_sso_account = "285233622501"  # source
    # customer_sso_region = "eu-north-1"
    # ck_sso_account = "364010288443"  # dest
    # ck_sso_region = "us-east-1"
    customer_sso_account = sys.argv[1]
    customer_sso_region = sys.argv[2]
    ck_sso_account = sys.argv[3]
    ck_sso_region = sys.argv[4]

    credentials_customer = assume_role(customer_sso_account)
    customer_session = create_session(credentials_customer)
    instance_id_customer = get_instance_id(customer_session, customer_sso_region)
    instance_arn_customer = get_instance_arn(customer_session, customer_sso_region)
    
    credentials_ck = assume_role(ck_sso_account)
    ck_session = create_session(credentials_ck)
    instance_id_ck = get_instance_id(ck_session, ck_sso_region)
    instance_arn_ck = get_instance_arn(ck_session, ck_sso_region)
    
    
    org_client = customer_session.client("organizations", region_name=customer_sso_region)
    identitystore_client = customer_session.client("identitystore", region_name=customer_sso_region)
    sso_admin = customer_session.client("sso-admin", region_name=customer_sso_region)
    

    accounts = list_account(org_client)
    all_assignment = get_all_assignment(accounts, instance_arn_customer, instance_id_customer, sso_admin, identitystore_client)
    grouped_output = group_by_account(all_assignment)

    with open("account_assignment-diya.json", "w") as f:
        json.dump(grouped_output, f, indent=4)
        print("\n--OUTPUT--")
        for account in grouped_output:
            account_name = account["account_name"]
            for assignment in account["assignments"]:
                name = assignment["name"]
                for perm in assignment["permission_sets"]:
                    print(f"{account_name}-{perm}")

    print("output saved")

    
    applications = list_sso_applications_in_other_account(instance_arn_ck, ck_session, ck_sso_region)

    valid_account_permission_sets = set()
    for account in grouped_output:
        account_name = account["account_name"]
        for assignment in account["assignments"]:
            for perm in assignment["permission_sets"]:
                valid_account_permission_sets.add((account_name.lower(), perm.lower()))

    matched_apps = []
    for app in applications:
        app_name = app.get('Name', '').lower()
        app_arn = app.get('ApplicationArn', 'Unknown')
        for (acc_name, perm_set) in valid_account_permission_sets:
            expected_name = f"{acc_name}-{perm_set}"
            if expected_name == app_name:
                matched_apps.append({
                    "ApplicationName": app.get("Name", ""),
                    "ApplicationArn": app_arn
                })

    with open("application_arn.json", "w") as f:
        json.dump(matched_apps, f, indent=4)
    print(f"{len(matched_apps)} matching applications saved to application_arn.json")

    try:
        create_application_assignments(ck_session, instance_arn_ck, instance_id_ck, ck_sso_region)
    except Exception as e:
        print(f"Error during application assignments: {e}")

if __name__ == "__main__":
    main()
