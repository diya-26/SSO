import boto3
import json
import sys

def assume_role(accountid: str):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{accountid}:role/CloudKeeper-SSO-Role'
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


def get_identity_store_id_for_client(sso_admin_client, instance_arn):
    response = sso_admin_client.list_instances()
    for instance in response['Instances']:
        if instance['InstanceArn'] == instance_arn:
            return instance['IdentityStoreId']
    return None


def main():
    customer_sso_account = sys.argv[1]
    customer_sso_region = sys.argv[2]
    ck_sso_account = sys.argv[3]
    ck_sso_region = sys.argv[4]
    # customer_sso_account = "285233622501"  # source
    # customer_sso_region = "eu-north-1"
    # ck_sso_account = "364010288443"  # dest
    # ck_sso_region = "us-east-1"
    

    credentials_customer = assume_role(customer_sso_account)
    customer_session = create_session(credentials_customer)
    instance_id_customer = get_instance_id(customer_session, customer_sso_region)
    instance_arn_customer = get_instance_arn(customer_session, customer_sso_region)
    
    # credentials_ck = assume_role(ck_sso_account)
    # ck_session = create_session(credentials_ck)
    # instance_id_ck = get_instance_id(ck_session, ck_sso_region)
    # instance_arn_ck = get_instance_arn(ck_session, ck_sso_region)
    
    
    org_client = customer_session.client("organizations", region_name=customer_sso_region)
    identitystore_client = customer_session.client("identitystore", region_name=customer_sso_region)
    sso_admin = customer_session.client("sso-admin", region_name=customer_sso_region)
    

    accounts = list_account(org_client)
    all_assignment = get_all_assignment(accounts, instance_arn_customer, instance_id_customer, sso_admin, identitystore_client)
    grouped_output = group_by_account(all_assignment)

    with open("account_assignment.json", "w") as f:
        json.dump(grouped_output, f, indent=4)
        print("\n--OUTPUT--")
        for account in grouped_output:
            account_name = account["account_name"]
            for assignment in account["assignments"]:
                name = assignment["name"]
                for perm in assignment["permission_sets"]:
                    print(f"{account_name}-{perm}")

    print("output saved")

    
if __name__ == "__main__":
    main()