import boto3
import botocore

def check_s3_public_buckets():
    s3 = boto3.client('s3')
    findings = []
    buckets = s3.list_buckets().get('Buckets', [])
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant['Grantee']):
                    findings.append(f"Public S3 Bucket: {name}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                findings.append(f"Access Denied: Cannot check ACL for bucket {name}")
            else:
                raise
    return findings

def check_security_groups():
    ec2 = boto3.client('ec2')
    findings = []
    groups = ec2.describe_security_groups()['SecurityGroups']
    for sg in groups:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    findings.append(f"Overly permissive SG: {sg['GroupId']} allows {perm.get('IpProtocol')} on {perm.get('FromPort')} from 0.0.0.0/0")
    return findings

def check_root_usage():
    cloudtrail = boto3.client('cloudtrail')
    findings = []
    events = cloudtrail.lookup_events(LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}])
    if events['Events']:
        findings.append("Root account usage detected")
    return findings

def check_users_without_mfa():
    iam = boto3.client('iam')
    findings = []
    users = iam.list_users()['Users']
    for user in users:
        mfa = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa:
            findings.append(f"IAM User {user['UserName']} has no MFA enabled")
    return findings

def run_all_checks():
    findings = []
    findings += check_s3_public_buckets()
    findings += check_security_groups()
    findings += check_root_usage()
    findings += check_users_without_mfa()
    return findings
