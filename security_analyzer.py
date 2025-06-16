import boto3
import botocore
from datetime import datetime


def check_s3_public_buckets():
    s3 = boto3.client('s3')
    findings = []
    detailed_findings = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            name = bucket['Name']
            try:
                # Check bucket ACL
                acl = s3.get_bucket_acl(Bucket=name)
                is_public = False

                for grant in acl['Grants']:
                    if 'AllUsers' in str(grant['Grantee']) or 'AuthenticatedUsers' in str(grant['Grantee']):
                        is_public = True
                        break

                # Check bucket policy
                try:
                    policy = s3.get_bucket_policy(Bucket=name)
                    if '"Principal": "*"' in policy['Policy']:
                        is_public = True
                except botocore.exceptions.ClientError:
                    pass  # No bucket policy exists

                if is_public:
                    finding = f"Public S3 Bucket: {name}"
                    findings.append(finding)
                    detailed_findings.append({
                        'service': 'S3',
                        'issue_type': 'Public Bucket',
                        'description': f'Bucket "{name}" is publicly accessible',
                        'severity': 'Critical',
                        'resource': name,
                        'recommendation': 'Review bucket permissions and restrict public access'
                    })

            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    finding = f"Access Denied: Cannot check ACL for bucket {name}"
                    findings.append(finding)
                    detailed_findings.append({
                        'service': 'S3',
                        'issue_type': 'Access Denied',
                        'description': f'Cannot access bucket "{name}" for security analysis',
                        'severity': 'Medium',
                        'resource': name,
                        'recommendation': 'Ensure appropriate permissions for security scanning'
                    })
                else:
                    raise
    except Exception as e:
        findings.append(f"Error checking S3 buckets: {str(e)}")

    return findings, detailed_findings


def check_security_groups():
    ec2 = boto3.client('ec2')
    findings = []
    detailed_findings = []

    try:
        groups = ec2.describe_security_groups()['SecurityGroups']
        for sg in groups:
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_info = ""
                        severity = "High"

                        if perm.get('FromPort') == perm.get('ToPort'):
                            port_info = f"port {perm.get('FromPort')}"
                        else:
                            port_info = f"ports {perm.get('FromPort')}-{perm.get('ToPort')}"

                        # Critical ports
                        if perm.get('FromPort') in [22, 3389, 1433, 3306, 5432]:
                            severity = "Critical"

                        finding = f"Overly permissive SG: {sg['GroupId']} allows {perm.get('IpProtocol')} on {port_info} from 0.0.0.0/0"
                        findings.append(finding)
                        detailed_findings.append({
                            'service': 'EC2',
                            'issue_type': 'Permissive Security Group',
                            'description': f'Security group allows {perm.get("IpProtocol")} traffic on {port_info} from anywhere',
                            'severity': severity,
                            'resource': sg['GroupId'],
                            'recommendation': 'Restrict source IP ranges to specific networks or addresses'
                        })
    except Exception as e:
        findings.append(f"Error checking security groups: {str(e)}")

    return findings, detailed_findings


def check_root_usage():
    cloudtrail = boto3.client('cloudtrail')
    findings = []
    detailed_findings = []

    try:
        events = cloudtrail.lookup_events(
            LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}],
            MaxItems=10
        )

        if events['Events']:
            finding = f"Root account usage detected ({len(events['Events'])} recent events)"
            findings.append(finding)
            detailed_findings.append({
                'service': 'IAM',
                'issue_type': 'Root Account Usage',
                'description': f'Root account has been used {len(events["Events"])} times recently',
                'severity': 'Critical',
                'resource': 'Root Account',
                'recommendation': 'Use IAM users with appropriate permissions instead of root account'
            })
    except Exception as e:
        findings.append(f"Error checking root usage: {str(e)}")

    return findings, detailed_findings


def check_users_without_mfa():
    iam = boto3.client('iam')
    findings = []
    detailed_findings = []

    try:
        users = iam.list_users()['Users']
        users_without_mfa = []

        for user in users:
            mfa = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            if not mfa:
                users_without_mfa.append(user['UserName'])
                finding = f"IAM User {user['UserName']} has no MFA enabled"
                findings.append(finding)
                detailed_findings.append({
                    'service': 'IAM',
                    'issue_type': 'No MFA',
                    'description': f'User "{user["UserName"]}" does not have MFA configured',
                    'severity': 'High',
                    'resource': user['UserName'],
                    'recommendation': 'Enable MFA for all IAM users with console access'
                })
    except Exception as e:
        findings.append(f"Error checking MFA status: {str(e)}")

    return findings, detailed_findings


def check_unused_access_keys():
    iam = boto3.client('iam')
    findings = []
    detailed_findings = []

    try:
        users = iam.list_users()['Users']

        for user in users:
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in access_keys:
                try:
                    last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    if 'LastUsedDate' not in last_used['AccessKeyLastUsed']:
                        finding = f"Unused access key for user {user['UserName']}"
                        findings.append(finding)
                        detailed_findings.append({
                            'service': 'IAM',
                            'issue_type': 'Unused Access Key',
                            'description': f'Access key for user "{user["UserName"]}" has never been used',
                            'severity': 'Medium',
                            'resource': f"{user['UserName']} ({key['AccessKeyId'][:8]}...)",
                            'recommendation': 'Remove unused access keys to reduce attack surface'
                        })
                except Exception:
                    pass  # Skip if unable to get last used date
    except Exception as e:
        findings.append(f"Error checking access keys: {str(e)}")

    return findings, detailed_findings


def check_public_rds_instances():
    rds = boto3.client('rds')
    findings = []
    detailed_findings = []

    try:
        instances = rds.describe_db_instances()['DBInstances']
        for instance in instances:
            if instance.get('PubliclyAccessible', False):
                finding = f"Public RDS instance: {instance['DBInstanceIdentifier']}"
                findings.append(finding)
                detailed_findings.append({
                    'service': 'RDS',
                    'issue_type': 'Public Database',
                    'description': f'RDS instance "{instance["DBInstanceIdentifier"]}" is publicly accessible',
                    'severity': 'Critical',
                    'resource': instance['DBInstanceIdentifier'],
                    'recommendation': 'Disable public accessibility and use VPC security groups'
                })
    except Exception as e:
        findings.append(f"Error checking RDS instances: {str(e)}")

    return findings, detailed_findings


def run_all_checks():
    """Legacy function for backward compatibility"""
    findings = []

    s3_findings, _ = check_s3_public_buckets()
    sg_findings, _ = check_security_groups()
    root_findings, _ = check_root_usage()
    mfa_findings, _ = check_users_without_mfa()

    findings.extend(s3_findings)
    findings.extend(sg_findings)
    findings.extend(root_findings)
    findings.extend(mfa_findings)

    return findings


def get_detailed_findings():
    """Get detailed findings with severity levels and recommendations"""
    all_detailed_findings = []

    # Run all security checks
    checks = [
        check_s3_public_buckets,
        check_security_groups,
        check_root_usage,
        check_users_without_mfa,
        check_unused_access_keys,
        check_public_rds_instances
    ]

    for check_function in checks:
        try:
            _, detailed_findings = check_function()
            all_detailed_findings.extend(detailed_findings)
        except Exception as e:
            # Add error as a finding
            all_detailed_findings.append({
                'service': 'System',
                'issue_type': 'Check Error',
                'description': f'Error running {check_function.__name__}: {str(e)}',
                'severity': 'Medium',
                'resource': 'Security Scanner',
                'recommendation': 'Check AWS credentials and permissions'
            })

    return all_detailed_findings


def get_summary_stats():
    """Get summary statistics for the dashboard"""
    detailed_findings = get_detailed_findings()

    stats = {
        'total_issues': len(detailed_findings),
        'critical_issues': len([f for f in detailed_findings if f['severity'] == 'Critical']),
        'high_issues': len([f for f in detailed_findings if f['severity'] == 'High']),
        'medium_issues': len([f for f in detailed_findings if f['severity'] == 'Medium']),
        'services_affected': len(set([f['service'] for f in detailed_findings])),
        'scan_timestamp': datetime.now().isoformat()
    }

    return stats
