from security_analyzer import run_all_checks

def lambda_handler(event, context):
    findings = run_all_checks()
    return {
        'statusCode': 200,
        'body': '\n'.join(findings)
    }
