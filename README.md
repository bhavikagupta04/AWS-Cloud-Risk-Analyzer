# AWS Cloud Security Analyzer 🔐

## Overview
An extensible, Python-based security scanner for AWS environments. Designed for security engineers, DevSecOps teams, and auditors, the tool identifies high-risk misconfigurations in IAM, S3, EC2, and more — with a Dash dashboard, PDF reporting, and Lambda-ready architecture. Built with CIS benchmarks and real-world security best practices in mind.

## Features
- Detects public S3 buckets
- Flags overly permissive security groups
- Alerts on root account usage
- Identifies IAM users without MFA
- Web UI with Dash
- Optional PDF report output

## Usage
```bash
python dashboard.py          # Launch the web dashboard
python report_generator.py   # Generate a PDF report
```

# Run the dashboard
python dashboard.py

# (Optional) Generate a PDF report
python report_generator.py

## Future Enhancements

- ✅ Add support for CloudFormation template linting
- 🕒 Scheduled scans using EventBridge + Lambda
- 📬 Slack/Email integration for alert delivery
- 🔍 Extend to check GuardDuty/Config/Trusted Advisor

## Screenshots

![Screenshot image](https://github.com/user-attachments/assets/da1b9677-69a6-4eec-a982-9327e30f8af2)
