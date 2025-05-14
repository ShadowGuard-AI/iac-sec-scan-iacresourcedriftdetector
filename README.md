# iac-sec-scan-IaCResourceDriftDetector
Compares the declared state in IaC files with the actual deployed infrastructure state in a cloud provider (e.g., AWS, Azure, GCP). Highlights discrepancies (resource drift) to identify unauthorized changes or misconfigurations. Uses `boto3`, `azure-identity`, or `google-cloud-sdk` for cloud interaction. - Focused on Scans Infrastructure-as-Code configuration files (e.g., Terraform, CloudFormation, Kubernetes manifests) for potential security misconfigurations, compliance violations, and best-practice deviations. Generates reports highlighting risky resources and suggested remediations.

## Install
`git clone https://github.com/ShadowStrikeHQ/iac-sec-scan-iacresourcedriftdetector`

## Usage
`./iac-sec-scan-iacresourcedriftdetector [params]`

## Parameters
- `-h`: Show help message and exit
- `--iac_file`: No description provided
- `--cloud_provider`: No description provided
- `--drift_report`: No description provided
- `--log_level`: Set the logging level.

## License
Copyright (c) ShadowStrikeHQ
