import argparse
import logging
import os
import sys
import hcl2
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(description="IaC Security Scanner and Resource Drift Detector.")
    parser.add_argument("--iac_file", required=True, help="Path to the IaC file (e.g., Terraform, CloudFormation, Kubernetes manifest).")
    parser.add_argument("--cloud_provider", required=True, choices=['aws', 'azure', 'gcp'], help="Cloud provider (aws, azure, gcp).")
    parser.add_argument("--drift_report", help="Path to save the drift report (optional). If not specified, output to console.")
    parser.add_argument("--log_level", default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Set the logging level.")

    return parser.parse_args()


def load_iac_file(iac_file):
    """
    Loads the IaC file based on its type (Terraform, CloudFormation, Kubernetes).
    Supports Terraform (.tf, .tfvars), CloudFormation (.yaml, .yml, .json), and Kubernetes (.yaml, .yml).
    """
    try:
        file_extension = os.path.splitext(iac_file)[1].lower()

        with open(iac_file, 'r') as f:
            if file_extension in ['.tf', '.tfvars']:
                try:
                    iac_data = hcl2.load(f)
                except Exception as e:
                    logging.error(f"Failed to parse Terraform file {iac_file}: {e}")
                    raise
            elif file_extension in ['.yaml', '.yml']:
                try:
                    iac_data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    logging.error(f"Failed to parse YAML file {iac_file}: {e}")
                    raise
            elif file_extension == '.json':
                try:
                    import json
                    iac_data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse JSON file {iac_file}: {e}")
                    raise
            else:
                raise ValueError(f"Unsupported file type: {file_extension}")

        return iac_data

    except FileNotFoundError:
        logging.error(f"File not found: {iac_file}")
        raise
    except Exception as e:
        logging.error(f"Error loading IaC file {iac_file}: {e}")
        raise


def detect_resource_drift(iac_data, cloud_provider):
    """
    Detects resource drift between the declared state in the IaC file and the actual state in the cloud provider.

    This is a placeholder function. In a real implementation, this function would:
    1. Authenticate to the cloud provider using boto3, azure-identity, or google-cloud-sdk.
    2. Fetch the current state of the infrastructure from the cloud provider.
    3. Compare the declared state (iac_data) with the actual state.
    4. Identify discrepancies (resource drift).
    """
    drift_report = {}

    if cloud_provider == 'aws':
        logging.info("Connecting to AWS...")
        # TODO: Implement AWS authentication and resource state fetching using boto3
        # Example:
        # import boto3
        # session = boto3.Session(profile_name='your_aws_profile')
        # ec2 = session.client('ec2')
        # instances = ec2.describe_instances()
        logging.warning("AWS drift detection is not fully implemented.  Returning an empty report.")

    elif cloud_provider == 'azure':
        logging.info("Connecting to Azure...")
        # TODO: Implement Azure authentication and resource state fetching using azure-identity and azure-mgmt-* libraries
        # Example:
        # from azure.identity import DefaultAzureCredential
        # from azure.mgmt.compute import ComputeManagementClient
        # credential = DefaultAzureCredential()
        # compute_client = ComputeManagementClient(credential, 'your_subscription_id')
        logging.warning("Azure drift detection is not fully implemented.  Returning an empty report.")

    elif cloud_provider == 'gcp':
        logging.info("Connecting to GCP...")
        # TODO: Implement GCP authentication and resource state fetching using google-cloud-sdk
        # Example:
        # from google.cloud import resource_manager
        # client = resource_manager.Client()
        # projects = client.list_projects()
        logging.warning("GCP drift detection is not fully implemented.  Returning an empty report.")

    else:
        raise ValueError(f"Unsupported cloud provider: {cloud_provider}")


    # Placeholder for drift detection logic
    # This would involve comparing resources defined in iac_data with the resources obtained from the cloud provider.
    # Example:
    # if iac_data['resource']['aws_instance']['example']['ami'] != actual_ami:
    #    drift_report['instance_ami_drift'] = f"AMI in IaC: {iac_data['resource']['aws_instance']['example']['ami']}, Actual AMI: {actual_ami}"

    return drift_report

def generate_report(drift_report, output_path=None):
    """
    Generates a report of the resource drift.

    Args:
        drift_report (dict): A dictionary containing the drift detection results.
        output_path (str, optional): The path to save the report to. If None, prints to the console.
    """

    if not drift_report:
        message = "No resource drift detected."
        if output_path:
            try:
                with open(output_path, 'w') as f:
                    f.write(message)
                logging.info(f"No drift report written to {output_path} as no drift was detected.")

            except Exception as e:
                logging.error(f"Error writing no drift report to {output_path}: {e}")

        else:
            print(message)
        return

    report_content = ""
    for resource, drift_info in drift_report.items():
        report_content += f"Resource: {resource}\n"
        report_content += f"Drift: {drift_info}\n\n"

    if output_path:
        try:
            with open(output_path, 'w') as f:
                f.write(report_content)
            logging.info(f"Drift report written to {output_path}")

        except Exception as e:
            logging.error(f"Error writing drift report to {output_path}: {e}")

    else:
        print("Drift Report:\n")
        print(report_content)



def main():
    """
    Main function to orchestrate the IaC security scanning and resource drift detection.
    """
    try:
        args = setup_argparse()

        # Set logging level
        logging.getLogger().setLevel(args.log_level.upper())

        logging.info(f"Starting IaC security scan and drift detection for {args.iac_file} on {args.cloud_provider}")

        # Load the IaC file
        iac_data = load_iac_file(args.iac_file)

        # Detect resource drift
        drift_report = detect_resource_drift(iac_data, args.cloud_provider)

        # Generate the report
        generate_report(drift_report, args.drift_report)

        logging.info("IaC security scan and drift detection completed.")

    except ValueError as ve:
        logging.error(f"Value Error: {ve}")
        sys.exit(1)
    except FileNotFoundError as fnfe:
        logging.error(f"File Not Found Error: {fnfe}")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use exception to get the full stack trace in the logs
        sys.exit(1)


if __name__ == "__main__":
    main()