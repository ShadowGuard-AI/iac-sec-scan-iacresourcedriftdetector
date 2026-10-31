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
    parser = argparse.ArgumentParser(description="IaC Resource Drift Detector. Compares a declared IaC file with an actual-state file holding the deployed values in the same parsed shape. It does not contact a cloud provider and does not scan for security misconfigurations.")
    parser.add_argument("--iac_file", required=True, help="Path to the IaC file (e.g., Terraform, CloudFormation, Kubernetes manifest).")
    parser.add_argument("--actual_file", required=True, help="Path to a file holding the actual deployed state in the same parsed shape as the IaC file (Terraform, YAML, or JSON). Drift is the difference between this file and the IaC file.")
    parser.add_argument("--cloud_provider", required=True, choices=['aws', 'azure', 'gcp'], help="Cloud provider the two files describe (aws, azure, gcp). The comparison itself is over the two files for every provider.")
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


def _collect_drift(declared, actual, path, drift_report):
    """
    Walks both parsed structures and records one drift entry per
    differing path, naming the path and both values.
    """
    if isinstance(declared, dict) and isinstance(actual, dict):
        for key in sorted(set(declared) | set(actual), key=str):
            child_path = f"{path}.{key}" if path else str(key)
            if key not in declared:
                drift_report[child_path] = f"declared=<absent>, actual={actual[key]!r}"
            elif key not in actual:
                drift_report[child_path] = f"declared={declared[key]!r}, actual=<absent>"
            else:
                _collect_drift(declared[key], actual[key], child_path, drift_report)
    elif isinstance(declared, list) and isinstance(actual, list):
        if len(declared) != len(actual):
            drift_report[path or "root"] = (
                f"declared has {len(declared)} item(s), actual has {len(actual)} item(s)"
            )
        for index, (declared_item, actual_item) in enumerate(zip(declared, actual)):
            _collect_drift(declared_item, actual_item, f"{path}[{index}]", drift_report)
    elif declared != actual:
        drift_report[path or "root"] = f"declared={declared!r}, actual={actual!r}"


def detect_resource_drift(iac_data, cloud_provider, actual_data):
    """
    Detects resource drift between the declared state in the IaC file
    and the actual state loaded from the actual-state file.

    The comparison runs over the two parsed structures for every
    provider; no cloud provider is contacted. Returns a dict mapping
    each differing path to a line naming the declared and actual
    values. An empty dict means the two parsed structures match.
    """
    if cloud_provider not in ('aws', 'azure', 'gcp'):
        raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

    if not iac_data or not actual_data:
        raise ValueError("Drift detection not performed: the IaC data or the actual state parsed to an empty structure, so there is nothing to compare.")

    drift_report = {}
    _collect_drift(iac_data, actual_data, "", drift_report)
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
            with open(output_path, 'w') as f:
                f.write(message)
            logging.info(f"No drift report written to {output_path} as no drift was detected.")
        else:
            print(message)
        return

    report_content = ""
    for resource, drift_info in drift_report.items():
        report_content += f"Resource: {resource}\n"
        report_content += f"Drift: {drift_info}\n\n"

    if output_path:
        with open(output_path, 'w') as f:
            f.write(report_content)
        logging.info(f"Drift report written to {output_path}")
    else:
        print("Drift Report:\n")
        print(report_content)



def main():
    """
    Main function to orchestrate the IaC resource drift detection.
    """
    try:
        args = setup_argparse()

        # Set logging level
        logging.getLogger().setLevel(args.log_level.upper())

        if args.drift_report and os.path.realpath(args.drift_report) in (
            os.path.realpath(args.iac_file),
            os.path.realpath(args.actual_file),
        ):
            logging.error("Drift report path resolves to an input file, refusing to overwrite it.")
            sys.exit(1)

        logging.info(f"Starting IaC drift detection for {args.iac_file} on {args.cloud_provider}")

        # Load the IaC file and the actual-state file
        iac_data = load_iac_file(args.iac_file)
        actual_data = load_iac_file(args.actual_file)

        # Detect resource drift by comparing the two parsed structures
        drift_report = detect_resource_drift(iac_data, args.cloud_provider, actual_data)

        # Generate the report; a failed write raises and exits 1 below
        generate_report(drift_report, args.drift_report)

        if drift_report:
            logging.warning("Resource drift detected.")
            sys.exit(1)

        logging.info("IaC drift detection completed.")

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