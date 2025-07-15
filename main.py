#!/usr/bin/env python3

import argparse
import logging
import sys
import yaml
import json
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="pac-PolicyDryRun: Simulates policy execution against a provided environment."
    )

    parser.add_argument(
        "--policy-file",
        dest="policy_file",
        required=True,
        help="Path to the policy definition file (YAML or JSON)."
    )

    parser.add_argument(
        "--environment-file",
        dest="environment_file",
        required=True,
        help="Path to the environment definition file (YAML or JSON) representing the current infrastructure."
    )

    parser.add_argument(
        "--format",
        dest="format",
        choices=['yaml', 'json'],
        default='yaml',
        help="Format of the policy and environment files (yaml or json). Default: yaml"
    )

    parser.add_argument(
        "--schema-file",
        dest="schema_file",
        required=False,
        help="Path to the JSON schema file for validating the policy definition."
    )

    parser.add_argument(
        "--log-level",
        dest="log_level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help="Set the logging level. Default: INFO"
    )

    return parser

def load_data(file_path, file_format):
    """
    Loads data from a YAML or JSON file.

    Args:
        file_path (str): The path to the file.
        file_format (str): The format of the file ('yaml' or 'json').

    Returns:
        dict: The loaded data as a dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is invalid.
        yaml.YAMLError: If there is an error parsing the YAML file.
        json.JSONDecodeError: If there is an error parsing the JSON file.
    """
    try:
        with open(file_path, 'r') as f:
            if file_format == 'yaml':
                data = yaml.safe_load(f)
            elif file_format == 'json':
                data = json.load(f)
            else:
                raise ValueError("Invalid file format.  Must be 'yaml' or 'json'.")
        return data
    except FileNotFoundError as e:
        logging.error(f"File not found: {file_path}")
        raise e
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {file_path} - {e}")
        raise e
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {file_path} - {e}")
        raise e
    except ValueError as e:
        logging.error(e)
        raise e


def validate_policy(policy_data, schema_file):
  """
  Validates the policy data against a JSON schema.

  Args:
      policy_data (dict): The policy data to validate.
      schema_file (str): The path to the JSON schema file.

  Returns:
      bool: True if the policy is valid, False otherwise.

  Raises:
      FileNotFoundError: If the schema file does not exist.
      jsonschema.exceptions.ValidationError: If the policy data does not conform to the schema.
  """
  if not schema_file:
      logging.warning("Schema file not provided, skipping policy validation.")
      return True

  try:
      schema_data = load_data(schema_file, 'json')
      validate(instance=policy_data, schema=schema_data)
      logging.info("Policy validation successful.")
      return True
  except FileNotFoundError as e:
      logging.error(f"Schema file not found: {schema_file}")
      raise e
  except ValidationError as e:
      logging.error(f"Policy validation failed: {e}")
      return False
  except Exception as e:
      logging.error(f"An unexpected error occurred during policy validation: {e}")
      return False


def evaluate_policy(policy_data, environment_data):
    """
    Evaluates the policy against the environment data.

    Args:
        policy_data (dict): The policy definition.
        environment_data (dict): The environment data.

    Returns:
        list: A list of findings (e.g., violations, warnings).
    """
    findings = []

    # Placeholder for policy evaluation logic.  This will need to be extended
    # based on the specific policy language and environment being targeted.
    #
    # Example:
    # if policy_data['type'] == 'security_group' and environment_data['resource_type'] == 'aws_security_group':
    #   for rule in policy_data['rules']:
    #     if rule['type'] == 'ingress' and rule['port'] == 22:
    #       for sg_rule in environment_data['ingress']:
    #         if sg_rule['port'] == 22:
    #           findings.append(f"Security Group allows SSH access: {environment_data['name']}")

    logging.info("Policy evaluation started.")

    #Basic example - check if a specific resource exists
    if 'resource_must_exist' in policy_data:
        resource_type = policy_data['resource_must_exist']['type']
        resource_name = policy_data['resource_must_exist']['name']

        resource_found = False
        for resource in environment_data.get(resource_type, []):
            if resource.get('name') == resource_name:
                resource_found = True
                break

        if not resource_found:
            findings.append(f"Resource of type '{resource_type}' with name '{resource_name}' does not exist.")

    logging.info("Policy evaluation completed.")
    return findings


def main():
    """
    Main function to execute the policy dry run.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(args.log_level)
    logging.debug("Starting pac-PolicyDryRun with arguments: %s", args)

    try:
        policy_data = load_data(args.policy_file, args.format)
        environment_data = load_data(args.environment_file, args.format)

        # Validate policy against schema if provided
        if args.schema_file:
            if not validate_policy(policy_data, args.schema_file):
                logging.error("Policy validation failed. Exiting.")
                sys.exit(1)

        findings = evaluate_policy(policy_data, environment_data)

        if findings:
            print("Policy Violations:")
            for finding in findings:
                print(f"  - {finding}")
            logging.warning("Policy violations found.")
        else:
            print("No policy violations found.")
            logging.info("No policy violations found.")

        logging.debug("pac-PolicyDryRun completed successfully.")

    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# Example Usage:
#
# 1.  Create policy.yaml:
#     ```yaml
#     resource_must_exist:
#       type: security_groups
#       name: my-security-group
#     ```
#
# 2. Create environment.yaml:
#    ```yaml
#    security_groups:
#      - name: my-security-group
#        id: sg-12345
#      - name: other-security-group
#        id: sg-67890
#    ```
#
# 3. Run the tool:
#    ```bash
#    python pac-PolicyDryRun.py --policy-file policy.yaml --environment-file environment.yaml --format yaml
#    ```
#
# 4. Expected output:
#    ```
#    No policy violations found.
#    ```
#
# 5. Example of a missing resource. Update environment.yaml:
#    ```yaml
#    security_groups:
#      - name: other-security-group
#        id: sg-67890
#    ```
#
# 6. Run the tool:
#    ```bash
#    python pac-PolicyDryRun.py --policy-file policy.yaml --environment-file environment.yaml --format yaml
#    ```
#
# 7. Expected output:
#    ```
#    Policy Violations:
#      - Resource of type 'security_groups' with name 'my-security-group' does not exist.
#    ```