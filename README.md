# pac-PolicyDryRun
Simulates policy execution against a provided environment (e.g., AWS, Azure) to predict outcomes before actual deployment, highlighting potential conflicts or unintended consequences. Uses boto3 or azure-sdk to fetch resources for simulation. - Focused on Tools to validate infrastructure-as-code (IaC) definitions (e.g., Terraform, CloudFormation) and configuration files against predefined security policies. Automates security checks during infrastructure development and deployment.

## Install
`git clone https://github.com/ShadowGuardAI/pac-policydryrun`

## Usage
`./pac-policydryrun [params]`

## Parameters
- `-h`: Show help message and exit
- `--policy-file`: No description provided
- `--environment-file`: No description provided
- `--format`: No description provided
- `--schema-file`: Path to the JSON schema file for validating the policy definition.
- `--log-level`: Set the logging level. Default: INFO

## License
Copyright (c) ShadowGuardAI
