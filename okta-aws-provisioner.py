#!/usr/bin/env python3

import argparse
import json
import logging
import os

import boto3
import requests


def create_okta_application(app_name,
                            aws_account_id,
                            iam_role_name,
                            iam_idp_name,
                            okta_fqdn,
                            okta_token):
    """Creates an Okta application.

    Note: There is an Okta Python SDK, but it currently doesn't have a way to
    get the metadata, so just using requests for everything.

    Args:
        app_name: the name of the Okta application to be created.
        aws_account_id: the account ID of the AWS account where the Okta
            application will direct users.
        iam_role_name: used to construct the role ARN to match the role created
            in AWS.
        iam_idp_name: used to construct the identity provider ARN to
        match the identity provider in AWS.
        okta_fqdn: hostname of the Okta API. Used to construct URL.
        okta_token: Okta API Token.
    Returns:
        sso_metadata: Identity Provider Metadata - which should be used when
            creating an IAM Identity Provider.
    """
    okta_api_url = 'https://{}/api/v1'.format(okta_fqdn)
    # headers used when making JSON requests
    json_headers = {'Authorization': 'SSWS {}'.format(okta_token),
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'}
    # headers used when making XML requests
    xml_headers = {'Authorization': 'SSWS {}'.format(okta_token),
                   'Accept': 'application/xml',
                   'Content-Type': 'application/xml'}
    # Derive the arns of the idp and role based on name and account id
    iam_idp_arn = 'arn:aws:iam::{}:saml-provider/{}'.format(
        aws_account_id, iam_idp_name)
    iam_role_arn = 'arn:aws:iam::{}:role/{}'.format(
        aws_account_id, iam_role_name)
    app_definition = {
      'name': 'amazon_aws',
      'label': app_name,
      'signOnMode': 'SAML_2_0',
      'settings': {
        'app': {
          'identityProviderArn': '{},{}'.format(iam_idp_arn,
                                                iam_role_arn),
          'awsEnvironmentType': 'aws.amazon',
          'loginURL': 'https://console.aws.amazon.com/ec2/home'
        }
      }
    }

    create_app_url = '{}/apps'.format(okta_api_url)
    create_app_response = requests.post(create_app_url,
                                        json=app_definition,
                                        headers=json_headers)
    logger.debug(create_app_response)
    if create_app_response.status_code == 200:
        app_id = create_app_response.json()['id']
        logger.info(
            "Application {} created with id {}".format(app_name, app_id)
        )
    else:
        raise RuntimeError(
            "Okta App {} could not be created. Error is: {}".format(
                app_name, create_app_response.text))

    sso_metadata_url = create_app_response.json()['_links']['metadata']['href']
    sso_metadata = requests.get(sso_metadata_url, headers=xml_headers).text

    return sso_metadata


def create_iam_role(role_name, iam_client, aws_account_id, iam_idp_name,
                    role_policy_arns, trusted_aws_accounts=None):
    """Creates an IAM role to be assumed via Okta.

    Args:
        role_name: name of the IAM role.
        iam_client: an object representing a boto3.iam connection.
        aws_account_id: id of the AWS account where Okta is being provisioned.
        iam_idp_name: used to construct the identity provider ARN to
        match the identity provider in AWS.
        role_policy_arns: list of policy ARNs to attach to the role.
        trusted_aws_accounts: list of AWS account ids in which this role should
            also allow to assume.
    Returns:
        role_arn: ARN of the created role.
    """
    iam_idp_arn = 'arn:aws:iam::{}:saml-provider/{}'.format(
        aws_account_id, iam_idp_name)

    trust_statements = []
    trust_idp_statement = {
      "Effect": "Allow",
      "Principal": {
        "Federated": iam_idp_arn
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }

    trust_statements.append(trust_idp_statement)

    if trusted_aws_accounts is not None:
        for account_id in trusted_aws_accounts:
            account_arn = 'arn:aws:iam::{}:root'.format(str(account_id))
            trust_account_statement = {
              "Effect": "Allow",
              "Principal": {
                  "AWS": account_arn
              },
              "Action": "sts:AssumeRole"
            }
            trust_statements.append(trust_account_statement)
            logger.info(
                "Added trust for AWS account id {}". format(account_id)
            )

    role_policy_doc = {
      "Version": "2012-10-17",
      "Statement": trust_statements
    }
    create_role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(role_policy_doc))
    logger.debug(create_role_response)
    role_arn = create_role_response['Role']['Arn']
    logger.info("Role {} has been created with ARN {}".format(role_name,
                                                              role_arn))
    for policy_arn in role_policy_arns:
        attach_role_policy_response = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        logger.debug(attach_role_policy_response)
        logger.info("Policy {} has been attached to {}".format(policy_arn,
                                                               role_arn))

    return role_arn


def okta_aws_provision(app_name,
                       iam_client,
                       aws_account_id,
                       role_policy_arns,
                       okta_fqdn,
                       okta_token,
                       iam_rolename=None,
                       trusted_aws_accounts=None):
    """Builds an Okta application and all required AWS resources.

    Args:
        app_name: the name of the Okta application to be created.
        iam_client: an object representing a boto3.iam connection.
        aws_account_id: id of the AWS account where Okta is being provisioned.
        role_policy_arns: list of policy ARNs to attach to the role.
        okta_fqdn: hostname of the Okta API. Used to construct URL.
        okta_token: Okta API Token.
        iam_rolename: Name of IAM role to create, defaults to app_name.
        trusted_aws_accounts: list of account ids
    Returns:
        None.
    """
    iam_idp_name = 'okta-{}'.format(app_name)
    if iam_rolename is None:
        iam_rolename = app_name

    okta_sso_metadata = create_okta_application(app_name,
                                                aws_account_id,
                                                iam_rolename,
                                                iam_idp_name,
                                                okta_fqdn,
                                                okta_token)
    create_saml_provider_response = iam_client.create_saml_provider(
        SAMLMetadataDocument=okta_sso_metadata, Name=iam_idp_name)
    logger.debug(create_saml_provider_response)
    logger.info(
        "IDP {} for Okta has been created in AWS.".format(iam_idp_name)
    )
    role_arn = create_iam_role(iam_rolename,
                               iam_client,
                               aws_account_id,
                               iam_idp_name,
                               role_policy_arns,
                               trusted_aws_accounts=trusted_aws_accounts)
    return role_arn


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Creates an Okta app tied to an IAM Role in AWS.'
    )

    parser.add_argument('--AppName',
                        required=True,
                        help='Name of the App (i.e. Tile) created in Okta.')
    parser.add_argument('--OktaFqdn',
                        required=True,
                        help='FQDN of your Okta instance')
    parser.add_argument('--OktaToken',
                        help='Okta API Token. Can also be set via the '
                             'OKTA_TOKEN environment variable')
    parser.add_argument('--TrustedAwsAccounts',
                        help='Comma separated list of AWS Account Ids that'
                             'should also be trusted to assume the created '
                             'role.')
    parser.add_argument('--RolePolicyArns',
                        help='Comma separated list of Polices that should be '
                             'attached to the created IAM role. '
                             'This argument is not required if the AppName '
                             'includes "admin", "poweruser" or "readonly". '
                             'In this case the provisioner will use the '
                             'related AWS managed policies.')
    parser.add_argument('--LogLevel',
                        choices=['debug', 'info', 'warn', 'error'],
                        default='warn',
                        help="Log level sent to the console. Defaults to warn")
    args = parser.parse_args()

    logging_levels = {
        'debug':    logging.DEBUG,
        'info':     logging.INFO,
        'warn':     logging.WARN,
        'error':    logging.ERROR
    }
    log_level = logging_levels[args.LogLevel.lower()]
    logger = logging.getLogger('okta-aws-provisioner')
    logger.setLevel(log_level)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)

    if args.OktaToken is None:
        okta_token = os.environ.get('OKTA_TOKEN')
    else:
        okta_token = args.OktaToken
    if okta_token is None:
        raise RuntimeError(
            "Okta API Token needs to be set either via OKTA_TOKEN env var or "
            "via --OktaToken arg."
        )

    role_policy_arns = None
    if args.RolePolicyArns is None:
        if 'admin' in args.AppName:
            role_policy_arns = ['arn:aws:iam::aws:policy/AdministratorAccess']
        elif 'poweruser' in args.AppName:
            role_policy_arns = ['arn:aws:iam::aws:policy/PowerUserAccess']
        elif 'readonly' in args.AppName:
            role_policy_arns = ['arn:aws:iam::aws:policy/ReadOnlyAccess']
    else:
        role_policy_arns = args.RolePolicyArns.split(',')

    if role_policy_arns is None:
        raise RuntimeError(
            "Unable to determine the policies that should be attached to "
            "the role. Either use a name where the policy can be derived "
            "or provide a comma sperated list via the --RolePolicyArns "
            "arg."
        )

    if args.TrustedAwsAccounts:
        trusted_aws_accounts = args.TrustedAwsAccounts.split(',')
    else:
        trusted_aws_accounts = None

    sts_client = boto3.client('sts', region_name='us-east-1')
    aws_account_id = sts_client.get_caller_identity()['Account']
    iam_client = boto3.client('iam')

    okta_aws_provision(args.AppName,
                       iam_client,
                       aws_account_id,
                       role_policy_arns,
                       args.OktaFqdn,
                       okta_token,
                       trusted_aws_accounts=trusted_aws_accounts)
