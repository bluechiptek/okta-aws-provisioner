# OKTA-AWS-PROVISIONER

The okta-aws-provisioner is a utility that automates the creation of an Okta App (i.e. tile) and related AWS resources to allow AWS console access via Okta.

This software is distributed under the GNU General Public License v3.0. Please see the file LICENSE.txt for terms of use and redistribution.

## DESCRIPTION
The okta-aws-provisioner creates an AWS Console access application in Okta and performs the following in AWS:

* Creates a SAML IDP using metadata provided by Okta
* Creates an IAM role in AWS
  * Sets the IAM role to trust the created SAML IDP
  * Sets the IAM tole to trust one or more AWS accounts to allow cross account access (optional)
* Attached one or more IAM policies to the IAM Role

After the okta-aws-provisioner is run the application will need to be assigned to users and/or groups within Okta. Anyone assigned to the application can click on the tile and will be logged into the AWS console assuming the related role.

Currently only a one-to-one mapping of a Okta Applications to IAM Roles is supported.

## INSTALLATION

okta-aws-provisioner is written in Python3.

A requirements.txt has been provided to install the Python package dependencies.

## CONFIGURATION

All configuration is done via runtime with CLI arguments.

CLI arguments are as follows, but can also be viewed with the `--help` argument (and should be in case this README hasn't been updated).

```
./okta-aws-provisioner.py --help
usage: okta-aws-provisioner.py [-h] --AppName APPNAME --OktaFqdn OKTAFQDN
                               [--OktaToken OKTATOKEN]
                               [--TrustedAwsAccounts TRUSTEDAWSACCOUNTS]
                               [--RolePolicyArns ROLEPOLICYARNS]
                               [--LogLevel {debug,info,warn,error}]

Creates an Okta app tied to an IAM Role in AWS.

optional arguments:
  -h, --help            show this help message and exit
  --AppName APPNAME     Name of the App (i.e. Tile) created in Okta.
  --OktaFqdn OKTAFQDN   FQDN of your Okta instance
  --OktaToken OKTATOKEN
                        Okta API Token. Can also be set via the OKTA_TOKEN
                        environment variable
  --TrustedAwsAccounts TRUSTEDAWSACCOUNTS
                        Comma separated list of AWS Account Ids thatshould
                        also be trusted to assume the created role.
  --RolePolicyArns ROLEPOLICYARNS
                        Comma separated list of Polices that should be
                        attached to the created IAM role. This argument is not
                        required if the AppName includes "admin", "poweruser"
                        or "readonly". In this case the provisioner will use
                        the related AWS managed policies.
  --LogLevel {debug,info,warn,error}
                        Log level sent to the console.
```

## USAGE
An Okta API token is needed to use the okta-aws-provisioner. Directions on how to get an API Token can be found here: https://developer.okta.com/docs/api/getting_started/getting_a_token. The token can be provided either via --OktaToken argument or OKTA_TOKEN env variable.

Example to create an IAM poweruser role and related Okta application for a sandbox account. This sandbox-poweruser role will have the AWS managed PowerUserAccess attached to it. OKTA_TOKEN env variable has been set.

```
./okta-aws-provisioner.py --AppName sandbox-poweruser --OktaFqdn company.okta.com
```


Example to create an IAM role and related Okta application for an account where you wish to specify the roles you wish attached and allow trust fom multiple accounts.

```
./okta-aws-provisioner.py --AppName aws-access --OktaFqdn company.okta.com \
 --TrustedAwsAccounts "123456789012,741085209630" \
 --RolePolicyArns "arn:aws:iam::aws:policy/IAMReadOnlyAccess,arn:aws:iam::aws:policy/AmazonEC2FullAccess"