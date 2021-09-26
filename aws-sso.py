#!/usr/local/bin/python3

from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import base64
from pathlib import Path
import getpass
import re
import inquirer
import configparser
import requests
import boto.s3
import boto.sts
import argparse
import sys
import json
import os

##########################################################################
# Variables

AWS_CONFIG_PATH = f'{Path.home()}/.aws/config'
AWS_CREDENTIAL_PATH = f'{Path.home()}/.aws/credentials'
AWS_SSO_CACHE_PATH = f'{Path.home()}/.aws/sso/cache'
AWS_DEFAULT_REGION = 'us-east-1'

# # region: The default AWS region that this script will connect
# # to for all API calls
# region = 'us-east-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# AWS_CREDENTIAL_PATH: The file where this script will store the temp
# credentials under the saml profile
# AWS_CREDENTIAL_PATH = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# AWS_SSO_URL: The initial URL that starts the authentication process.
AWS_SSO_URL = os.environ['AWS_SSO_URL']

##########################################################################


def _read_config(path):
    config = configparser.RawConfigParser()
    config.read(path)
    return config


def get_user():
    print("Username:", end=' ')
    return input()


def _select_profile():
    config = _read_config(AWS_CREDENTIAL_PATH)

    if len(config.sections()) == 0:
        return 'default'

    profiles = []
    for section in config.sections():
        profiles.append(re.sub(r"^profile ", "", str(section)))
    profiles.sort()

    questions = [
        inquirer.List(
            'name',
            message='Please select an AWS config profile',
            choices=profiles
        ),
    ]
    answer = inquirer.prompt(questions)
    return answer['name'] if answer else sys.exit(1)


def _write_config(profile, config, token):
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)

    config.set(profile, 'output', outputformat)
    config.set(profile, 'region', AWS_DEFAULT_REGION)
    config.set(profile, 'aws_access_key_id', token.credentials.access_key)
    config.set(profile, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(profile, 'aws_session_token', token.credentials.session_token)

    # Write the updated config file
    with open(AWS_CREDENTIAL_PATH, 'w+') as configfile:
        config.write(configfile)


def main():
    parser = argparse.ArgumentParser(
        description='Retrieves AWS credentials from SSO for use with CLI/Boto3 apps.')

    parser.add_argument('--profile',
                        action='store',
                        help='AWS config profile to retrieve credentials for.')

    parser.add_argument('--user',
                        action='store',
                        help='User credential')

    parser.add_argument('--password',
                        action='store',
                        help='User password')

    parser.add_argument('--use-default', '-d',
                        action='store_true',
                        help='Clones selected profile and credentials into the default profile.')

    parser.add_argument('--accounts',
                        action='store',
                        help='Account mapping file to have a more friendly name for roles')

    args = parser.parse_args()

    # Get the federated credentials from the user
    username = args.user if args.user else get_user()
    password = args.password if args.password else getpass.getpass()
    print('')

    # Initiate session handler
    session = requests.Session()

    POSTDATA = {'UserName': username,
                'Password': password}
    response = requests.post(AWS_SSO_URL, data=POSTDATA)

    # Debug the response if needed
    # print(response.text)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, features="html.parser")
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            # print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if (assertion == ''):
        # TODO: Insert valid error checking/handling
        print('Response did not contain a valid SAML assertion')
        sys.exit(0)

    # Debug only
    # print(base64.b64decode(assertion))

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))

    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    if args.accounts:
        # Load account mapping
        # Opening JSON file
        with open(args.accounts) as json_file:
            data = json.load(json_file)

    # ask the user which one they want
    roles = []
    provider_dict = {}
    for awsrole in awsroles:
        arns = awsrole.split(',')
        account = re.findall(r"(?<=arn:aws:iam::)(.*)(?=:role\/)", arns[0])
        role = re.findall(r":role\/(.*)", arns[0])

        if args.accounts:
            option = f"{data[account[0]]} - {role[0]}"
        else:
            option = arns[0]

        roles.append(option)
        provider_dict[option] = {"role_arn": arns[0], "saml_provider": arns[1]}

    questions = [
        inquirer.List(
            'role',
            message='Please select an Role',
            choices=roles
        ),
    ]

    answer = inquirer.prompt(questions)

    role_arn = provider_dict[answer['role']]['role_arn']
    principal_arn = provider_dict[answer['role']]['saml_provider']

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    conn = boto.sts.connect_to_region(AWS_DEFAULT_REGION)
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

    # Read in the existing config file
    config = _read_config(AWS_CREDENTIAL_PATH)

    profile = args.profile if args.profile else _select_profile()

    _write_config(profile, config, token)
    if args.use_default and profile != 'default':
        _write_config('default', config, token)


if __name__ == "__main__":
    main()
