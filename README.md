#AWS-SSO

Python script to make it easier to work with SSO Saml federation.

Based on [NeilJed repo](https://github.com/NeilJed/aws-sso-credentials) and on [this AWS post](https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/)

## Requirements

Just run `pip3 install -r requirements.txt` to install all requirements

## Usage

Set the **AWS_SSO_URL** environment variable with the SSO URL:

```sh
export AWS_SSO_URL=https://<fqdn>/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices
```

Then run the script.

```sh
usage: aws-sso.py [-h] [--profile PROFILE] [--user USER] [--password PASSWORD] [--use-default] [--login]

Retrieves AWS credentials from SSO for use with CLI/Boto3 apps.

optional arguments:
  -h, --help           show this help message and exit
  --profile PROFILE    AWS config profile to retrieve credentials for.
  --user USER          User credential
  --password PASSWORD  User password
  --use-default, -d    Clones selected profile and credentials into the default profile.
  --login              Perform an SSO login by default, not just when SSO credentials have expired
```

## Account Mapping

Map your accounts in **account_mapping.json** to have a better looking when choosing between roles.
This file can be referenced with **--accounts** parameter.

Example **account_mapping.json**:
```json
{
    "999999999999": "account-1",
    "888888888888": "account-2"
}
```

This parameter will change from:
```
[?] Please select an Role: arn:aws:iam::888888888888:role/Admin
   arn:aws:iam::999999999999:role/ReadOnly
   arn:aws:iam::888888888888:role/ReadOnly
 > arn:aws:iam::888888888888:role/Admin
```

to: 
```
[?] Please select an Role: account-2 - Admin
   account-1 - ReadOnly
   account-2 - ReadOnly
 > account-2 - Admin
```

## Helpers

You can move the script to your `$PATH`, for example:
```sh
mv aws-sso.py /usr/local/bin/aws-sso
```

and put your mappings on your `$HOME/.aws/` folder:
```sh
mv account_mapping.json $HOME/.aws/account_mapping.json
```

Then create a function on yout `.bashrc` file, like:

```sh
sso ()
{
  AWS_SSO_URL='https://<fqdn>/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices' \
  aws-sso --use-default \
          --profile $1 \
          --user example@company.com \
          --accounts $HOME/.aws/account_mapping.json
}
```

Restart your session and its ready:
```
sso <profile-name>
```

This way its easy to use this script with multiple SSO Accounts, just by creating a new function to each SSO URL.