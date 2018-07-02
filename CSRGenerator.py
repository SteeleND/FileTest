from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr
import os
import datetime
import sendgrid
import sys
import json
import requests

# CSR Generator using CSRBuilder Library
#
# CSRBuilder docs-
# https://github.com/wbond/csrbuilder/blob/master/docs/api.md#subject-attribute
# @author Nathan Steele
#
# Variables for implementation
HOME = os.getenv(
    "USERPROFILE")  # this is the file location of the saved CSR/key files OS USERPROFILE is example: C:\Users\n.steele
public_key, private_key = asymmetric.generate_pair('rsa',
                                                   bit_size=2048)  # RSA Public key, encryption type, bit size is adjustable, CSRs do not go under 2048
now = datetime.datetime.now()  # generates timestamp for the filenames
date = now.date()
# sg = sendgrid.SendGridClient('Username',
#                              'Password')  # Input username and password of SendGrid account to send emails.
# message = sendgrid.Mail()
errorToEmail = 'ErrorEmail'  # email that it sends error reports too.

# User promopt variables, URL AND DIGICERT ORGANIZATION ID.
domainName = input("Enter the Domain: ")
orgID = input("please input the organziation ID: ")
expireDate = input('expiration date: ')
country = input("Country: ")
state = input("State: ")
city = input("City: ")
companyName = input("Company name: ")
years = input("Number of years cert: ")
# File path setup and file name setup variables
keyName = str(domainName) + '-' + str(date) + '.key'
keypath = str(HOME) + "/" + str(domainName) + '-' + str(date) + '.key'
csrName = str(domainName) + '-' + str(date) + '.csr'
csrpath = str(HOME) + '/' + str(domainName) + '-' + str(date) + '.csr'


# If statement to check if the file path exists already. If not, it generates the key.
def generatekey():
    if os.path.exists(str(keypath)):
        print("Certificate already exists in: ")
        print(keypath)
        message = sendgrid.Mail()
        sg = sendgrid.SendGridClient('Username ',
                                     'Password')  # Input username and password of SendGrid account to send emails.
        # Sends an email so we can track failures of key generation.
        message.set_from("Email Notification")
        message.add_to(errorToEmail)
        message.set_subject("CSR Generation failed report ")
        message.set_html('CSR Generation failed for ' + domainName + ' KEY file already exists')

        sg.send(message)
        sys.exit(1)
    else:
        with open(keypath, 'wb') as f:
            f.write(asymmetric.dump_private_key(private_key, 'ENCRYPT'))# encrypts private key, using a password to unencrypt

    builder = CSRBuilder(
        {
            'country_name': country,
            'state_or_province_name': state,
            'locality_name': city,
            'organization_name': companyName,
            'common_name': 'secure.' + domainName,
        },
        public_key
    )
    request = builder.build(private_key)
    # Writes the CSR to a file
    with open(csrpath, 'wb') as f:
        f.write(pem_armor_csr(request))
    f = open(HOME + '/' + csrName)
    readCSR = f.read()

    # AUTH INFORMATION FOR DIGICERT
    headers = {
        "X-DC-DEVKEY": "",
        "Content-Type": "application/json",
    }
    # Parameters for the DigiCert order
    p = json.dumps({
        "certificate": {
            "common_name": str('secure.' + domainName),
            "csr": readCSR,
            "signature_hash": "sha256",
            "server_platform": {
                "id": 31
            },
        },
        "organization": {
            "id": orgID
        },
        "validity_years": years,
        "payment_method": "balance",
    })

    response = requests.post('https://www.digicert.com/services/v2/order/certificate/ssl_plus', headers=headers,
                             data=p)

    api_json = json.loads(response.text)
    print(api_json)

    idVal = api_json['id']
    print(idVal)

    sg = sendgrid.SendGridClient('Username ', 'Password')  # Creates email, sends to the account contact notifing of order
    message = sendgrid.Mail()

    # Grabbed the DigiCert order information for the confirmation email
    clientInfo = requests.get('https://www.digicert.com/services/v2/order/certificate/' + str(idVal), headers=headers)
    info_json = json.loads(clientInfo.text)
    # Grabs details from the Order confirmation for email notification
    clientFirstName = info_json['organization_contact']['first_name']
    clientName = info_json['organization_contact']['first_name'] + ' ' + info_json['organization_contact']['last_name']
    clientEmail = info_json['organization_contact']['email']
    clientPhone = info_json['organization_contact']['telephone']

    emailString = """Hello """ + str(clientFirstName) + """,
Your DigiCert SSL Certificate order has been placed and is pending your verification. If the new order is not issued soon, your current SSL Certificate will expire. As a result, your secure, online, check out page will no longer function along with your LiveScore survey system.
We recommend you contact DigiCert directly to help ensure your SSL Certificate is issued in a timely manner.

Your Order Number: """ + str(idVal) + """

Your Current SSL Certificate Expiration: """ + str(expireDate) + """

DigiCert Business Contact Associated with Order (Please confirm this information is correct): 
""" + str(clientName) + """
""" + str(clientEmail) + """
""" + str(clientPhone) + """

DigiCert Support Phone Number: 801-701-9600

DigiCert Support Email: support@digicert.com

Most of the time, DigiCert attempts an outbound call to the business contact listed in their system. DigiCert requires this phone call as part of their verification process before your SSL Certificate can be issued. If your business contact number listed above is incorrect, please let me know as soon as possible so I can update the order information."""

    message.add_bcc(clientEmail)
    message.add_to('User Email')  # Set add_to email for the users email so that you can monitor the sent emails
    message.set_from("FROM EMAIL")  # the From field value, for people to see
    message.set_subject("Recent Digicert SSL Certificate Order Placed")
    message.set_text(emailString)
    print("email sent to: " + str(clientEmail))
    sg.send(message)


generatekey()
