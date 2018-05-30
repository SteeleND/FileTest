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
# CSR Generator docs-
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
sg = sendgrid.SendGridClient('# ',
                             'Passwod')  # Input username and password of SendGrid account to send emails.
message = sendgrid.Mail()
errorToEmail = 'n.steele@liverez.com'  # email that it sends error reports too.

# User promopt
domainName = input("Enter the Domain: ")
orgID = input("please input the organziation ID")

# File path setup and file name setup variables
keyName = str(domainName) + '-' + str(date) + '.key'
keypath = str(HOME) + "/" + str(domainName) + '-' + str(date) + '.key'
csrName = str(domainName) + '-' + str(date) + '.csr'
csrpath = str(HOME) + '/' + str(domainName) + '-' + str(date) + '.csr'


# If statement to check if the file path exists already. if not, it generates the key.
def generatekey():
    if os.path.exists(str(keypath)):
        print("Certificate already exists in: ")
        print(keypath)
        message = sendgrid.Mail()
        sg = sendgrid.SendGridClient('# ',
                                     'Password')  # Input username and password of SendGrid account to send emails.
        # Sends an email so we can track failures of key generation.
        message.set_from("EMAIL GOES HERE")
        message.add_to(errorToEmail)
        message.set_subject("CSR Generation failed report ")
        message.set_html('CSR Generation failed for ' + domainName + ' KEY file already exists')

        sg.send(message)
        sys.exit(1)
    else:
        with open(keypath, 'wb') as f:
            f.write(asymmetric.dump_private_key(private_key, 'PRIVATE KEY PASSWORD'))
            
    builder = CSRBuilder(
        {
            'country_name': 'US',
            'state_or_province_name': '',
            'locality_name': '',
            'organization_name': '',
            'common_name': 'secure.' + domainName,
        },
        public_key
    )
    request = builder.build(private_key)
    with open(csrpath, 'wb') as f:
        f.write(pem_armor_csr(request))
    f = open(HOME+'/'+csrName)

    readCSR = f.read()


    headers = {
        "X-DC-DEVKEY": "#",
        "Content-Type": "application/json",
    }
    p = json.dumps({
        "certificate": {
            "common_name": str(domainName),
            "csr": readCSR,
            "signature_hash": "sha256",
            "server_platform": {
                "id": 31
            },
        },
        "organization": {
            "id": 275437
        },
        "validity_years": 1,
        "payment_method": "balance",
    })

    response = requests.post('https://www.digicert.com/services/v2/order/certificate/ssl_plus', headers=headers,
                             data=p)

    api_json = json.loads(response.text)
    print(api_json)


    idVal = api_json['id']
    print(idVal)

    sg = sendgrid.SendGridClient('# ', '#')
    message = sendgrid.Mail()
    emailTo = input('Email address for conformation email: ')


    message.add_bcc(emailTo)
    message.add_to('TO EMAIL (USE BCC FOR SECURITY)')
    message.set_from("FROMEMAIL")
    message.set_subject("Recent Digicert SSL Certificate Order Placed")
    message.set_text("""EMAIL MESSAGE GOES HERE.""")



generatekey()
