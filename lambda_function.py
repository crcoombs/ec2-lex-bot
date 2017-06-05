
import boto3
import os
import json

from base64 import b64decode
from botocore.exceptions import ClientError

#Use encrypted environment variables in Lambda, fallback to awscli creds on dev machine
try:
    ENCRYPTED_ACCESS_KEY = os.environ['ACCESS_KEY_ID']
    DECRYPTED_ACCESS_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_ACCESS_KEY))['Plaintext'].decode("utf-8")

    ENCRYPTED_SECRET_KEY = os.environ['SECRET_ACCESS_KEY']
    DECRYPTED_SECRET_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_SECRET_KEY))['Plaintext'].decode("utf-8")

    ec2 = boto3.resource('ec2', aws_access_key_id=DECRYPTED_ACCESS_KEY, aws_secret_access_key=DECRYPTED_SECRET_KEY)
except ClientError as ex:
    if ex.response['Error']['Code'] == 'InvalidCiphertextException':
        ec2 = boto3.resource('ec2')
except KeyError:
    ec2 = boto3.resource('ec2')

def generate_response(response_data):
    output = {
        "dialogAction": {
            "type": None,
            "message": {
                "contentType": "PlainText",
                "content": None
            },
           "intentName": None,
           "slots": None 
        }
    }
    
    for field in response_data.keys():
        if field in ("type", "intentName", "slots"):
            output["dialogAction"][field] = response_data[field]
        elif field == "content":
            output["dialogAction"]["message"]["content"] = response_data[field]
    print (output)
    return output

def get_num_instances():
    running_filter = {'Name': 'instance-state-name', 'Values': ['running']}
    instances = ec2.instances.filter(Filters=[running_filter])
    running_instances = [instance.id for instance in instances]
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": "There are {0} instances running.".format(len(running_instances))
    }
    return generate_response(response_data)

def get_instance_status():
    status = []
    instances = ec2.instances.filter(InstanceIds=[])
    for instance in instances:
        if instance.platform:
            platform = instance.platform
        else:
            platform = 'Linux'
        status.append("{0}, a {1} instance, is currently {2}.".format(instance.id, platform, instance.state["Name"]))
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''.join(status)
    }    
    return generate_response(response_data)

def lambda_handler(event, context):
    output = None
    if event["currentIntent"]["name"] == "RunningInstances":
        output = get_num_instances()
    elif event["currentIntent"]["name"] == "InstanceStatus":
        output = get_instance_status()
        
    if output is not None:
        return output
    else:
        return None

