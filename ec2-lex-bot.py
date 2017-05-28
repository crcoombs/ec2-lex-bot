
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

def get_num_instances():
    running_filter = {'Name': 'instance-state-name', 'Values': ['running']}
    instances = ec2.instances.filter(Filters=[running_filter])
    running_instances = [instance.id for instance in instances]
    output = {
                "dialogAction": {
                    "type": "Close",
                    "fulfillmentState": "Fulfilled",
                    "message": {
                        "contentType": "PlainText",
                        "content": "There are {0} instances running.".format(len(running_instances))
                    }
                }
            }    
    print (output)
    return output

def lambda_handler(event, context):
    if event["currentIntent"]["name"] == "RunningInstances":
        output = get_num_instances()
    return output

mock_event = {
  "currentIntent": {
    "name": "intent-name",
    "slots": {
      "slot-name": "value",
      "slot-name": "value",
      "slot-name": "value"
    },
    "confirmationStatus": "None, Confirmed, or Denied (intent confirmation, if configured)",
  },
  "bot": {
    "name": "bot-name",
    "alias": "bot-alias",
    "version": "bot-version"
  },
  "userId": "user-id specified in the POST request to Amazon Lex.",
  "inputTranscript": "Text used to process the request",
  "invocationSource": "FulfillmentCodeHook or DialogCodeHook",
  "outputDialogMode": "Text or Voice, based on ContentType request header in runtime API request",
  "messageVersion": "1.0",
  "sessionAttributes": { 
     "key1": "value1",
     "key2": "value2"
  }
}

mock_event["currentIntent"]["name"] = "RunningInstances"
lambda_handler(mock_event,'null')
