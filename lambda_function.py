#TODO: No instance error handling in status
import os
from base64 import b64decode
import boto3
from botocore.exceptions import ClientError

#Use encrypted environment variables in Lambda, fallback to awscli creds on dev machine
try:
    ENCRYPTED_ACCESS_KEY = os.environ['ACCESS_KEY_ID']
    DECRYPTED_ACCESS_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_ACCESS_KEY))['Plaintext'].decode("utf-8")

    ENCRYPTED_SECRET_KEY = os.environ['SECRET_ACCESS_KEY']
    DECRYPTED_SECRET_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_SECRET_KEY))['Plaintext'].decode("utf-8")

    EC2 = boto3.resource('ec2', aws_access_key_id=DECRYPTED_ACCESS_KEY, aws_secret_access_key=DECRYPTED_SECRET_KEY)
except ClientError as ex:
    if ex.response['Error']['Code'] == 'InvalidCiphertextException':
        EC2 = boto3.resource('ec2')
except KeyError:
    EC2 = boto3.resource('ec2')

def generate_response(response_data):
    output = {
        "dialogAction": {
            "type": '',
            "fulfillmentState": '',
            "message": {
                "contentType": "PlainText",
                "content": ''
            }
        }
    }

    for field in response_data.keys():
        if field in ("type", "fulfillmentState", "slots"):
            output["dialogAction"][field] = response_data[field]
        elif field == "content":
            output["dialogAction"]["message"]["content"] = response_data[field]
        else:
            output[field] = response_data[field]

    print(output)
    return output

def get_num_instances():
    running_filter = {'Name': 'instance-state-name', 'Values': ['running']}
    instances = EC2.instances.filter(Filters=[running_filter])
    running_instances = [instance.id for instance in instances]
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": "There are {0} instances running.".format(len(running_instances))
    }
    return response_data

def get_instance_status():
    status = []
    index = 0
    sessionAttributes = {}
    #InstanceIDs=[] gets all instances
    instances = EC2.instances.filter(InstanceIds=[])
    for instance in instances:
        index += 1
        sessionAttributes[index] = instance.id
        if instance.platform:
            platform = instance.platform.capitalize()
        else:
            platform = 'Linux'
        status.append("No. {0}: id {1}, a {2} instance, is currently {3}. ".format(index, instance.id, platform, instance.state["Name"]))

    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''.join(status)
    }
    if index > 0:
        response_data["sessionAttributes"] = sessionAttributes
    return response_data

def get_shutdown_reason(instance_id):
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    instance = EC2.Instance(instance_id)
    try:
        transition_string = instance.state_transition_reason
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'InvalidInstanceID.NotFound' or ex.response['Error']['Code'] == 'InvalidInstanceID.Malformed':
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        else:
            print(ex.response['Error']['Code'])
            return None
    if transition_string == '':
        response_data["content"] = "This instance is currntly running, so there's no information."
        return response_data
    else:
        reason, time_string = transition_string.split('(')
        reason = reason.strip()
        time_string = time_string.replace(')', '')
        date, time, zone = time_string.split()
        response_data["content"] = "The reason for the shutdown was: {0}. It happened on {1} at {2} {3}.".format(reason, date, time, zone)
        return response_data

def start_instance(instance_id):
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    instance = EC2.Instance(instance_id)
    try:
        if instance.state["Code"] in (0, 16):
            response_data["content"] = "This instance is already running."
            return response_data
        result = instance.start()
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'InvalidInstanceID.NotFound' or ex.response['Error']['Code'] == 'InvalidInstanceID.Malformed':
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        else:
            print(ex.response['Error']['Code'])
            return None
    response_data["content"] = "The instance has been started."
    return response_data

def stop_instance(instance_id):
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    instance = EC2.Instance(instance_id)
    try:
        if instance.state["Code"] in (32, 64, 80):
            response_data["content"] = "This instance is already stopped."
            return response_data
        result = instance.stop()
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'InvalidInstanceID.NotFound' or ex.response['Error']['Code'] == 'InvalidInstanceID.Malformed':
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        else:
            print(ex.response['Error']['Code'])
            return None
    response_data["content"] = "The instance has been stopped."
    return response_data

def lambda_handler(event, context):
    output = None
    try:
        instance_id = event["currentIntent"]["slots"]["instance_id"]
        if instance_id is None:
            short_code = event["currentIntent"]["slots"]["short_code"]
            instance_id = event["sessionAttributes"][short_code]
    except KeyError:
        pass
    print(event)
    if event["currentIntent"]["name"] == "RunningInstances":
        output = get_num_instances()
    elif event["currentIntent"]["name"] == "InstanceStatus":
        output = get_instance_status()
    elif event["currentIntent"]["name"] == "ShutdownReason":
        output = get_shutdown_reason(instance_id)
    elif event["currentIntent"]["name"] == "StartInstance":
        output = start_instance(instance_id)
    elif event["currentIntent"]["name"] == "StopInstance":
        output = stop_instance(id)

    if output is not None:
        if "sessionAttributes" not in output:
            output["sessionAttributes"] = event["sessionAttributes"]
        return generate_response(output)
    else:
        return generate_response({})
