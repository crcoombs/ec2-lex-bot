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
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": '',
        "sessionAttributes": {}
    }
    index = 0
    status = []
    #InstanceIDs=[] gets all instances
    instances = EC2.instances.filter(InstanceIds=[])
    for instance in instances:
        index += 1
        response_data["sessionAttributes"][index] = instance.id
        if instance.platform:
            platform = instance.platform.capitalize()
        else:
            platform = 'Linux'
        status.append("No. {0}: id {1}, a {2} instance, is currently {3}. ".format(index, instance.id, platform, instance.state["Name"]))
    if index == 0:
        response_data["content"] = "There are no existing instances."
    else:
        response_data["content"] = ''.join(status)
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
        if ex.response['Error']['Code'] in ('InvalidInstanceID.NotFound', 'InvalidInstanceID.Malformed'):
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        print(ex.response['Error']['Code'])
        return None
    if transition_string == '':
        response_data["content"] = "This instance is currntly running, so there's no information."
        return response_data
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
        if instance.state["Code"] in (32, 64, 80):
            result = instance.start()
        elif instance.state["Code"] in (0, 16):
            response_data["content"] = "This instance is already running."
            return response_data
        else:
            response_data["content"] = "Unhanded state: {0}".format(instance.state["Code"])
            return response_data
    except ClientError as ex:
        if ex.response['Error']['Code'] in ('InvalidInstanceID.NotFound', 'InvalidInstanceID.Malformed'):
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        print(ex.response['Error']['Code'])
        return None
    if result["StartingInstances"][0]["CurrentState"]["Code"] == 0:
        response_data["content"] = "The instance is starting."
    return response_data

def stop_instance(instance_id):
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    instance = EC2.Instance(instance_id)
    try:
        if instance.state["Code"] in (0, 16):
            result = instance.stop()
        elif instance.state["Code"] in (32, 64, 80):
            response_data["content"] = "This instance is already stopped."
            return response_data
        else:
            response_data["content"] = "Unhanded state: {0}".format(instance.state["Code"])
            return response_data
    except ClientError as ex:
        if ex.response['Error']['Code'] in ('InvalidInstanceID.NotFound', 'InvalidInstanceID.Malformed'):
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        print(ex.response['Error']['Code'])
        return None
    if result["StoppingInstances"][0]["CurrentState"]["Code"] == 64:
        response_data["content"] = "The instance is stopping."
    return response_data

def get_address(instance_id):
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    instance = EC2.Instance(instance_id)
    try:
        if instance.state["Code"] in (0, 16):
            address = instance.public_ip_address
            hostname = instance.public_dns_name
            response_data["content"] = "The IP address is {0}, the hostname is {1}.".format(address, hostname)
            return response_data
        elif instance.state["Code"] in (32, 64, 80):
            response_data["content"] = "This instance is stopped, so it doesn't have an IP address."
            return response_data
        else:
            response_data["content"] = "Unhanded state: {0}".format(instance.state["Code"])
            return response_data
    except ClientError as ex:
        if ex.response['Error']['Code'] in ('InvalidInstanceID.NotFound', 'InvalidInstanceID.Malformed'):
            response_data["content"] = "I'm sorry, there's no instance by that name."
            return response_data
        print(ex.response['Error']['Code'])
        return None

def list_functions():
    response_data = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "content": ''
    }
    response_data["content"] = '''I can:
             * Tell you the number of running instances
             * Tell you the current state of all your instances
             * Tell you the reason for an instance being stopped
             * Tell you the hostname and IP address of an instance
             * Start a stopped instance
             * Stop a running instance'''
    return response_data

def lambda_handler(event, context):
    response_data = {}
    print(event)

    if event["currentIntent"]["name"] in ("ShutdownReason", "StartInstance", "StopInstance", "GetAddress"):
        try:
            instance_id = event["currentIntent"]["slots"]["instance_id"]
            short_code = event["currentIntent"]["slots"]["short_code"]
            if short_code:
                instance_id = event["sessionAttributes"][short_code]
        except KeyError:
                response_data["type"] = "Close"
                response_data["fulfillmentState"] = "Failed"
                response_data["content"] = "I'm sorry, that ID is invalid."
                return generate_response(response_data)

    if event["currentIntent"]["name"] == "RunningInstances":
        response_data = get_num_instances()
    elif event["currentIntent"]["name"] == "InstanceStatus":
        response_data = get_instance_status()
    elif event["currentIntent"]["name"] == "ShutdownReason":
        response_data = get_shutdown_reason(instance_id)
    elif event["currentIntent"]["name"] == "StartInstance":
        response_data = start_instance(instance_id)
    elif event["currentIntent"]["name"] == "StopInstance":
        response_data = stop_instance(instance_id)
    elif event["currentIntent"]["name"] == "GetAddress":
        response_data = get_address(instance_id)
    elif event["currentIntent"]["name"] == "Discovery":
        response_data = list_functions()

    if "sessionAttributes" not in response_data:
        response_data["sessionAttributes"] = event["sessionAttributes"]
    return generate_response(response_data)
