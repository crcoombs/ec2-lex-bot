import unittest
import re
import lambda_function

class TestReadFunctions(unittest.TestCase):
    def setUp(self):
        self.mock_event = {
            "currentIntent": {
                "name": "intent-name",
                "slots": {
                    "slot-name": "value"
                },
                "confirmationStatus": "None, Confirmed, or Denied",
            },
            "bot": {
                "name": "bot-name",
                "alias": "bot-alias",
                "version": "bot-version"
            },
            "userId": "user-id specified in the POST request to Amazon Lex.",
            "inputTranscript": "Text used to process the request",
            "invocationSource": "FulfillmentCodeHook or DialogCodeHook",
            "outputDialogMode": "Text or Voice",
            "messageVersion": "1.0",
            "sessionAttributes": {
                "key1": "value1",
                "key2": "value2"
            }
        }

    def test_num_instances(self):
        self.mock_event["currentIntent"]["name"] = "RunningInstances"
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'There are [0-9]\d* instances running\.')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

    def test_instance_status(self):
        self.mock_event["currentIntent"]["name"] = "InstanceStatus"
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'No\. \d: id (i-[a-f0-9]{8,}, a (Windows|Linux) instance, is currently (pending|running|shutting down|terminated|stopping|stopped)\. )+')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

    def test_shutdown_reason(self):
        self.mock_event["currentIntent"]["name"] = "ShutdownReason"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": "i-08ef48460a83ae3cf", "short_code": None}
        output = lambda_function.lambda_handler(self.mock_event, None)
        success = re.compile(r'The reason for the shutdown was: .*\. It happened on \d{4}-\d{2}-\d{2} at \d{2}:\d{2}:\d{2} \w{3}\.')
        fail = re.compile(r'This instance is currntly running, so there\'s no information.')
        success_match = success.match(output["dialogAction"]["message"]["content"])
        fail_match = fail.match(output["dialogAction"]["message"]["content"])
        if success_match is not None or fail_match is not None:
            match = True
        else:
            match = None
        self.assertIsNotNone(match)

    def test_shutdown_reason_bad_id(self):
        self.mock_event["currentIntent"]["name"] = "ShutdownReason"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": "deadbeef", "short_code": None}
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'I\'m sorry, there\'s no instance by that name\.')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

    def test_shutdown_reason_short_code(self):
        self.mock_event["currentIntent"]["name"] = "ShutdownReason"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": None, "short_code": "1"}
        self.mock_event["sessionAttributes"] = {"1": "i-08ef48460a83ae3cf"}
        output = lambda_function.lambda_handler(self.mock_event, None)
        success = re.compile(r'The reason for the shutdown was: .*\. It happened on \d{4}-\d{2}-\d{2} at \d{2}:\d{2}:\d{2} \w{3}\.')
        fail = re.compile(r'This instance is currntly running, so there\'s no information.')
        success_match = success.match(output["dialogAction"]["message"]["content"])
        fail_match = fail.match(output["dialogAction"]["message"]["content"])
        if success_match is not None or fail_match is not None:
            match = True
        else:
            match = None
        self.assertIsNotNone(match)

    def test_invalid_short_code(self):
        self.mock_event["currentIntent"]["name"] = "ShutdownReason"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": None, "short_code": "0"}
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'I\'m sorry, that ID is invalid\.')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

    def test_stop_instance(self):
        self.mock_event["currentIntent"]["name"] = "StopInstance"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": "i-08ef48460a83ae3cf", "short_code": None}
        output = lambda_function.lambda_handler(self.mock_event, None)
        success = re.compile(r'The instance is stopping\.')
        fail = re.compile(r'This instance is already stopped\.')
        success_match = success.match(output["dialogAction"]["message"]["content"])
        fail_match = fail.match(output["dialogAction"]["message"]["content"])
        if success_match is not None or fail_match is not None:
            match = True
        else:
            match = None
        self.assertIsNotNone(match)

    def test_start_instance(self):
        self.mock_event["currentIntent"]["name"] = "StartInstance"
        self.mock_event["currentIntent"]["slots"] = {"instance_id": "i-08ef48460a83ae3cf", "short_code": None}
        output = lambda_function.lambda_handler(self.mock_event, None)
        success = re.compile(r'The instance is starting\.')
        fail = re.compile(r'This instance is already running\.')
        success_match = success.match(output["dialogAction"]["message"]["content"])
        fail_match = fail.match(output["dialogAction"]["message"]["content"])
        if success_match is not None or fail_match is not None:
            match = True
        else:
            match = None
        self.assertIsNotNone(match)

    def test_get_address(self):
            self.mock_event["currentIntent"]["name"] = "GetAddress"
            self.mock_event["currentIntent"]["slots"] = {"instance_id": "i-08ef48460a83ae3cf", "short_code": None}
            output = lambda_function.lambda_handler(self.mock_event, None)
            success = re.compile(r'The IP address is (\d{1,3}\.){3}\d{1,3}, the hostname is ec2-(\d{1,3}-){3}\d{1,3}\.compute-1\.amazonaws\.com\.')
            fail = re.compile(r'This instance is stopped, so it doesn\'t have an IP address\.')
            success_match = success.match(output["dialogAction"]["message"]["content"])
            fail_match = fail.match(output["dialogAction"]["message"]["content"])
            if success_match is not None or fail_match is not None:
                match = True
            else:
                match = None
            self.assertIsNotNone(match)

    def test_discovery(self):
        self.mock_event["currentIntent"]["name"] = "Discovery"
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'''I can:
             \* Tell you the number of running instances
             \* Tell you the current state of all your instances
             \* Tell you the reason for an instance being stopped
             \* Tell you the hostname and IP address of an instance
             \* Start a stopped instance
             \* Stop a running instance''')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)



if __name__ == '__main__':
    unittest.main()
