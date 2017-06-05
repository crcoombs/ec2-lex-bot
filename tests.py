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
        regex = re.compile(r'There are [1-9]\d* instances running\.')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

    def test_instance_status(self):
        self.mock_event["currentIntent"]["name"] = "InstanceStatus"
        output = lambda_function.lambda_handler(self.mock_event, None)
        regex = re.compile(r'(i-[a-f0-9]{8,}, a (Windows|Linux) instance, is currently (pending|running|shutting down|terminated|stopping|stopped)\.)+')
        match = regex.match(output["dialogAction"]["message"]["content"])
        self.assertIsNotNone(match)

if __name__ == '__main__':
    unittest.main()
