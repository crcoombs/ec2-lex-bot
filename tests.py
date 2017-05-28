import unittest
import ec2_lex_bot

class TestReadFunctions(unittest.TestCase):

    def setUp(self):
        self.mock_event = {
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

    def test_num_instances(self):
        self.mock_event["currentIntent"]["name"] = "RunningInstances"
        output = ec2_lex_bot.lambda_handler(self.mock_event,'null')
        self.assertEqual(len(output["dialogAction"]["message"]["content"].split()), 5)

if __name__ == '__main__':
    unittest.main()
