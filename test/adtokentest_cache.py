import unittest
from  adtokenfactory import AzureAdTokenFactory
from configobj import ConfigObj
from apigwauth import authlambda
import json
import boto3

class TokenTestCache(unittest.TestCase):
        
    def setUp(self):
        config = ConfigObj("./test/test_config_cache.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]
        self.cache_table = self.config["DynamoDBCache"]["Table"]
        client = boto3.client('dynamodb')
        try:
            client = boto3.client('dynamodb')
            client.create_table(
                TableName=self.cache_table,
                AttributeDefinitions=[
                        {
                            'AttributeName':'JWKS_URI',
                            'AttributeType':'S'
                        }
                    ],
                    KeySchema=[
                        {
                            'AttributeName': 'JWKS_URI',
                            'KeyType': 'HASH'
                        }
                    ],
                    BillingMode='PAY_PER_REQUEST'
                )
            waiter = client.get_waiter('table_exists')
            waiter.wait(TableName=self.cache_table)
        except Exception as e:
            print('Raised exception creating table: %s' % str(e))

    def tearDown(self):
        client = boto3.client('dynamodb')
        try:
            client.delete_table(TableName=self.cache_table)
            waiter = client.get_waiter('table_not_exists')
            waiter.wait(TableName=self.cache_table)
        except Exception:
            pass
        
    def xtest_valid_token_no_cache(self):
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event aquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            token = AzureAdTokenFactory(self.client_id,self.tenant_id,self.secret).getToken(self.config["AzureAD"]["Scope"])
            self.assertIsNotNone(token)
            event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

    def test_expired_token_keys_notin_cache(self):
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event aquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        with self.assertRaises(Exception) as context:
            result = authlambda.handler(event, self.config)
            self.assertTrue("expired" in str(context.exception))
            print(result)

    def test_expired_token_keys_in_cache(self):
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event aquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        with self.assertRaises(Exception) as context:
            result = authlambda.handler(event, self.config)
            print('First result')
            print(result)
            self.assertTrue("expired" in str(context.exception))
        with self.assertRaises(Exception) as context:
            result = authlambda.handler(event, self.config)
            print('Second result')
            print(result)
            self.assertTrue("expired" in str(context.exception))
        
if __name__ == '__main__':
    unittest.main()