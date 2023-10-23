'''
Created on Jul 19, 2023

@author: Juan Alvarez Ferrando
'''
import unittest
import configparser
from apigwauth.authlambda import JWKSCache_DynamoDB
import time
from jwt import PyJWKClient
import boto3

# This test needs finding AWS credentials in the environment

class Test(unittest.TestCase):

    def setUp(self):
        config = configparser.ConfigParser()
        config.read(["./test/test_config_cache.ini","test_config_cache.ini"])
        self.config = config
        self.jwks_uri = self.config["LAMBDA"]["JwksUrl"]
        self.cache_table = self.config["DynamoDBCache"]["table"]
        self.cache_lifespan = self.config["DynamoDBCache"]["life_seconds"]
        self.cache = JWKSCache_DynamoDB(self.config["DynamoDBCache"])
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

    def testFirstGet(self):
        keys,created = self.cache.get(jwks_uri=self.jwks_uri)
        self.assertIsNone(keys,"First time, result can't be in the cache or must be expired")

    def testPut(self):
        jwt_client = PyJWKClient(uri=self.jwks_uri,lifespan=5)
        keys = jwt_client.get_jwk_set(refresh=True).keys
        self.cache.put(jwks_uri=self.jwks_uri,jwks={'keys':keys})
        
    def testGetNotExpired(self):
        jwt_client = PyJWKClient(uri=self.jwks_uri,lifespan=5)
        keys = jwt_client.get_jwk_set(refresh=True).keys
        self.cache.put(jwks_uri=self.jwks_uri,jwks={'keys':keys})
        keys,created = self.cache.get(self.jwks_uri)
        self.assertIsNotNone(keys, "Should return the set we just inserted")

    def testGetExpired(self):
        jwt_client = PyJWKClient(uri=self.jwks_uri,lifespan=5)
        keys = jwt_client.get_jwk_set(refresh=True).keys
        self.cache.put(jwks_uri=self.jwks_uri,jwks={'keys':keys})
        time.sleep(6)
        keys,created = self.cache.get(self.jwks_uri)
        self.assertIsNone(keys, "Should return None as the JWKS has expired")


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()