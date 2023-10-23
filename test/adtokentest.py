import unittest
import os
from  adtokenfactory import AzureAdTokenFactory
from configobj import ConfigObj
from apigwauth import authlambda
import json

valid_token=None

def _get_azure_token(event,test):
    global valid_token
    # If {caller-supplied-token} in test event acquire a token interactively
    # otherwise use the received value as the token
    if not valid_token:
        if event["authorizationToken"] == "{caller-supplied-token}":
            token = AzureAdTokenFactory(test.client_id,test.tenant_id,test.secret).getToken(test.config["AzureAD"]["Scope"])
            test.assertIsNotNone(token)
            valid_token = token
    else:
        token = valid_token
    print(token)
    return token
    

class TokenTest(unittest.TestCase):
    
    def setUp(self):
        config = ConfigObj("./test/test_config.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]
        
    def test_valid_token_nocache(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

    def test_valid_token_cache(self):
        global valid_token
        self.config = ConfigObj("./test/test_config_cache.ini")
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Allow")
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Allow")
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Allow")
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Allow")
        print(result)

    def test_expired_token_nocache(self):
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        print(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Deny")

    def test_valid_token_nocache_discovery(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # Force using OIDC discovery by not explicitly providing the JWKS URI
        if "LAMBDA" in self.config and "JwksUrl" in self.config["LAMBDA"]:
            del self.config["LAMBDA"]["JwksUrl"]
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

class ConfigTest(unittest.TestCase):
    
    def setUp(self):
        pass
        
    def test_s3_config_expired_token(self):
        self.assertIsNotNone(os.environ['CONFIG_S3'], 'CONFIG_S3 environment variable not set for test')
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, {})
        print(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Deny")

    def test_ssm_config_expired_token(self):
        self.assertIsNotNone(os.environ['CONFIG_SSM'], 'CONFIG_SMM environment variable not set for test')
        if 'CONFIG_S3' in os.environ:
            os.environ.pop('CONFIG_S3')
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, {})
        print(result)
        self.assertTrue(result["policyDocument"]["Statement"][0]["Effect"] == "Deny")

    
class CustomPolicyTest(unittest.TestCase):
    
    def setUp(self):
        config = ConfigObj("./test/test_config_custom_policy.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]
        
    def test_template_policy(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # Force using OIDC discovery by not explicitly providing the JWKS URI
        if "LAMBDA" in self.config and "JwksUrl" in self.config["LAMBDA"]:
            del self.config["LAMBDA"]["JwksUrl"]
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

class CustomPolicyTestS3(unittest.TestCase):
    
    def setUp(self):
        config = ConfigObj("./test/test_config_custom_policy_s3.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]

    def test_template_policy_s3(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # Force using OIDC discovery by not explicitly providing the JWKS URI
        if "LAMBDA" in self.config and "JwksUrl" in self.config["LAMBDA"]:
            del self.config["LAMBDA"]["JwksUrl"]
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

class CustomPolicyTestGroups(unittest.TestCase):
    
    def setUp(self):
        config = ConfigObj("./test/test_config_custom_policy_groups.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]

    def test_template_policy_groups(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # Force using OIDC discovery by not explicitly providing the JWKS URI
        if "LAMBDA" in self.config and "JwksUrl" in self.config["LAMBDA"]:
            del self.config["LAMBDA"]["JwksUrl"]
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertIsNotNone(result)
        print(result)

class RequiredClaimsTest(unittest.TestCase):
    
    def setUp(self):
        config = ConfigObj("./test/test_config_required_claims.ini")
        self.config = config
        self.client_id = self.config["AzureAD"]["ClientID"]
        self.tenant_id = self.config["AzureAD"]["TenantID"]
        self.secret = self.config["AzureAD"]["ClientSecret"]

    def test_default_required_claims(self):
        global valid_token
        with open("./test/event_token.json","rb") as f:
            event = json.load(f)
        # Force using OIDC discovery by not explicitly providing the JWKS URI
        if "LAMBDA" in self.config and "JwksUrl" in self.config["LAMBDA"]:
            del self.config["LAMBDA"]["JwksUrl"]
        token = _get_azure_token(event,self)
        event["authorizationToken"] = "Bearer "+token
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        print(result)

    def test_no_expiration(self):
        self.config['LAMBDA']['RequiredClaims'].remove('exp')
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        print(result)

    def test_no_issuer(self):
        self.config['LAMBDA']['RequiredClaims'].remove('exp')
        self.config['LAMBDA'].pop('Issuer')
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        print(result)

    def test_no_audience(self):
        self.config['LAMBDA']['RequiredClaims'].remove('exp')
        self.config['LAMBDA'].pop('Audience')
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        print(result)
       
    def test_valid_scope(self):
        self.config['LAMBDA']['RequiredClaims'].remove('exp')
        self.config['LAMBDA']['RequiredScopes']='default'
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        print(result)

    def test_missing_scope(self):
        self.config['LAMBDA']['RequiredClaims'].remove('exp')
        self.config['LAMBDA']['RequiredScopes']=['default','missing']
        with open("./test/event_token_expired.json","rb") as f:
            event = json.load(f)
        # If {caller-supplied-token} in test event acquire a token interactively
        # otherwise use the received value as the token
        if event["authorizationToken"] == "{caller-supplied-token}":
            raise Exception("Test event JSON must provide a token in 'authorizationToken'")
        result = authlambda.handler(event, self.config)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')
        print(result)
       
if __name__ == '__main__':
    unittest.main()