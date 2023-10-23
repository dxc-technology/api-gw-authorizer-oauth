'''
Created on July 7, 2023

Lambda function to use as API Gateway Authenticator with JWT tokens

Parts of this code come from AWS Authorizer Lambda template and Darren J Robinson blog:

https://blog.darrenjrobinson.com/decoding-azure-ad-access-tokens-with-python/ 

@author Juan Alvarez Ferrando
'''

import logging
import os
import time
import json
import importlib
import site

from typing import Optional,Dict

import jwt
from jwt.api_jwt import decode_complete as decode_token
from jwt import PyJWKClient

import configobj
import urllib3
import boto3

import util
import cache_extension

from .policy_factory import DefaultPolicyFactory

root_logger = logging.getLogger('')
root_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s - %(message)s')
ch.setFormatter(formatter)
root_logger.addHandler(ch)
logger = logging.getLogger("apigwauthlambda")

class AuthLambdaException(Exception):
    '''
    custom exception
    '''

class JWKSCacheDynamoDB:
    '''
    A DynamoDB backed cache for JWKS
    '''
    def __init__(self,config:Dict,use_local_cache:bool = True)->None:
        '''
        Constructor.
        Gets local extension cache listen port from LOCAL_CACHE_LISTEN_PORT environment
        variable if present, or defaults to port 8000
        Config dictionary must include:
        'Table' for the DynamoDB table
        'LifeSeconds' for the life time of items in the cache
        '''
        self.table_name = config['Table']
        self.lifespan = int(config['LifeSeconds'])
        self.ddb = boto3.resource('dynamodb')
        self.table = self.ddb.Table(self.table_name)
        if use_local_cache:
            '''
            WARNING: USE 127.0.0.1 and NOT localhost as at leat on Windows platform it incurs
            in a +1 second delay
            '''
            self.local_client = cache_extension.DynamoDbLocalCacheClient(host='127.0.0.1',
                                    port=os.getenv('LOCAL_CACHE_LISTEN_PORT','8000'),
                                    lifespan=int(os.getenv('JWKS_CACHE_LIFESPAN','300')))
        else:
            self.local_client = None

    def create_table(self):
        '''
        Creates the configured DynamoDB table with pay per request billing
        and the JWKS_URI as key attribute
        '''
        try:
            client = boto3.client('dynamodb')
            client.create_table(
                TableName=self.table_name,
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
            waiter.wait(TableName=self.table_name)
        except Exception as e: # pylint: disable=broad-except
            logger.debug('Raised exception creating table: %s', str(e))

    def _item_json_decode(self,item):
        '''
        For items received from the local cache, the JSON encoding
        converted numeric data to strings. This function converts them
        back to the same type as if recovered directly from DynamoDB
        to make the client code using the cache transparent to where
        the item was obtained from
        '''
        if item:
            if isinstance(item['Expires'],str):
                item['Expires'] = int(str(item['Expires']))
            if isinstance(item['Created'],str):
                item['Created'] = int(str(item['Created']))
        return item

    def get(self,jwks_uri:str)->(Dict,int):
        '''
        Try to get the keyset from the local cache extension
        if it is not there it will return None, if the cache extension is not
        installed or working, it will fail and we fall back to direct use
        of DynamoDB or no cache if that does not work either
        '''
        item_local = False
        if self.local_client:
            try:
                logger.debug("Attempting local cache")
                item = self._item_json_decode(self.local_client.get(self.table_name,
                                                                   'JWKS_URI','S',jwks_uri))
                if item:
                    item_local = True
                    logger.debug("Keys found in local cache")
                else:
                    logger.debug("Keys NOT found in local cache")
            except Exception as e: # pylint: disable=broad-except
                logger.exception(e)
                item = None
        else:
            item = None
        # Go directly to DynamoDB, maybe the cache extension is not installed or not working,
        #  or the item is not yet populated
        if not item:
            try:
                result = self.table.get_item(Key={'JWKS_URI':jwks_uri},
                                             ProjectionExpression ='Created,JWKS,Expires')
            except Exception as e: # pylint: disable=broad-except
                # Raised when the table does not exist
                if 'ResourceNotFoundException' in str(e):
                    self.create_table()
                    return (None,0)
                raise e
            if 'Item' in result:
                item = result['Item']
        logger.debug(str(item))
        if item:
            current_time = time.time()
            if item['Expires'] < round(current_time):
                try:
                    # remove expired item from the local cache
                    # or we will keep getting it until it expires there
                    if item_local:
                        self.local_client.delete(self.table_name,
                                               'JWKS_URI','S',jwks_uri)
                    # try to remove the stale keys from the cache
                    self.table.delete_item(Key={'JWKS_URI':jwks_uri})
                except Exception: # pylint: disable=broad-except
                    pass
                return (None,0)
            keyset = json.loads(item['JWKS'])
            timestamp = item['Created']
            return (keyset,timestamp)
        # JWKS URI not found in the cache
        return (None,0)

    def put(self,jwks_uri:str,jwks:Dict)->None:
        '''
        Puts don't feed the local cache. It will get fed the
        next time the same JWKS is requested
        '''
        assert 'keys' in jwks

        timestamp = round(time.time())
        item = {
                'JWKS_URI': jwks_uri,
                'Expires': timestamp+self.lifespan,
                'Created': timestamp,
                'JWKS': json.dumps(jwks)
            }
        logger.debug("Storing in cache: %s", str(item))
        try:
            self.table.put_item(Item=item)
        except Exception as e: # pylint: disable=broad-except
            # Raised when the table does not exist
            if 'ResourceNotFoundException' in str(e):
                self.create_table()
                self.table.put_item(Item=item)
            else:
                raise e

class JwtTokenDecoder:
    '''
    Validates and decodes JWT tokens, obtaining the required JWKS keys from
    cache, or the provider JWKS uri.
    The JWKS uri is taken from configuration but if not present will be
    obtained from the OIDC discovery document of the issuer present in the token.
    '''

    # Default REQUIRED claims of the the OAuth 2.0 JWT token profile
    # https://datatracker.ietf.org/doc/html/draft-ietf-oauth-access-token-jwt-07
    required_claims = ['iss','exp','aud','sub','client_id','iat','jti']

    def __init__(self,config:Optional[Dict]):
        self.config = config if config else {}
        if "RequiredClaims" in self.config["LAMBDA"]:
            if isinstance(self.config["LAMBDA"]["RequiredClaims"] , list):
                self.required_claims = self.config["LAMBDA"]["RequiredClaims"]
            else:
                self.required_claims = [self.config["LAMBDA"]["RequiredClaims"]]
        if "UserIdClaim" in self.config["LAMBDA"]:
            self.required_claims.append(self.config["LAMBDA"]['UserIdClaim'])
        if 'RequiredScopes' in self.config['LAMBDA']:
            self.required_claims.append('scp')

        if 'DISABLE_LOCAL_CACHE' in os.environ:
            self.use_local_cache = False
        else:
            self.use_local_cache = True

        self.jwt_client = None

        if 'DynamoDBCache' in config:
            self.cache = JWKSCacheDynamoDB(config['DynamoDBCache'],self.use_local_cache)
        else:
            self.cache = None

        self.headers={}
        self.timeout=2
        self.retries=2

    def __discover_jwks__(self,issuer:str):
        '''
        OIDC discovery is obtained from issuer when Issuer is a URL
        https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
        '''
        if issuer.startswith('https://'):
            discovery_uri = (issuer[:-1] if issuer.endswith('/') else issuer)+ \
                "/.well-known/openid-configuration"
            logger.debug("Will learn JWKS URI from issuer OIDC discovery: %s", discovery_uri)
        elif 'oidc_providers' in self.config and issuer in self.config['oidc_providers']:
            discovery_uri = self.config['oidc_providers'][issuer]
            msg = "OIDC Discovery URI is configured for "+\
                         f"this issuer: {issuer},{discovery_uri}"
            logger.debug(msg)
        else:
            raise AuthLambdaException(f'OIDC discovery not possible for issuer: {issuer}')

        try:
            pmgr = urllib3.PoolManager()
            resp = pmgr.request(method="GET", url=discovery_uri,
                               headers=self.headers,
                               timeout=urllib3.Timeout(connect=1.0,read=self.timeout),
                               retries=self.retries)
            resp_json = json.loads(resp.data)
        except urllib3.exceptions.HTTPError as e:
            raise AuthLambdaException("Failed to collect discovery document: "+str(e)) from e
        else:
        # Defined by OIDC 1.0 RFC :
        # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
            if 'jwks_uri' in resp_json:
                return resp_json['jwks_uri']
            else:
                raise AuthLambdaException('Response does not seem an OPENID discovery document."+\
                " No jwks_uri found')

    def _get_jwks_key_from_client(self,jwks_uri:str,token:str):

        if not self.cache:
            logger.debug("No DynamoDB cache configured")
            logger.debug("(TRACE) JWKS without cache start: %f", time.monotonic())
            # Work without an external cache
            if self.jwt_client:
                if self.jwt_client.uri == jwks_uri:
                    # Got a client for this same JWKS URI, use it
                    signing_key = self.jwt_client.get_signing_key_from_jwt(token)
                    logger.debug("(TRACE) JWKS without cache from existing client: %f",
                                    time.monotonic())
                    return signing_key.key
            # No client for the requested JWKS URI, get one
            self.jwt_client = PyJWKClient(uri=jwks_uri,
                                          lifespan=int(os.getenv('JWKS_CACHE_LIFESPAN','300')))
            signing_key = self.jwt_client.get_signing_key_from_jwt(token)
            logger.debug("(TRACE) JWKS without cache new client: %f", time.monotonic())
            return signing_key.key
        else:
            logger.debug('Using the configured DynamoDB cache')
            logger.debug("(TRACE) JWKS with cache start: %f", time.monotonic())
            if self.jwt_client:
                if self.jwt_client.uri == jwks_uri:
                    logger.debug('Already have a client for this JWKS, using it')
                    # If we have a client for this same JWKS URI, use it
                    fresh_keys = None
                    if self.jwt_client.jwk_set_cache.is_expired():
                        # Our client has stale keys, get them to refresh the cache of others
                        fresh_keys = self.jwt_client.get_jwk_set(refresh=True).keys
                    # Get the key before refreshing the cache, in case it fails
                    # for the key not existing
                    signing_key = self.jwt_client.get_signing_key_from_jwt(token)
                    # Only update the cache if there is no error in getting the key
                    # and if we have new keys
                    if fresh_keys:
                        self.cache.put(jwks_uri=jwks_uri, jwks={'keys':fresh_keys})
                    return signing_key.key
                else:
                    return None
            else:
                return None

    def get_jwks_key(self,token:str,jwks_uri:Optional[str]):#pylint: disable=too-many-locals
        '''
        Uses the provided JWKS URI to get the keys, or uses the 'iss' claim to obtain 
        the issuer's OIDC discovery document and find out the JWKS URI there.
        If DynamoDB cache configuration was provided will use it to find the JKWS
        and if not present will get the key set from the issuer's JWKS URI
        '''
        if not jwks_uri:
            try:
                logger.debug("JWKS URI not provided, trying discovery from iss claim")
                # Try to find out the JWKS URI from the OIDC discovery document
                decoded = jwt.decode(token,options={'verify_signature': False})
                issuer = decoded['iss']
                jwks_uri = self.__discover_jwks__(issuer)
            except Exception as e: # pylint: disable=broad-except
                raise e

        client_key = self._get_jwks_key_from_client(jwks_uri, token)
        if client_key:
            return client_key

        # Have no client for this JWKS URI, try to get the keys from the cache
        logger.debug('Don\'t have a client for this JWKS, trying to find the keys in cache')
        jwks,created = self.cache.get(jwks_uri)
        logger.debug("(TRACE) JWKS response from cache: %f", time.monotonic())
        new_jwks = not jwks
        if new_jwks:
            logger.debug("(TRACE) JWKS get from source URI: %f", time.monotonic())
            # Keys are not in the cache or they expired, get them with a client
            self.jwt_client = PyJWKClient(uri=jwks_uri,
                                          lifespan=int(os.getenv('JWKS_CACHE_LIFESPAN','300')))

            # Get the keys directly from the uri and in JSON format
            jwks = self.jwt_client.fetch_data()
        else:
            lifespan = max(round(time.time())-created,1)
            self.jwt_client = PyJWKClient(uri=jwks_uri,lifespan=lifespan)

            logger.debug("(TRACE) JWKS from cache: %f", time.monotonic())
            
        # We use the obtained JWKS but can't put them into the
        # PyJWT client cache because of issue #914
        # https://github.com/jpadilla/pyjwt/issues/914
        # So we do the lookup of the key ourselves
        unverified=decode_token(jwt=token,options={"verify_signature": False})
        # Check the key in the token is in the set
        kid = unverified['header'].get('kid')
        matched =  [key for key in jwks['keys'] if key['kid']==kid]
        if len(matched)==0:
            raise AuthLambdaException('JWKS set does not contain token key')

        # The set contains the key, put it in the client cache
        kset = jwt.PyJWKSet.from_dict(jwks)
        self.jwt_client.jwk_set_cache = self.jwt_client.jwk_set_cache.put(kset)

        logger.debug("(TRACE) JWKS set obtained: %f", time.monotonic())

        if new_jwks:
            # Put the keys in the external cache
            self.cache.put(jwks_uri=jwks_uri, jwks=jwks)
            logger.debug("(TRACE) Refreshed JWKS key saved in cache: %f", time.monotonic())
        return jwt.PyJWK.from_dict(matched[0]).key

    def decode(self,token:str,jwks:Optional[str]):#pylint: disable=too-many-branches,too-many-statements
        '''
        Validates and decodes the tokens, using the provided JWKS uri or 
        discovered from the issuer OIDC discovery document.
        Validates:
        - Algorithm can only be RS256
        - Configured issuer/s
        - Configured audience/s
        - Presence of required claims
        - Token not expired and already usable if time stamp claims are required
        Required claims include all which are validated, and optionally one configured
        to collect the user principal id from.
        '''
        try:
            msg = None
            # From PyJWT: Do not compute the algorithms parameter based on the alg
            # from the token itself,
            # or on any other data that an attacker may be able to influence, as that might
            # expose you to  various vulnerabilities (see RFC 8725 �2.1). Instead, either
            # hard-code a fixed value for algorithms, or configure it in the same place
            # you configure the key
            unverified_headers = jwt.get_unverified_header(token)
            alg = unverified_headers['alg']

            if alg != 'RS256':
                raise AuthLambdaException('Potential token tampering. Expected alg RS256,'+\
                                          ' but received '+alg)

            signing_key = self.get_jwks_key(token,jwks)
            kwargs = {
                    "jwt":token,
                    "algorithms":[alg],
                    "key":signing_key,
                    "options":{'verify_signature': True,
                        'require':self.required_claims,
                        'verify_aud':False,
                        'verify_iss':False,
                        'verify_exp':'exp' in self.required_claims,
                        'verify_iat':'exp' in self.required_claims,
                        'verify_nbf':'exp' in self.required_claims},
                    "leeway":5
                }
            if "Audience" in self.config["LAMBDA"]:
                logger.debug("Required audience is: %s",self.config["LAMBDA"]["Audience"])
                kwargs["audience"]=[self.config['LAMBDA']['Audience']]
                kwargs["options"]["verify_aud"]=True
                kwargs["options"]["require"].append("aud")
            if "Issuer" in self.config["LAMBDA"]:
                logger.debug("Required issuer is: %s",self.config["LAMBDA"]["Issuer"])
                kwargs["options"]["issuer"]=self.config['LAMBDA']['Issuer']
                kwargs["options"]["verify_iss"]=True
                kwargs["options"]["require"].append("iss")
            decoded_access_token = jwt.decode(**kwargs)

            if 'RequiredScopes' in self.config['LAMBDA']:
                required_scopes = self.config['LAMBDA']['RequiredScopes']
                required_scopes = required_scopes if isinstance(required_scopes, list) \
                                                  else [required_scopes]
                logger.debug('Required scopes: %s',str(required_scopes))
                valid = all(rscp in decoded_access_token['scp'] for rscp in required_scopes)
                if not valid:
                    msg = "Token does not include all required scopes"
                    raise AuthLambdaException(msg)

        except jwt.exceptions.InvalidSignatureError:
            msg = 'Token signature is invalid'
        except jwt.exceptions.ExpiredSignatureError:
            msg = 'Token is expired'
        except jwt.exceptions.InvalidAudienceError:
            msg = 'Audience is not authorized'
        except jwt.exceptions.InvalidIssuerError:
            msg = 'Issuer is not authorized'
        except jwt.exceptions.InvalidIssuedAtError:
            msg = 'Token issued timestamp is in the future'
        except jwt.exceptions.ImmatureSignatureError:
            msg = 'Token not before time has not yet arrived'
        except jwt.exceptions.InvalidKeyError:
            msg = 'Key is not in a valid format'
        except jwt.exceptions.InvalidAlgorithmError:
            msg = 'Algorithm is not supported'
        except jwt.exceptions.MissingRequiredClaimError:
            msg = 'Missing one or more mandatory claims of '+ str(self.required_claims)
        except jwt.exceptions.DecodeError:
            msg = 'Error decoding token because of failed validation'
        finally:
            if msg:
                decoded_access_token = jwt.decode(token,options={"verify_signature": False})
                decoded_access_token_str = json.dumps(decoded_access_token)
                msg = msg + ' : ' + decoded_access_token_str
                logger.error(msg)
                raise AuthLambdaException(msg)

        access_token_formatted = json.dumps(decoded_access_token, indent=2)
        logger.debug("Decoded Access Token: %s", access_token_formatted)
        return decoded_access_token

def handler(event, context): #pylint: disable=too-many-branches,too-many-locals,too-many-statements
    '''
    Handles the AWS API Gateway Authorizer event
    '''
    try:
        logger.debug("(TRACE) Start: %f", time.monotonic())
        logger.debug(event)
        logger.debug("Client token: %s ", (event['authorizationToken']
                                           if 'authorizationToken' in event else 'NOT FOUND'))
        logger.debug("Method ARN: %s", (event['methodArn'] if 'methodArn'
                                        in event else 'NOT FOUND'))

        if 'authorizationToken' not in event:
            logger.debug("Unauthorized. Missing authorization token in request")
            raise AuthLambdaException("Unauthorized")
        if not event['authorizationToken'].startswith('Bearer '):
            logger.debug("Unauthorized. Authorization header is not of Bearer scheme")
            raise AuthLambdaException("Unauthorized")

        token = event['authorizationToken'].split(' ')[1]

        # For unit test purposes
        if isinstance(context,configobj.ConfigObj):
            logger.debug("Running from unit tests")
            if "LAMBDA" in context:
                config = context
        else:
            logger.debug("Running from lambda configuration")
            s3_config = os.getenv("CONFIG_S3", None)
            ssm_config = os.getenv("CONFIG_SSM",None)
            if not(s3_config or ssm_config):
                raise AuthLambdaException("No configuration environment vars found. "+\
                                          "CONFIG_S3 or CONFIG_SSM must be defined")
            if s3_config:
                config = util.ConfigFactoryS3(local_lifespan=int(os.getenv('CONFIG_CACHE_LIFESPAN',
                            '60'))).get_config([s3_config])
                logger.debug('Loaded S3 configuration:\n %s', str(config))
            elif ssm_config:
                config = util.ConfigFactorySSM(local_lifespan=int(os.getenv('CONFIG_CACHE_LIFESPAN',
                            '60'))).get_config(ssm_config)
                logger.debug('Loaded SSM configuration:\n %s', str(config))

        logger.debug("(TRACE) Configured: %f", time.monotonic())

        if 'LOGGING' in config:
            if 'Level' in config['LOGGING']:
                logger.setLevel(config['LOGGING']['Level'])
            if 'Format' in config['LOGGING']:
                fmt = logging.Formatter(config['LOGGING']['Format'])
                ch.setFormatter(fmt)

        token_decoder = JwtTokenDecoder(config)
        try:
            decoded_token = token_decoder.decode(token, config["LAMBDA"].get('JwksUrl',None))
            logger.debug("(TRACE) Decoded: %f", time.monotonic())
        except Exception as e: # pylint: disable=broad-except
            logger.debug("Unauthorized: %s", str(e))
            raise AuthLambdaException('Unauthorized: %s' % str(e)) from e

        # If the layer is not installed default policy is allowing all for requests with valid token
        try:
            if "POLICY_CUSTOM" in config:
                custom_config = config["POLICY_CUSTOM"]
                if "PolicyFactoryModule" in custom_config \
                    and "PolicyFactoryClass" in custom_config:
                    module_name=custom_config["PolicyFactoryModule"]
                    pkg_name=custom_config["PolicyFactoryPackage"]
                    class_name= custom_config["PolicyFactoryClass"]

                    logger.debug("Site paths: %s", str(site.getsitepackages()))
                    logger.debug("Importing: %s", f"{pkg_name}.{module_name}.{class_name}")
                    module = importlib.import_module(
                        name=f"{pkg_name}.{module_name}")
                    logger.debug("Policy customization Layer found")
                    assert hasattr(module, class_name)
                    cls = getattr(module,class_name)
                    factory = cls()
                    logger.debug("Policy customization Class found")
            else:
                factory = DefaultPolicyFactory()
        except Exception as exc: # pylint: disable=broad-except
            logger.debug("Policy customization Layer NOT found: %s",str(exc))
            factory= DefaultPolicyFactory()

        auth_response,resp_context = factory.get_policy(decoded_token,event,config)
        logger.debug("(TRACE) Policy generated: %f", time.monotonic())

        if resp_context:
            auth_response['context'] = resp_context

        logger.debug("Response:\n %s",str(auth_response))
        return auth_response
    except Exception as exc: # pylint: disable=broad-except
        logger.debug("Exiting through exception %s", str(exc))
        if 'Unauthorized' in str(exc):
            factory= DefaultPolicyFactory()
            result,context = factory.get_deny_policy(event)
            return result
        raise exc
