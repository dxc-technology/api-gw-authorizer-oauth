'''
Created on Aug 9, 2023

Interface classes to use the local cache extension service

@author: Juan Alvarez Ferrando
'''

import time
import urllib.parse
import logging
import json
import requests
from requests.adapters import HTTPAdapter, Retry

requests_session = requests.Session()
retries = Retry(total=0)
adapter = HTTPAdapter(max_retries=retries)
requests_session.mount('http://', adapter)
logger = logging.getLogger("apigwauthlambda.LocalCacheClient")

class CacheAccessError(Exception):
    '''
    Generic error type
    '''

class DynamoDbLocalCacheClient():
    '''
    Facace to access the DynamoDB cache extension
    '''

    def __init__(self, host, port, timeout=5, lifespan=60):
        '''
        Constructor
        '''
        self.host = host
        self.port = port
        self.timeout = timeout
        self.lifespan = lifespan

    def _build_url(self,table, key, key_type, value):
        '''
        Create the URL string to request the local cache extension
        '''
        base_url = f"http://{self.host}:{self.port}"
        enc_table = urllib.parse.quote(table)
        enc_key = urllib.parse.quote(key)
        enc_key_type = urllib.parse.quote(key_type)
        enc_value = urllib.parse.quote(value)
        encoded_url = f"/dynamodb/{enc_table}/{enc_key}?type={enc_key_type}&value={enc_value}&lifespan={self.lifespan}"
        url = f"{base_url}{encoded_url}"
        return url

    def get(self, table, key, key_type, value): #pylint: disable=too-many-locals
        '''
        Get an object from the cache or collect it from DynamoDB
        Returns None if the object is not in either
        '''
        try:
            url = self._build_url(table, key, key_type, value)
            logger.debug("GET sent to local cache: %f", time.monotonic())
            response = requests_session.get(url,timeout=self.timeout)
            logger.debug("GET response received: %f", time.monotonic())
            if response.status_code == 200:
                json_data = response.content.decode('utf8')
                logger.debug("Server Response: %s", json_data)
                data = json.loads(json_data)
                return data
            if response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
                return None
            if response.status_code == 404:
                return None
            logger.warning("Local cache extension returned unexpected status code: %d",
                           response.status_code)
            return None
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e

    def delete(self,table, key, key_type,value):
        '''
        Request cache service to remove an item
        This is used to remove items that have expired according to
        the client's expiration criteria
        '''
        try:
            url = self._build_url(table, key, key_type, value)
            response = requests_session.delete(url,timeout=self.timeout)
            if response.status_code == 200:
                json_data = response.content.decode('utf8')
                logger.debug("Server Response: %s", json_data)
            elif response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
            elif response.status_code == 404:
                logger.warning("Item to delete was not found in local cache: %s",
                               response.content.decode('utf8'))
            else:
                logger.warning("Local cache extension returned unexpected status code: %d",
                               response.status_code)
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e

class S3LocalCacheClient():
    '''
    Facace to access the cache extension for S3 text objects
    '''

    def __init__(self, host, port, timeout=10, lifespan=60):
        '''
        Constructor. Don't set timeout below 5
        '''
        self.host = host
        self.port = port
        self.timeout = timeout
        self.lifespan = lifespan

    def _build_url(self,uri):
        '''
        Create the URL string to request the local cache extension
        '''
        base_url = f"http://{self.host}:{self.port}"
        enc_uri = urllib.parse.quote(uri)
        encoded_url = f"/s3/?uri={enc_uri}&lifespan={self.lifespan}"
        url = f"{base_url}{encoded_url}"
        return url

    def get(self, uri): #pylint: disable=too-many-locals
        '''
        Get an object from the cache or collect it from DynamoDB
        Returns None if the object is not in either
        '''
        try:
            url = self._build_url(uri)
            response = requests_session.get(url,timeout=self.timeout)
            if response.status_code == 200:
                data = response.content.decode('utf8')
                logger.debug("Server Response: %s", data)
                return data
            if response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
                raise CacheAccessError("Cache extension error: %s" % response.content)
            if response.status_code == 404:
                return None
            logger.warning("Local cache extension returned unexpected status code: %d",
                           response.status_code)
            return None
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e

    def delete(self,uri):
        '''
        Request cache service to remove an item
        This is used to remove items that have expired according to
        the client's expiration criteria
        '''
        try:
            url = self._build_url(uri)
            response = requests_session.delete(url,timeout=self.timeout)
            if response.status_code == 200:
                json_data = response.content.decode('utf8')
                logger.debug("Server Response: %s", json_data)
            elif response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
            elif response.status_code == 404:
                logger.warning("Item to delete was not found in local cache: %s",
                               response.content.decode('utf8'))
            else:
                logger.warning("Local cache extension returned unexpected status code: %d",
                               response.status_code)
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e

class SSMLocalCacheClient():
    '''
    Facace to access the cache extension for SSM parameters
    '''

    def __init__(self, host, port, timeout=5, lifespan=60):
        '''
        Constructor.
        '''
        self.host = host
        self.port = port
        self.timeout = timeout
        self.lifespan = lifespan

    def _build_url(self,parameter):
        '''
        Create the URL string to request the local cache extension
        '''
        base_url = f"http://{self.host}:{self.port}"
        enc_parameter = urllib.parse.quote(parameter)
        encoded_url = f"/ssm/?parameter={enc_parameter}&lifespan={self.lifespan}"
        url = f"{base_url}{encoded_url}"
        return url

    def get(self, parameter): #pylint: disable=too-many-locals
        '''
        Get an object from the cache or collect it from DynamoDB
        Returns None if the object is not in either
        '''
        try:
            url = self._build_url(parameter)
            response = requests_session.get(url,timeout=self.timeout)
            if response.status_code == 200:
                data = response.content.decode('utf8')
                logger.debug("Server Response: %s", data)
                return data
            if response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
                raise CacheAccessError("Cache extension error: %s" % response.content)
            if response.status_code == 404:
                return None
            logger.warning("Local cache extension returned unexpected status code: %d",
                           response.status_code)
            return None
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e

    def delete(self,parameter):
        '''
        Request cache service to remove an item
        This is used to remove items that have expired according to
        the client's expiration criteria
        '''
        try:
            url = self._build_url(parameter)
            response = requests_session.delete(url,timeout=self.timeout)
            if response.status_code == 200:
                json_data = response.content.decode('utf8')
                logger.debug("Server Response: %s", json_data)
            elif response.status_code == 500:
                logger.warning("Local cache extension returned status code 500 : %s",
                               response.content.decode('utf8'))
            elif response.status_code == 404:
                logger.warning("Item to delete was not found in local cache: %s",
                               response.content.decode('utf8'))
            else:
                logger.warning("Local cache extension returned unexpected status code: %d",
                               response.status_code)
        except Exception as e:
            logger.exception(e)
            raise CacheAccessError(e) from e
