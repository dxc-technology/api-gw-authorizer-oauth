'''
Classes to obtain configuration from different sources
'''

import os
import re
from io import StringIO

import boto3
from configobj import ConfigObj

import cache_extension

class ConfigFactoryS3():
    '''
    Gets configuration from an S3 object
    '''
    def __init__(self,local_lifespan=60):
        '''
        Constructor
        '''
        self.s3 = boto3.resource('s3')
        if not 'DISABLE_LOCAL_CACHE' in os.environ:
            # WARNING: USE 127.0.0.1 and NOT localhost as at least on Windows platform it incurs
            #in a +1 second delay
            self.local_client = cache_extension.S3LocalCacheClient('127.0.0.1',
                                                    os.getenv('LOCAL_CACHE_LISTEN_PORT','8000'),
                                                    lifespan=local_lifespan)
        else:
            self.local_client = None

    def _get_from_s3(self,uri):
        match= re.match('s3://(.+?)/(.*)',uri)
        if match:
            bucket = match.group(1)
            object_path = match.group(2)
            obj = self.s3.Object(bucket,object_path)
            item = obj.get()['Body'].read().decode('utf-8')
            return item
        else:
            raise Exception(f"Invalid S3 URI: {uri}")

    def get_config(self,uri_list,**kvargs):
        '''
        Reads the configuration from one of the passed S3 objects, trying them in
        the given order.
        Raises Exception if none can be read
        '''
        exception_str = ''
        config_str = None
        for uri in uri_list:
            try:
                # Try getting the object from the local cache
                # That will put it the first time it is requested
                if self.local_client:
                    try:
                        config_str = self.local_client.get(uri)
                    except cache_extension.CacheAccessError:
                        pass
                if not config_str:
                    config_str = self._get_from_s3(uri)
            except Exception as e:
                exception_str = exception_str + str(e)
            if config_str:
                break
        if not config_str:
            raise Exception("No config found in any URI:"+exception_str)
        strio = StringIO(config_str)
        kvargs['infile'] = strio
        return ConfigObj(**kvargs)

class ConfigFactorySSM():
    '''
    Gets configuration from an S3 object
    '''
    def __init__(self,local_lifespan=60):
        '''
        Constructor
        '''
        self.ssm = boto3.client('ssm')
        if not 'DISABLE_LOCAL_CACHE' in os.environ:
            '''
            WARNING: USE 127.0.0.1 and NOT localhost as at leat on Windows platform it incurs
            in a +1 second delay
            '''
            self.local_client = cache_extension.SSMLocalCacheClient('127.0.0.1',
                                                os.getenv('LOCAL_CACHE_LISTEN_PORT','8000'),
                                                lifespan=local_lifespan)
        else:
            self.local_client = None

    def get_config(self,parameter,**kvargs):
        '''
        Reads the configuration from a SSM parameter
        Raises Exception if it can't be read
        '''
        config_str = None
        try:
            # Try getting the object from the local cache
            # That will put it the first time it is requested
            if self.local_client:
                try:
                    config_str = self.local_client.get(parameter)
                except cache_extension.CacheAccessError as exc:
                    pass

            if not config_str:
                config_str = self.ssm.get_parameter(Name=parameter,
                                        WithDecryption=True)['Parameter']['Value']
        except Exception as exc:
            raise Exception("No config found in SSM") from exc
        strio = StringIO(config_str)
        kvargs['infile'] = strio
        return ConfigObj(**kvargs)
