#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
'''
Created on Jul 24, 2023

AWS Lambda extension providing DynamoDB, S3 and SSM cache
Starts a local HTTP server that accept requests for DynamoDB, S3 or SSM and stores
results in a memory cache.
This speeds up lambda access tdata that does not change frequently and
reduces queries to the backend services that consume capacity and cost.

The AWS Lambda execution role must be given privilege to read the required DynamoDB
tables, S3 objects and SSM parameters.

Accepts a DELETE operation that deletes the object from the cache, allowing the
client to remove stale objects base on its own expiration criteria. The object is not
deleted from the source repository, that is the responsibility of the client.

Responses:

- 404: Object not found or table/bucket does not exist
- 500: Internal error. Check the logs
- 200: Returns the object data as a JSON string if a DynamoDB object or as utf8 text if
       an S3 object or SSM parameter

Limitations:

- Can only run in Python AWS Lambda environments
- DynamoDB table must have a single attribute as key
- S3 objects must be UTF-8 text files
- SSM parameters must be of String or SecureString type
- The client is responsible for storing data in the DynamoDB table. The table is not
  populated by this service.
- Decimal data is returned in string form for JSON serialization
- The cache exist at module level and as an extension it is not expected for multiple
  service instances using it
- Service listens on the loopback interface only

@author: Juan Alvarez Ferrando
'''
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import re
import os
import time
import json
from threading import Thread
import decimal

import urllib
import boto3
from boto3.dynamodb.types import TypeDeserializer

root_logger = logging.getLogger('')
root_logger.setLevel(os.getenv('LOCAL_CACHE_LOG_LEVEL',logging.INFO))#pylint: disable=invalid-envvar-default
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s - %(message)s')
ch.setFormatter(formatter)
root_logger.addHandler(ch)
logger = logging.getLogger("cache-extension")

class Cache():
    '''
    In memory cache with expiration time
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.cache={}

    def put(self,key,data,lifespan=60):
        '''
        Insert an object in the cache
        '''
        logger.debug("Storing key %s", key)
        self.cache[key] = {
                'expires': time.time()+lifespan,
                'data': data 
            }

    def get(self,key):
        '''
        Return an object from the cache. None if not found or expired
        '''
        entry = self.cache.get(key,None)
        if entry:
            if entry['expires'] < time.time():
                logger.debug("Expired key %s", key)
                self.cache.pop(key)
                result = None
            else:
                result = entry['data']
        else:
            result = None
        return result

    def pop(self,key):
        '''
        Remove item from cache
        '''
        self.cache.pop(key)

cache = Cache()

class DecimalEncoder(json.JSONEncoder):
    '''
    Used to encode decimal data in JSON format
    '''
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return str(o)
        return super(DecimalEncoder, self).default(o) #pylint: disable=super-with-arguments

class CacheRequestHandler(BaseHTTPRequestHandler):
    '''
    Acts as an AWS Lambda Extension providing a local cache for
    JSON documents obtained from DynamnoDB, S3 or SSM
    '''
    def __init__(self, request, client_address, server):
        self.ddb  = boto3.client('dynamodb')
        self.s3 = boto3.resource('s3')
        self.ssm = boto3.client('ssm')
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _respond_500(self,msg):
        '''
        Send 500 response code with message
        '''
        self.send_error(500, msg)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()

    def _respond_404(self,msg):
        '''
        Send 404 response code with message
        '''
        self.send_error(404, msg)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()

    def _respond_200(self,data,content_type):
        '''
        Send 200 response code with data
        '''
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()
        self.wfile.write(data.encode('utf8'))

    def _get_dynamodb_document(self,table,key,datatype,value):
        '''
        Try to load the item from the DynamoDB table
        '''
        result = self.ddb.get_item(TableName=table,Key={key:{datatype:value}})
        if 'Item' in result:
            deserializer = TypeDeserializer()
            python_data = {k: deserializer.deserialize(v) for k,v in result['Item'].items()}
            return python_data
        else:
            return None

    def _process_delete_request(self,path):
        '''
        Remove an item from the cache. 404 if not in the cache, 200 if deleted
        Items are not deleted from DynamoDB or S3 source
        '''
        item = cache.get(path)
        if item:
            cache.pop(path)
            self._respond_200(json.dumps({"Message":"Deleted"}),content_type='application/json')
        else:
            self._respond_404("Not Found")

    def _process_dynamo_get_request(self,path):
        '''
        Caches items from DynamoDB tables
        '''
        try:
            match = re.match('/dynamodb/(.+)/(.+)\?type=(.+)&value=(.+)&lifespan=(.+)',path) # pylint: disable=anomalous-backslash-in-string
            if match:
                item = cache.get(path)
                logger.debug("(TRACE) Cache checked: %f", time.monotonic())
                if not item:
                    table = urllib.parse.unquote(match.group(1))
                    key = urllib.parse.unquote(match.group(2))
                    datatype = urllib.parse.unquote(match.group(3))
                    value = urllib.parse.unquote(match.group(4))
                    lifespan = int(urllib.parse.unquote(match.group(5)))
                    logmsg = f"Querying DynamoDB for:\nTable: {table}\n\
                            Key:{key}\nType:{datatype}\nvalue:{value}"
                    logger.debug(logmsg)
                    item = self._get_dynamodb_document(table, key, datatype, value)
                    if item:
                        logger.debug("Storing in local cache: %s", str(item))
                        cache.put(path, item, lifespan)
                    else:
                        self._respond_404("Not found")
                        return
                else:
                    logger.debug("Key found in local cache")
                logger.debug("(TRACE) Responding: %f", time.monotonic())
                self._respond_200(json.dumps(item,cls=DecimalEncoder),
                                  content_type='application/json')
                logger.debug("(TRACE) Responded: %f", time.monotonic())
            else:
                logger.error("Invalid request specification")
                self._respond_500("Invalid request specification")
        except Exception as e:
            logger.exception(e)
            self._respond_500(str(e))

    def _process_s3_get_request(self,path):#pylint: disable=too-many-nested-blocks
        '''
        Cache S3 utf8 text objects
        '''
        try:
            match = re.match('/s3/\?uri=(.+)&lifespan=(.+)',path) # pylint: disable=anomalous-backslash-in-string
            if match:
                item = cache.get(path)
                if not item:
                    uri = urllib.parse.unquote(match.group(1))
                    lifespan = int(urllib.parse.unquote(match.group(2)))
                    try:
                        logger.debug("GET %s",uri)
                        match= re.match('s3://(.+?)/(.*)',uri)
                        if match:
                            bucket = match.group(1)
                            object_path = match.group(2)
                            obj = self.s3.Object(bucket,object_path)
                            item = obj.get()['Body'].read().decode('utf-8')
                            if item:
                                logger.debug("Storing in local cache: %s", str(item))
                                cache.put(path, item, lifespan)
                            else:
                                self._respond_404("Not found")
                                return
                        else:
                            raise Exception(f"Invalid S3 URI: {uri}")
                    except Exception as s3_exc:
                        if 'NoSuchKey' in str(s3_exc) or 'NoSuchBucket' in str(s3_exc):
                            self._respond_404("Not found")
                            return
                        else:
                            self._respond_500(str(s3_exc))
                            return
                else:
                    logger.debug("Key found in local cache")
                print(item)
                self._respond_200(item,content_type='text/plain; charset=utf-8')
            else:
                logger.error("Invalid request specification")
                self._respond_500("Invalid request specification")
        except Exception as exc:
            logger.exception(exc)
            self._respond_500(str(exc))

    def _process_ssm_get_request(self,path):
        '''
        Cache SSM String or SecureString parameters
        '''
        try:
            match = re.match('/ssm/\?parameter=(.+)&lifespan=(.+)',path) # pylint: disable=anomalous-backslash-in-string
            if match:
                item = cache.get(path)
                if not item:
                    parameter = urllib.parse.unquote(match.group(1))
                    lifespan = int(urllib.parse.unquote(match.group(2)))
                    try:
                        logger.debug("GET %s",parameter)
                        item = self.ssm.get_parameter(Name=parameter,WithDecryption=True)\
                                    ['Parameter']['Value']
                        cache.put(key=path,data=item,lifespan=lifespan)
                    except Exception as exc:
                        if 'NotFound' in str(exc):
                            self._respond_404("Not found")
                            return
                        else:
                            self._respond_500(str(exc))
                            return
                else:
                    logger.debug("Key found in local cache")
                print(item)
                self._respond_200(item,content_type='text/plain; charset=utf-8')
            else:
                logger.error("Invalid request specification")
                self._respond_500("Invalid request specification")
        except Exception as exc:
            logger.exception(exc)
            self._respond_500(str(exc))

    def do_GET(self): #pylint: disable=invalid-name
        '''
        Called when server receives a GET verb request
        '''
        logger.debug("%f GET request,\nPath: %s\nHeaders:\n%s\n",
                     time.monotonic(), str(self.path), str(self.headers))
        if self.path.startswith('/dynamodb/'):
            self._process_dynamo_get_request(self.path)
        elif self.path.startswith('/s3/'):
            self._process_s3_get_request(self.path)
        elif self.path.startswith('/ssm/'):
            self._process_ssm_get_request(self.path)
        else:
            logger.error('Path must start with "/dynamodb/", "/s3/" or "/ssm/')

    def do_DELETE(self): #pylint: disable=invalid-name
        '''
        Called when server receives a DELETE verb request
        '''
        logger.debug("DELETE request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        if self.path.startswith('/dynamodb/') or self.path.startswith('/s3/'):
            self._process_delete_request(self.path)
        else:
            logger.error('Path must start with "/dynamodb/" or "/s3/"')

# Following code comes from
# https://github.com/aws-samples/aws-lambda-extensions/tree/main/python-example-extension/python-example-extension
# Used under MIT license
import sys #pylint: disable=wrong-import-order,wrong-import-position
import signal #pylint: disable=wrong-import-order,wrong-import-position
import requests #pylint: disable=wrong-import-order,wrong-import-position
from pathlib import Path #pylint: disable=wrong-import-order,wrong-import-position
from typing import Optional #pylint: disable=wrong-import-order,wrong-import-position

server_thread: Optional[Thread]

# global variables
# extension name has to match the file's parent directory name)
LAMBDA_EXTENSION_NAME = Path(__file__).parent.name

# custom extension code
def execute_custom_processing(event):
    # perform custom per-event processing here
    print(f"[{LAMBDA_EXTENSION_NAME}] Received event: {json.dumps(event)}", flush=True)

# boiler plate code
def handle_signal(rsignal, frame): # pylint: disable=unused-argument
    # if needed pass this signal down to child processes
    print(f"[{LAMBDA_EXTENSION_NAME}] Received signal={rsignal}. Exiting.", flush=True)
    sys.exit(0)

def register_extension():
    if not 'AWS_LAMBDA_RUNTIME_API' in os.environ:
        # For local testing out of lambda environment
        return None

    print(f"[{LAMBDA_EXTENSION_NAME}] Registering...", flush=True)
    headers = {
        'Lambda-Extension-Name': LAMBDA_EXTENSION_NAME,
    }
    payload = {
        'events': [
            'SHUTDOWN'
        ],
    }
    response = requests.post(
        url=f"http://{os.environ['AWS_LAMBDA_RUNTIME_API']}/2020-01-01/extension/register",
        json=payload,
        headers=headers,
        timeout=1.5
    )
    ext_id = response.headers['Lambda-Extension-Identifier']
    print(f"[{LAMBDA_EXTENSION_NAME}] Registered with ID: {ext_id}", flush=True)

    return ext_id

def process_events(ext_id):
    headers = {
        'Lambda-Extension-Identifier': ext_id
    }
    while True:
        print(f"[{LAMBDA_EXTENSION_NAME}] Waiting for event...", flush=True)
        if not 'AWS_LAMBDA_RUNTIME_API' in os.environ:
            # For local testing out of lambda environment
            time.sleep(1)
            continue

        response = requests.get(
            url=f"http://{os.environ['AWS_LAMBDA_RUNTIME_API']}/2020-01-01/extension/event/next",
            headers=headers,
            timeout=None
        )
        event = json.loads(response.text)
        if event['eventType'] == 'SHUTDOWN':
            print(f"[{LAMBDA_EXTENSION_NAME}] Received SHUTDOWN event. Exiting.", flush=True)
            sys.exit(0)
        else:
            pass

# End of vendored code

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Start the service in a separate thread
    server_address = ("localhost",int(os.getenv("LOCAL_CACHE_LISTEN_PORT","8000")))
    srv = HTTPServer(server_address,CacheRequestHandler)
    def serve_forever(server):
        with server:
            server.serve_forever()

    server_thread = Thread(target=serve_forever,args=(srv, ))
    server_thread.daemon = True
    server_thread.start()

    # Register extension with API
    extension_id = register_extension()
    # Enter infinite loop fetching events from the Lambda API
    process_events(extension_id)
