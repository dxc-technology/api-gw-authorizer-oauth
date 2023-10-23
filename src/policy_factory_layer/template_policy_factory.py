'''
Created on Aug 18, 2023

Policy generation JSON document schema

The resulting policy document is generated from a Jinja2 template

The template can be obtained in two ways:

- Including it with the AWS Lambda layer used to install this policy
  factory. In this case the apigwauth lambda configuration file must
  include the options:
  
[POLICY_CUSTOM]
PolicyFactoryPackage=policy_factory_layer -> Name of the package installed
PolicyFactoryModule=template_policy_factory -> Name of the module with the 
                                               factory class
PolicyFactoryClass=TemplatePolicyFactory -> Name of the factory class
PolicyFactoryTemplateDirectory=templates -> Name of the submodule where
                                            templates are
PolicyFactoryTemplateFile=allow1.j2 -> Name of the template file to use

- From an S3 Object, in which case configuration must be in the form:

[POLICY_CUSTOM]
TEMPLATE_S3=s3://apigwauth.bucket/policy_template.j2

The Jinja2 template processing will receive the following environment data
that can be used in Jinja2 expressions in the template:

token: The JSON decoded token in the form of a Python object
event: The event as received from API Gateway
config: The ConfigObj configuration object
datetime: The datetime.datetime class allowing to use time expressions

The template must generate a valid JSON document conforming with the 
AWS API Gateway lambda authorizer specification:

https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html

@author: Juan Alvarez Ferrando
'''

import os
import logging
import datetime
import json
import importlib.resources
from importlib import import_module

from jinja2 import Environment, FunctionLoader, BaseLoader

from apigwauth import PolicyFactory,PolicyFactoryException
from cache_extension import S3LocalCacheClient,CacheAccessError

logger = logging.getLogger("apigwauthlambda.TemplatePolicyFactory")

class CustomPackageLoader(BaseLoader):
    '''
    Jinja2 Package Loader does not find templates installed as lambda layers
    This reverts to use importlib to find the template file if the stock
    method does not.
    '''
    def __init__(
        self,
        package_name:str,
        package_path:"str"="templates")->None:
        self.package_name = package_name
        self.package_path = package_path

    def get_source(
            self, environment:Environment,template:str):
        '''
        Using importlib resource loading, read the template from the module pointed
        by package_name.package_path
        In python3.8 the directory package_path must include an __init__.py file
        even if empty.
        The open_binary function is deprecated in python 3.11 and wil need to be
        replaced by:
            importlib.resources.files(package_name)
                .joinpath(package_path).joinpath(template).open('rb')
        then the directory does not need to be a Package and have an __init__.py file
        '''
        try:
            package_str = f"{self.package_name}.{self.package_path}" if self.package_path \
                else f"{self.package_name}"

            with importlib.resources.open_binary(package_str,template) as fileh:
                data = fileh.read().decode('utf8')
                return data,fileh.name,datetime.datetime.now()
        except Exception as exc:
            raise ValueError("Importlib could not find the template.\
                Check if there's an __init__.py file") from exc

class TemplatePolicyFactory(PolicyFactory):
    '''
    Customizes an API Gateway Policy document based on a policy 
    generation document and the groups present in the token 'groups' claim
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.local_client = S3LocalCacheClient('localhost',
                                                    os.getenv('LOCAL_CACHE_LISTEN_PORT','8000'))

    def _get_template_s3(self,uri):
        '''
        To be used with Jinja2 FunctionLoader, to load the template
        from an S3 Object
        '''
        try:
            print(uri)
            # Try getting the object from the local cache
            # That will put it the first time it is requested
            try:
                obj = self.local_client.get(uri)
                if not obj:
                    raise Exception("Template S3 object not found")
                return obj
            except CacheAccessError as exc:
                raise exc
        except CacheAccessError as exc:
            raise Exception() from exc

    def _render_template(self,template,loader,event,token,config): #pylint: disable=too-many-arguments
        '''
        Create the Jinja2 environment an render the document from the
        template obtained by the provided loader.
        This abstracts the loader used.
        '''
        environment = Environment(loader=loader,extensions=['jinja2.ext.loopcontrols'],
                                  trim_blocks=True)
        template = environment.get_template(template)
        kwargs = {
                'event':event,
                'token':token,
                'config':config,
                'datetime':datetime.datetime,
                'import_module': import_module
            }
        result = template.render(**kwargs)
        return result

    def get_policy(self,token,event,config):
        '''
        Load template and render policy document from it
        '''
        config_custom = config.get("POLICY_CUSTOM")
        if not config_custom:
            raise PolicyFactoryException("POLICY_CUSTOM configuration group missing")
        try:
            if "TEMPLATE_S3" in config_custom:
                template_src = config_custom.get("TEMPLATE_S3",None)
                loader = FunctionLoader(self._get_template_s3)
            else:
                policy_package=config_custom.get("PolicyFactoryPackage",None)
                policy_package_directory=config_custom.\
                                            get("PolicyFactoryTemplateDirectory",None)
                template_src=config_custom.\
                                 get("PolicyFactoryTemplateFile",None)
                if not (policy_package and policy_package_directory and template_src):
                    raise PolicyFactoryException("Incomplete POLICY_CUSTOM configuration")

                loader= CustomPackageLoader(package_name=policy_package,
                                            package_path=policy_package_directory)
            policy_json = self._render_template(template_src, loader, event, token, config)
            logger.debug("Rendered policy:\n%s",policy_json)
            policy_map = json.loads(policy_json)
            if 'Context' in policy_map:
                result_context = policy_map['Context']
                policy_map.pop('Context')
            else:
                result_context = {}
            return policy_map,result_context
        except Exception as exc:
            logger.exception(exc)
            raise PolicyFactoryException() from exc
