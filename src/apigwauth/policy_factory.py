'''
Created on August 22, 2023

Base classes and default PolicyFactory implementation

@author: Juan Alvarez Ferrando
'''
from util import AuthPolicy

class PolicyFactoryException(Exception):
    '''
    Custom exception type
    '''

class PolicyFactory():
    '''
    Abstract base class
    '''
    def get_policy(self,token,event,config):
        '''
        Abstract method. Fail if the class is directly used
        '''
        raise PolicyFactoryException("Abstract class PolicyFactory can't be directly used")

class DefaultPolicyFactory(PolicyFactory):
    '''
    Allows all access
    Extracts groups from context and returns them as a comma separated
    list in the context element "GroupsCsv"
    
    '''
    def __init__(self):
        pass

    def get_allow_policy(self, token, event, config):
        '''
        Returns a policy with an Allow for all API paths and verbs
        Principal ID is obtained from the configured claim or 'sub' if 
        no other claim is configured in [LAMBDA] -> UserIdClaim 
        '''
        tmp = event['methodArn'].split(':')
        api_gateway_arn_tmp = tmp[5].split('/')
        aws_account_id = tmp[4]

        context = {}
        if 'groups' in token:
            groups = token['groups']
            context['GroupsCsv'] = ','.join(groups)

        if 'LAMBDA' in config and 'UserIdClaim' in config['LAMBDA']:
            principal_id = token[config['LAMBDA']['UserIdClaim']]
        else:
            principal_id = token['sub']

        context ['PrincipalId']= principal_id
        context ['Token']= event['authorizationToken']

        policy = AuthPolicy(principal_id, aws_account_id)
        policy.restApiId = api_gateway_arn_tmp[0]
        policy.region = tmp[3]
        policy.stage = api_gateway_arn_tmp[1]
        policy.allowAllMethods()

        auth_response = policy.build()
        return auth_response,context

    def get_policy(self,token,event,config):
        '''
        Defaults to an allow policy
        '''
        return self.get_allow_policy(token, event, config)

    def get_deny_policy(self, event):
        '''
        Returns a policy with a Deny for all API paths and verbs
        Principal ID is obtained from the configured claim or 'sub' if 
        no other claim is configured in [LAMBDA] -> UserIdClaim 
        '''
        tmp = event['methodArn'].split(':')
        api_gateway_arn_tmp = tmp[5].split('/')
        aws_account_id = tmp[4]

        policy = AuthPolicy("unauthorized", aws_account_id)
        policy.restApiId = api_gateway_arn_tmp[0]
        policy.region = tmp[3]
        policy.stage = api_gateway_arn_tmp[1]
        policy.denyAllMethods()

        auth_response = policy.build()
        return auth_response,None
