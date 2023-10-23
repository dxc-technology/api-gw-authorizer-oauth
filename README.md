&copy; Copyright DXC Technology, 2023
Released as OSS under [MIT License](LICENSE)

# API Gateway Authorizer Lambda

API Gateway is one of the most used AWS services. Almost every API needs to be protected against
unauthorized access, and OAuth is the current standard for API access authorization.

AWS provides integration with AWS Cognito, but most organizations use Azure AD or other OAuth 
providers, needing a custom authorization lambda to validate tokens and produce the access policy 
document.

For this, API Gateway provides a JWT validation but only for HTTP APIs and not for REST APIs.

Moreover, JWT validation implies that access is based on the token validity only, without option to customize 
based on other rules. Any custom access policy and OAuth based authorization for REST APIs require a 
Lambda Authorizer.

This project provides a business grade implementation of this lambda that can be directly plugged as 
an Authorizer for API Gateway, providing JWT token validation and the option to customize the 
generated policy document using a Lambda layer added to it, with just the custom code base on 
the access logic that is required.

Read the [AWS Documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

![API Gateway Authorizer Lambda](ApiGwAuthorizer.png)

# Features

- OAuth token validation. Including:
  - Issuer validation (optional, necessary for OAuth 2.0 compliance)
  - Audience validation (optional, necessary for OAuth 2.0 compliance)
  - Expiration, Issued, and Not Before time stamp validation (optional, `exp` and `iat` 
    necessary for OAuth 2.0 compliance) 
  - All validated claims are required to be present in tokens
  - Explicit list of required claims (check [RFC9068](https://datatracker.ietf.org/doc/html/rfc9068) 
    for OAuth 2.0 compliance)
  - If configured, require a claim taken as the user's principal ID
  - If configured, require scopes to be present in the `scp` claim of tokens
- Use OIDC discovery of JWKS unless an URI is explicitly configured
- Defaults to allowing access to all routes and verbs to users presenting a valid token
- Returned policy including in the context the user principal ID and groups (if received)
- Policy customizable using an AWS Lambda Layer
  - (optional) Sample policy customization layer based on a Jinja2 template
- (optional) JWKS Cache in a DynamoDB table
- (optional) Lambda extension service for local DynamoDB, S3 and SSM data Cache:
  - JWKS DynamoDB items
  - S3 or SSM stored configuration
  - Custom Policy Factory data (cache service is available for custom policy factory layers)

# Performance

Notice that the first invocation to the lambda when there are no instances running in AWS or
after any change to its configuration takes between 3.5 and 4.9 seconds, due to the environment
initialization. It is recommended that some mechanism to keep the lambda warm, such as an 
AWS CloudWatch event rule is used to prevent the lambda from going cold.

In our tests, done from the API Gateway console authorizer test, we observed the following results:

- With DynamoDB and local cache deployed and enabled: Around 200-150ms
- With DynamoDB and local cache deployed and disabled: Around 330-250ms
- With DynamoDB and local cache not deployed and enabled: Around 220-180ms
- With DynamoDB and local cache not deployed and disabled: Around 220-180ms

- Without DynamoDB and local cache deployed and enabled: Around 230-210ms
- Without DynamoDB and local cache deployed and disabled: Around 250-230ms
- Without DynamoDB and local cache not deployed and disabled: Around 290-230ms
- Without DynamoDB and local cache not deployed and disabled: Around 290-230ms

Use of a DynamoDB is the mayor performance gain, while use of the local cache results in small
additional improvement, with the best results obtained combining both.

Following the API Gateway intended use for the authorizer lambda, it is recommended that the lambda
produces a complete policy document for the principal associated with the request, and that policy
caching is enabled in the API Gateway. This way, the lambda is only invoked when the API Gateway cache
needs refresh, providing the highest overall performance from the API client perspective.

# Policy Customization

Create a package with a module including a class derived from `apigwauth.policy_factory.PolicyFactory`.

The `apigwauth.policy_factory` module includes a `DefaultPolicyFactory` class that is used if no custom
factory is configured or found (not installed correctly in a an AWS Lambda layer). This default factory
always generates an allow statement for all requested resources, providing open access to the API to
any authenticated user.

A custom policy factory layer is also provided that allows generating the policy document from a Jinja2
template. This is built as a separate ZIP assembly that can be deployed to an AWS Lambda layer and
added to the authorizer lambda.

Custom policy factory classes receive all the information regarding the API Gateway event, the decoded
token and the full configuration. The configuration can then be extended by custom factory classes to 
add any additional settings they may require.

The custom policy factory can leverage the local cache service, if installed. Custom factories should not
take for granted that the local cache is installed or operational and should revert to direclty
fetching data from the source if accessing the local cache fails.

Refer to the [Configuration](#configuration) and [Deployment](#deployment) chapters for details on how 
to use the provided template based custom policy factory.

# Configuration

The configuration document syntax follows the general rules of [ConfigObj config file](https://configobj.readthedocs.io/en/latest/configobj.html#the-config-file-format).

- It is divided in sections that start with a line with the section name in between brackets
- Each section contains a group of keywords and their value, separated by an equal sign
- Keywords and values can be surrounded by single or double quotes
- It can include comment lines, that start with a pound sign that can be preceded by white spaces
- Certain values can be lists as indicated below, which is expressed separating values with a comma.
  A single element list is indicated by adding a comma after the value

The lambda can be configured either from an S3 object or an SSM parameter 
in [ConfigObj](https://configobj.readthedocs.io/en/latest/configobj.html#writing-a-config-file) 
format.

Set the environment variables `CONFIG_S3` with an S3 URI or `CONFIG_SSM` with an SSM parameter name.
If both are present `CONFIG_S3` takes precedence.

For unit testing, the configuration can include an optional `[AzureAD]` section that is not used 
by the lambda itself and can be omitted from the deployed configuration. If present, this section
is ignored.

Use the provided `test/test_config.ini.template` file to create a configuration file.

## Token Validation Configuration

`JwksUrl` is optional. If not provided ad if the `iss` claim in the token has an HTTPS scheme, the JWKS URI will be 
fetched from the OIDC discovery document as defined by the [OIDC Discovery 1.0 RFC](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) 

`UserIdClaim` is optional. If included, its value is required to be a claim present in the tokens
and the Default Policy Factory will put the value of that claim in the `PrincipalId` element of the returned
context.

`RequiredClaims` is optional and defaults to the [OAuth 2.0 mandatory claims](https://datatracker.ietf.org/doc/html/rfc9068).
If provided, the value will replace the default and is interpreted a list of claims that must be present in tokens.

**WARNING**: The RFC9068 states the `client_id` and `jti` claims to be REQUIRED. This is not honored by Azure AD, these claims
would correspond to `appid` and  `uti` in Azure AD (see the [Azure AD access token claims reference](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-token-claims-reference)).
For an AzureAD use, use the `RequiredClaims` configuration to replace the default RFC9068 required claims (see example below).

`RequiredScopes`is optional. If present, tokens must have an `scp` claim ant its value must include all the configured
values.

```
[LAMBDA]
Issuer={{Value/e expected in the iss claim}}
Audience={{Audience value/s expected in the aud claim}}
UserIdClaim={{Name of the claim from where the user principal ID is taken}}
JwksUrl={{URL of the JWKS document with the public keys of the token issuer}}
RequiredClaims={{List of claims that must be present in tokens, defaults to ='iss','exp','aud','sub','client_id','iat','jti'}}
RequiredScopes={{List of values that must all be present in the 'scp' claim}}
```

Both `Issuer` and `Audience` can be lists of values, in which case any of the indicated values, 
and all their combinations, will be considered valid.

When the provider is an Azure AD application on which custom claims mapping has been used, 
the JWKS URI does not comply with the OIDC Discovery 1.0 RFC and must be explicitly configured as described by the
[Azure AD documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-the-signature):

### Token Validation Configuration Examples

Minimal OAuth 2.0 compliant configuration with required issuer and audience:

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-e4b88f4da1f5
```

Forced JWKS source URL, not using OIDC discovery. This is quicker only when cached JWKS expire and it is 
needed to fetch the JWKS, saving the connection to obtain the OIDC discovery document.

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-e4b88f4da1f5
JwksUrl=https://login.microsoftonline.com/e3a03bbe-00ec-4584-a5e7-666666666666/discovery/keys?appid=bb11c1b7-9e34-4353-6666-e4b88f4da1f5
```

Default policy generator return the email claim value in the `PrincipalId` element of the context. The `email` claim
must be present in tokens even if `RequiredClaims` uses the default value:

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-e4b88f4da1f5
JwksUrl=https://login.microsoftonline.com/e3a03bbe-00ec-4584-a5e7-666666666666/discovery/keys?appid=bb11c1b7-9e34-4353-6666-e4b88f4da1f5
UserIdClaim=email
```

Additional custom claims `appid`, `uti` and `nbf`, as produced by Azure AD are required to be present in tokens, 
all required claims must be specified, as the default value is superseded. The presence of `nfb` as required
will cause its value to also be validated to be a time in the past. The `email` claim is implicitly required
even if not included in the `RequiredClaims` list.

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-e4b88f4da1f5
JwksUrl=https://login.microsoftonline.com/e3a03bbe-00ec-4584-a5e7-666666666666/discovery/keys?appid=bb11c1b7-9e34-4353-6666-e4b88f4da1f5
UserIdClaim=email
RequiredClaims='iss','exp','aud','sub','appid,'iat','uti','nbf'
```

Tokens must have the `scp` claim with the `Read.All` and `Write.All` values. The `scp` claim is implicitly required 
and does not need to be included in the `RequiredClaims` value:

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-e4b88f4da1f5
JwksUrl=https://login.microsoftonline.com/e3a03bbe-00ec-4584-a5e7-666666666666/discovery/keys?appid=bb11c1b7-9e34-4353-6666-e4b88f4da1f5
RequiredClaims='iss','exp','aud','sub','client_id','iat','jti','appid'
RequiredScopes=Read.All,Write.All
```

**Non OAuth 2.0 compliant** configuration, not validating the issuer and audience claims. The claims must be 
present in the token anyway.

```
[LAMBDA]
```

**Non OAuth 2.0 compliant** configuration, not validating or requiring the issuer and audience claims. Token is validated to
be properly signed, not be expired, and present the indicated claims.

```
[LAMBDA]
RequiredClaims='exp','sub','client_id','iat','jti'
```

## AzureAD Configuration for Unit Tests

Add this section only for local unit testing, to allow the test process to acquire a valid Azure AD token:

```
[AzureAD]
ClientID={{The Application ID of an Azure AD registered application}}
TenantID={{The Tenant ID where the application is registered}}
ClientSecret={{A secret configured in the registered application}}
Scope={{A scope defined in the registered application}}
```

Example:

```
[AzureAD]
ClientID=bb11c1b7-9e34-4353-a671-eeeeeeeeeeee
TenantID=e3a03bbe-00ec-4584-a5e7-666666666666
ClientSecret=DuG8Q~LJQjKdMxJOnWilMjb-GGGGGGGGGGGGGGGG
Scope=api://bb11c1b7-9e34-4353-a671-eeeeeeeeeeee/default
```

## Logging

Add this section to control logs. Logs are emitted by the lambda and sent to AWS CloudWatch Logs.

```
[LOGGING]
Level={{DEBUG|INFO|WARN|ERROR}}
Format= {{Format String}}
```

The format string must be valid for [Python logging Formatter](https://docs.python.org/3/library/logging.html#formatter-objects).

## DynamoDB Cache

Add this section to make the lambda use a DynamoDB table as cache for JWKS key sets.

```
[DynamoDBCache]
Table={{DynamoDB table name}}
LifeSeconds={{Time that the cached data will be used, in seconds}}
```

If the DynamoDB table does not exist, the lambda will try to create it using standard type and on demand billing.
It can be created with custom properties, if it exists it will use the existing table. The table must have a single 
key attribute of String type named `JWKS_URI`.

Example creation with AWS CLI for provisioned throughput:

```
aws dynamodb create-table \
    --table-name jwkscache \
    --attribute-definitions AttributeName=JWKS_URI,AttributeType=S \
    --key-schema AttributeName=JWKS_URI,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

## Policy Customization Layer

The lambda will use a custom policy factory if a `[POLICY_CUSTOM]` group is found in the configuration.

This group must include at least:

```
[POLICY_CUSTOM]
PolicyFactoryPackage=<<name of the package installed by the AWS Lambda layer (the directory under /opt/python)>>
PolicyFactoryModule=<<name of the module in the package (the .py file)>>
PolicyFactoryClass=<<name of the policy factory class>>
```

## Template Based Policy Customization

If the provided policy customization layer based on Jinja2 templates is used, the following additional settings
are required under the same `[POLICY_CUSTOM]` section.

For using templates deployed together with the AWS Lambda layer, which provides faster execution as the
template is locally installed in the lambda environment:

```
PolicyFactoryTemplateDirectory=<<name of the directory below the factory package where templates are>>
PolicyFactoryTemplateFile=<<name of the template file>>
```

**WARNING**: Under the current Python 3.8 environment, the directory containing the templates **must** have
a `__init__.py` file, even if empty, for the loader mechanism to locate the template file.

For using an S3 Object as source of the template, which provides more flexibility in test scenarios to
update the template without deploying a new layer version and updating the lambda with it:

```
TEMPLATE_S3=<<URI of the S3 Object (s3://...)>>
```

### Custom Policy Generation Template Example

The code includes examples of valid templates at `apigwauth/policy_factory_layer/templates`

Templates can be any valid Jinja2 template file that generates a valid 
[AWS API Gateway response JSON document](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html)

The template renderization receives the following data objects that can be used in the template
order be used to include in the output or in the generation logic:

  - token: The JSON decoded token in the form of a Python object
  - event: The event as received from API Gateway
  - config: The ConfigObj configuration object with the full lambda configuration
  - datetime: The datetime.datetime class allowing to use time expressions
  - import_module: The `importlib.import_module` function allowing to import any installed or Python stock module

A simple example that allows the requested action to the principal based on the `sub` claim and returns
the user email and groups in the context:

```
{
  "principalId": "{{ token.sub }}",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow",
        "Resource": "{{ event.methodArn }}"
      }
    ]
  },
  "context": {
    "userId": "{{ token.email }}",
    "groups": "{{ token.groups | join(',') }}"
  }
}
```

A more complete template example that generates the policy based on the groups present in the token and
lists of administrator and user groups present in a custom configuration is also provided.

## Complete Configuration Example

The following configurtion validates Azure AD tokens obtained for an application including scope `default`
in the token request, and uses the template based custom policy factory to produce a policy
using template `groups1.j2`, passing the IDs of two security groups corresponding to the administrators
and general users of the application.

```
[LAMBDA]
Issuer=https://sts.windows.net/e3a03bbe-00ec-4584-a5e7-666666666666/
Audience=api://bb11c1b7-9e34-4353-a671-eeeeeeeeeeee
JwksUrl=https://login.microsoftonline.com/e3a03bbe-00ec-4584-a5e7-666666666666/discovery/keys?appid=bb11c1b7-9e34-4353-a671-eeeeeeeeeeee
RequiredScopes=default
RequiredClaims='iss','exp','aud','sub','appid','iat','uti','nbf'

[DynamoDBCache]
Table=jwkscache
LifeSeconds=300

[LOGGING]
Level=INFO

[POLICY_CUSTOM]
PolicyFactoryPackage=policy_factory_layer
PolicyFactoryModule=template_policy_factory
PolicyFactoryClass=TemplatePolicyFactory
PolicyFactoryTemplateDirectory=templates
PolicyFactoryTemplateFile=groups.j2
Admin_Groups=d989b5f9-4eb2-45a4-b94f-999999999999
User_Groups=18c75b32-dc4d-4f40-9256-999999999999
```

# Local Cache Extension

An AWS Lambda extension can be added to the lambda in the form of an AWS Lambda Layer, providing a local cache of
DynamoDB items, S3 text objects and SSM parameter store parameter string values.

The lambda will initially try to obtain the data from the local cache before reverting to directly accessing the 
corresponding data source if the request fails or does not contain the requested data.

The extension is a generic HTTP service and does not require any configuration, it receives a request to get an 
item from a DynamoDB table, S3 bucket or SSM parameter, and returns it from in memory cache if present 
and not expired, or tries to get it from the source if not.

By default the local cache service will listen on port TCP/8000. This can be changed using environment variable 
`LOCAL_CACHE_LISTEN_PORT`. This variable, if existing in the lambda configuration, will be used both by the extension
service and the lambda cache client.

Log level can be controlled with environment variable `LOCAL_CACHE_LOG_LEVEL` set to a valid 
value (DEBUG, INFO, WARNING, ERROR).

Returns 200 if found, 404 if not found or 500 on any error.

By default, configuration is cached for 60 seconds, this can be controlled through the environment variable 
`CONFIG_CACHE_LIFESPAN`.

By default JWKS objects obtained from DynamoDB are cached locally for 300 seconds, and this can too be controlled 
through the environment variable `JWKS_CACHE_LIFESPAN`.

The use of the local cache by the lambda can be disabled by setting the environment variable `DISABLE_LOCAL_CACHE`.
Removing the layer from the lambda configuration has a similar effect, as failures to use the cache will make the
lambda access the data sources directly. However, setting this variable saves the lambda from the, yet slight, overhead
of trying.

![Cached JWKS retrieval flow](cache.png)

# Deployment

## Manual

1- Optionally create a DynamoDB table to use as JWKS cache, as described in the [Configuration chapter](#dynamodb-cache)

2- (optional) If the template based policy customization factory is used, create a template that suit your custom
   policy generation requirements and either:
   - Add it to the `templates` directory of the release ZIP file used to deploy the AWS Lambda layer
    `api-gw-authorizer-<release>-policy-factory-layer.zip` (recommended for production)
   - Upload it to an S3 bucket location of your choice

3- Create a configuration file as described and upload it to an S3 bucket or store it in an SSM parameter

4- Use the release package to deploy an AWS Lambda function with the following specifications:
  - Runtime Environment: Python 3.8
  - Lambda Role must include permission to read the S3 object with the configuration, beside the
    basic lambda privileges. If DynamoDB cache is configured, the role requires permissions to
    create and read the DynamoDB table.
    
5- (optional cache extension) Create an AWS Lambda Layer using the provided extension release package:
  - Architectures : arm64, x86_64
  - Platforms: Python 3.8
  Add the layer to the AWS Lambda function.
    
6- (optional policy customization) Create an AWS Lambda Layer with the package containing your
   custom policy factory class and any dependencies (be careful to not exceed the maximum 
   package size. Reuse the dependencies already installed by the lambda)-
  - Architectures : arm64, x86_64
  - Platforms: Python 3.8
  - Environment: Provide one of the two possible variables to indicate the configuration source:
    - CONFIG_S3: S3 URI of the object
    - CONFIG_SSM: Name of the SSM parameter
  Add the layer to the AWS Lambda function.
  
7- In your API Gateway register the lambda function as Authorizer:
  - The authorizer type must be `Lambda`
  - Define lambda event payload to be `Token`
  - If the header containing the token is not the default `Authorization` header, configure it in `Token Source`
  - Define token source to be `Authorization`
  - It is recommended to use policy caching to reduce the volume of lambda executions 
     
8- In your API Gateway resources definition modify the route verb on which you need to apply authorization, 
   setting `Method Execution` settings with `Authorization` set to the defined authorizer

## CloudFormation Deployment

1- Optionally create a DynamoDB table to use as JWKS cache, as described in the [Configuration chapter](#dynamodb-cache)

2- (optional) If the template based policy customization factory is used, create a template that suit your custom
   policy generation requirements and either:
   - Add it to the `templates` directory of the release ZIP file used to deploy the AWS Lambda layer
    `api-gw-authorizer-<release>-policy-factory-layer.zip` (recommended for production)
   - Upload it to an S3 bucket location of your choice

3- Create a configuration file as described and upload it to an S3 bucket

4- Upload the deployment packages to an S3 bucket in the same region as where the lambda needs to exist.

**WARNING**: The packages must not be in the root folder of the bucket

5- Use one the provided CloudFormation templates to create the required resources:

- `apigwauth-lambda.template`: Deploys only the lambda. It can use DynamoDB cache if configured, uses the default
  policy factory.
- `apigwauth-lambda-and-cache.template`: Adds the local cache extension layer, providing some performance
  improvement
- `apigwauth-lambda-all.template`: Adds both local cache and template based policy customization layers

Provide values to the required parameters of the chosen template:

- `CodeS3Url`: Provide the HTTP url of the base path in S3 where the deployment packages are. **DO NOT** include a
  trailing slash.
- `CONFIGS3`: S3 URI (in the form s3://...) to the lambda configuration file
- `CONFIGSSM`: Name of the SSM parameter storing the configuration (If provided takes precedence)
- `LambdaName`: Name to the lambda function, and root to the layer names.

# OAuth Token Pass Through for On Behalf Of Flows

A back end service of the API may need the token presented by the user to use in in a 
[OAuth 2.0 On Behalf Of flow](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1).

The default policy factory will include the token in the context element 'Token'.

If using a custom policy factory it is its responsibility to pass through the token in the context if
necessary. The provided template based custom policy factory can easily implement this feature
in the template using Jinja2:

```
...
  "context": {
    "Token": "{{ event.authorizationToken }}"
  }
...
```
