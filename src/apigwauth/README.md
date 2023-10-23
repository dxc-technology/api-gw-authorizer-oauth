# API Gateway Authorizer Lambda

This authorizer lambda validates JWT tokens and produces a policy to be applied by
AWS API Gateway to permit or deny a request.

The default policy will allow access to all routes and verbs to validated tokens.

The policy generation can be customized by implementing a module apigwPolicyFactory
with PolicyFactory class and method getPolicy(policy,decodedToken).