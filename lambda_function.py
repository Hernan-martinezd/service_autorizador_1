import json
def lambda_handler(event, context):
    token = event['authorizationToken']
    print("El evento:", event, "Token:", token)
    # Usar token
    if token == 'allow':
        policy = gen_policy('Allow', event['methodArn'])
        principal_id = 'Admin'
        context = {'simpleAuth': True}
        response = {
            'principalId': principal_id,
            'policyDocument': policy,
            'context': context
        }
        return response
    elif token == 'deny':
        policy = gen_policy('Deny', event['methodArn'])
        principal_id = 'DenyToken'
        context = {'simpleAuth': True}
        response = {
            'principalId': principal_id,
            'policyDocument': policy,
            'context': context
        }
        return response
    else:
        raise Exception('Unauthorized')
def gen_policy(effect, resource):
    policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Action': 'execute-api:Invoke',
            'Effect': effect,
            'Resource': resource
        }]
    }
    return policy