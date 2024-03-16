import boto3
import json

dynamoDB = boto3.client('dynamodb')

def lambda_handler(event, context):
    print(event)
    print(context)

    headers = event['headers']
    username = headers['username']
    token = headers['authorizationToken']
    
    try:
        response_DB = dynamoDB.get_item(
            TableName = "usuarios",
            Key = {"username": {"S": username}}        
        )  
        print(response_DB)
    except Exception as e:
        print(e)
        return 'unauthorized'
    total_requests = 0
    if 'Item' in response_DB:
        total_requests = response_DB['Item']['total_requests']['N']
        # response_DB = {key: value['S'] for key, value in response_DB.items()}
        # response_DB = json.dumps(response_DB)
        # total_requests = response_DB['total_requests']
    total = 0

    if int(total_requests) >= 6:
       
        return 'forbidden'
    elif token == 'allow':
        print('authorized')
        response = generatePolicy('user', 'Allow', event['methodArn'])
    elif token == 'deny':
        total= int(total_requests)
        print('unauthorized')
        response = generatePolicy('user', 'Deny', event['methodArn'])
    elif token == 'unauthorized':

         
        total= int(total_requests)+1
        print('unauthorized')
        response_DB = dynamoDB.update_item(
            TableName = "usuarios",
            Key = {"username": {"S": username}},
            UpdateExpression="set total_requests=:t",
            ExpressionAttributeValues={":t": {'N':str(total)}},
            ReturnValues="UPDATED_NEW",
        )
        raise Exception('Unauthorized')  # Return a 401 Unauthorized response
        # return 'unauthorized'
    try:
       
        response_DB = dynamoDB.update_item(
            TableName = "usuarios",
            Key = {"username": {"S": username}},
            UpdateExpression="set total_requests=:t",
            ExpressionAttributeValues={":t": {'N':str(total)}},
            ReturnValues="UPDATED_NEW",
        )
        return json.loads(response)
    
    except BaseException:
        print('unauthorized2')
        total= int(total_requests)+1
        response_DB = dynamoDB.update_item(
            TableName = "usuarios",
            Key = {"username": {"S": username}},
            UpdateExpression="set total_requests=:t",
            ExpressionAttributeValues={":t": {'N':str(total)}},
            ReturnValues="UPDATED_NEW",
        )
        return 'unauthorized'  # 


def generatePolicy(principalId, effect, resource):
    authResponse = {}
    authResponse['principalId'] = principalId
    if (effect and resource):
        policyDocument = {}
        policyDocument['Version'] = '2012-10-17'
        policyDocument['Statement'] = []
        statementOne = {}
        statementOne['Action'] = 'execute-api:Invoke'
        statementOne['Effect'] = effect
        statementOne['Resource'] = resource
        policyDocument['Statement'] = [statementOne]
        authResponse['policyDocument'] = policyDocument
    authResponse['context'] = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": True
    }
    authResponse_JSON = json.dumps(authResponse)
    return authResponse_JSON