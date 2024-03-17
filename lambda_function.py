import boto3
import json
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    print(event)
    print(context)

    headers = event['headers']
    username = headers['username']
    token = headers['authorizationToken']
    dynamoDB = boto3.client('dynamodb')
    response_DB = {}
    

    try:
        response_DB = dynamoDB.get_item(
            TableName="usuarios",
            Key={"username": {"S": username}}        
        )  
        print(response_DB)
    except ClientError as e:
        print(e)
        return 'unauthorized'
   
    total_requests = 0
    if 'Item' in response_DB:
        total_requests = response_DB['Item'].get('total_requests', {}).get('N', '0')

    total = int(total_requests)
    print('logged')
    print('token',token)
    principal_id = { "AWS": "767397706325" }
    if int(total_requests) >= 6:
        return 'forbidden'
    elif token == 'allow':
        print('authorized')
        total=0
        response = generatePolicy('user', 'Allow', event['methodArn'])
    elif token == 'deny':
        total= int(total_requests)
        print('unauthorized')
        response = generatePolicy('user', 'Deny', event['methodArn'])
    elif token == 'unauthorized':
        total += 1

        try:
            response_DB = dynamoDB.update_item(
                TableName="usuarios",
                Key={"username": {"S": username}},
                UpdateExpression="set total_requests=:t",
                ExpressionAttributeValues={":t": {'N': str(total)}},
                ReturnValues="UPDATED_NEW",
            )
            raise Exception('Unauthorized')  # Raise the exception
        except ClientError as e:
            print('Error updating total_requests:', e)
            return 'unauthorized'
        
    
    try:
        print('Total', total)
        response_DB = dynamoDB.update_item(
            TableName = "usuarios",
            Key = {"username": {"S": username}},
            UpdateExpression="set total_requests=:t",
            ExpressionAttributeValues={":t": {'N':str(total)}},
            ReturnValues="UPDATED_NEW",
        )
        return json.loads(response)
    except ClientError as e:
        print('Total error client', total)
        print(e)
        return 'unauthorized'
        
        
        # print('unauthorized2')
        # total= int(total_requests)+1
        # response_DB = dynamoDB.update_item(
        #     TableName = "usuarios",
        #     Key = {"username": {"S": username}},
        #     UpdateExpression="set total_requests=:t",
        #     ExpressionAttributeValues={":t": {'N':str(total)}},
        #     ReturnValues="UPDATED_NEW",
        # )
        # return 'unauthorized'  # Return a 500 error


def generatePolicy(principalId, effect, resource):
    try:
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
    except Exception as e:
        print(str(e))