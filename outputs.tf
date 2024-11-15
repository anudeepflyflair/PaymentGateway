# Output the full API Gateway URL for the /payment-gateway/process-payment endpoint with the custom domain
output "full_api_url" {
  value       = "https://${aws_api_gateway_domain_name.custom_domain.domain_name}/${aws_api_gateway_stage.api_stage.stage_name}/payment-gateway/process-payment"
  description = "The full URL for the /payment-gateway/process-payment endpoint with custom domain and stage"
}
---------------------------------
import hmac
import hashlib
import base64
import json
import boto3
import datetime
import uuid
import pandas as pd
from io import StringIO
from boto3.dynamodb.conditions import Attr

# Initialize AWS clients
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('PaymentGateway-IntelisysToken-Data-Store')
lambda_client = boto3.client('lambda')
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    
    # Retrieve Headers
    headers = event['headers']

    # Retrieve X-User-ID and X-Message-Hash from headers
    x_user_id_header = headers.get('X-User-ID')
    x_message_hash_header = headers.get('X-Message-Hash')
    
    # Retrieve x-user-id and API key from Parameter Store
    uid = ssm.get_parameter(Name='/myapi/user_id', WithDecryption=True)['Parameter']['Value']
    key = ssm.get_parameter(Name='/myapi/api_key', WithDecryption=True)['Parameter']['Value'].encode('utf-8')
    
    # Convert uid to bytes
    uid_bytes = uid.encode('utf-8')

    # Ensure body is in the correct format for hashing
    body_content = event['body']
    print(body_content)
    if isinstance(body_content, str):  # If already a string, skip encoding to JSON
        jsonstr = body_content.encode('utf-8')
    else:
        jsonstr = json.dumps(body_content, separators=(',', ':')).encode('utf-8')
    
    # Calculate HMAC hash on the original JSON payload
    uidb64, dig_value = process_data(uid_bytes, key, jsonstr)

    # Sanity check
    print("Generated UID base64:", uidb64)
    print("Generated Digest Value:", dig_value)
    print("Original JSON string:", jsonstr)
    print("Received Headers - User ID:", x_user_id_header, "Message Hash:", x_message_hash_header)
    
    # Authorization check
    if x_user_id_header == uidb64.decode('utf-8') and x_message_hash_header == dig_value.decode('utf-8'):
        # Parse the payload body
        payload = json.loads(jsonstr)
        
        # Process based on transaction_type
        if payload['transaction_type'] == "token_add":
            item = store_data_in_dynamodb(payload)  # Store token_add data
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'details': {
                        'token': item['token'],
                        'card_product': item['card_product'],
                        'card_last_four_digits': item['card_number'][-4:],
                        'card_country_of_origin': item['card_country_of_origin'],
                        'card_type': item['card_type'],
                        'expiry_date': f"{item['expiry_month']:02}{str(item['expiry_year'])[-2:]}",
                        'transaction_id': item['transaction_id']  # Sample transaction ID
                    },
                    'message': ""
                })
            }
        
        elif payload['transaction_type'] == "card_sale":
            # Verify that the token has already been processed
            data = retrieve_data_in_dynamodb(payload['token']['token'])  # Remove [0] to get all items

            if data:
                # Assuming 'data' is a list and you want the first item
                first_item = data[-1]  # Get the first item from the list of results
                # Sanity check
                print("DATA: ", first_item) 
                
                # Generate orchestrator_payload based on the data retrieved from DynamoDB
                orchestrator_payload = {
                    "terminal_id": first_item.get("terminal_id", ""), 
                    "transaction_id": first_item.get("transaction_id", ""),
                    "transaction_type": first_item.get("transaction_type", ""),
                    "reference": first_item.get("reference", ""),  # Corrected line with comma
                    "payment": {"amount": str(first_item.get("payment_amount",payload['payment']['amount']))},
                    "token": first_item.get("token", ""),
                    "card_data": first_item.get("card_number", ""),
                    "expiry_month": str(first_item.get("expiry_month", "")),
                    "expiry_year": str(first_item.get("expiry_year", ""))
                }

                print("Orchestrator Payload: ", orchestrator_payload)

                # Invoke PaymentGateway_Orchestrator Lambda
                response = lambda_client.invoke(
                    FunctionName='PaymentGateway_Orchestrator',
                    InvocationType='RequestResponse',
                    Payload=json.dumps(orchestrator_payload)
                )
                
                # orchestrator_response = json.loads(response['Payload'].read())

                # # sanity check
                # print(json.dumps(orchestrator_response))
                # return orchestrator_response
                
                # Attempt to parse JSON payload
                try:
                    orchestrator_response = json.loads(response['Payload'].read())
                    # Successful response format
                    return {
                        "statusCode": 200,
                        "headers": {
                            "Content-Type": "application/json"
                        },
                        "isBase64Encoded": False,
                        "body": json.dumps(orchestrator_response)
                    }
                
                except json.JSONDecodeError as e:
                    # Error response format
                    return {
                        "statusCode": 500,
                        "headers": {
                            "Content-Type": "text/plain"
                        },
                        "isBase64Encoded": False,
                        "body": f"Error parsing JSON: {str(e)}"
                    }
                
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': 'Token not found. Ensure token_add transaction has been processed.'})
                }
        
    else:
        # Return unauthorized error response
        return {
            'statusCode': 403,
            'body': json.dumps({'message': 'Unauthorized'})
        }

def process_data(uid_bytes, key, jsonstr):
    # Calculate HMAC hash of the JSON payload
    hm = hmac.new(key, jsonstr, hashlib.sha256)
    dig = hm.digest()
    
    # Base64 encode the uid and the hash (digest)
    uidb64 = base64.b64encode(uid_bytes)
    dig_value = base64.b64encode(dig)
    
    return uidb64, dig_value

def store_data_in_dynamodb(payload):
    # Generate a random transaction_id
    transaction_id = str(uuid.uuid4())

    # Read BINList.csv from S3 bucket
    bucket_name = 'risk-rule-payment-gateway-bucket-prod'
    file_key = 'creditcard-validation-files/BINList.csv'
    
    # Get the file from S3
    csv_obj = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    csv_content = csv_obj['Body'].read().decode('utf-8')
    
    # Load CSV content into DataFrame
    card_bin_df = pd.read_csv(StringIO(csv_content), header=0)
    card_bin_df['Product'] = None
    card_bin_df['Card_country_of_origin'] = None
    
    # Extract BIN for card lookup (first 6 digits of card number)
    card_bin = payload['card_information']['card_number'][:6]
    
    # Lookup in card_bin_df DataFrame based on the BIN
    bin_match = card_bin_df[card_bin_df['BIN'] == card_bin]
    if not bin_match.empty:
        card_product = bin_match['Product'].values[0]
        card_type = bin_match['Type'].values[0]
        card_country_of_origin = bin_match['Card_country_of_origin'].values[0]
    else:
        card_product = None
        card_type = None
        card_country_of_origin = None

    # Create item to store in DynamoDB
    item = {
        'terminal_id': payload.get('terminal_id', ""),
        'transaction_type': payload.get('transaction_type', ""),
        'transaction_id': transaction_id,
        'timestamp': datetime.datetime.now().isoformat()
    }

    # Add optional fields if they exist in the payload
    if 'reference' in payload:
        item.update({
            'reference': payload.get('reference', ""),
        })
    if 'token' in payload:
        item.update({
            'token': payload['token'].get('token', ""),
            'token_reference': payload['token'].get('reference', ""),
            'pnr': payload['token'].get('token', "").split("-")[1] if "-" in payload['token']['token'] else ""
        })
    if 'payment' in payload:
        item.update({
            'payment_amount': payload['payment'].get('amount', "")
        })
    if 'card_information' in payload:
        item.update({
            'card_number': payload['card_information'].get('card_number', ""),
            'expiry_year': payload['card_information'].get('expiry_year', ""),
            'expiry_month': payload['card_information'].get('expiry_month', ""),
            'card_product': card_product,
            'card_type': card_type,
            'card_country_of_origin': card_country_of_origin
        })

    # Store the item in DynamoDB
    table.put_item(Item=item)
    print("Data stored successfully:", item)
    return item

from boto3.dynamodb.conditions import Attr

def retrieve_data_in_dynamodb(token):
    all_items = []
    last_evaluated_key = None

    while True:
        # Prepare the scan parameters
        scan_kwargs = {
            'FilterExpression': Attr('token').eq(token)  # Filter items by token attribute
        }
        
        # Include ExclusiveStartKey only if it has a value
        if last_evaluated_key:
            scan_kwargs['ExclusiveStartKey'] = last_evaluated_key
        
        # Scan DynamoDB to locate the item(s) by token
        response = table.scan(**scan_kwargs)
        
        # Extend the list with the current batch of items
        all_items.extend(response.get('Items', []))

        # Check if there are more items to scan
        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break  # Exit the loop if there are no more items

    return all_items  # Return all matching items
