import os
import boto3
from dotenv import load_dotenv
load_dotenv()
ec2 = boto3.client('ec2', region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1'))
res = ec2.describe_security_groups()
import json
print(json.dumps(res.get('SecurityGroups', []), indent=2))
