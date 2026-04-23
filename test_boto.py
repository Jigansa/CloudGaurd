import os
import boto3
from dotenv import load_dotenv
load_dotenv()
ec2 = boto3.client('ec2', region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1'))
res = ec2.describe_security_groups()
for g in res.get('SecurityGroups', []):
    for perm in g.get('IpPermissions', []):
        for ip_range in perm.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                print(f"Found {g['GroupId']}")
                try:
                    bad_rule = [{
                        'IpProtocol': perm['IpProtocol'],
                        'FromPort': perm.get('FromPort'),
                        'ToPort': perm.get('ToPort'),
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                    if perm['IpProtocol'] == '-1':
                        bad_rule[0].pop('FromPort', None)
                        bad_rule[0].pop('ToPort', None)
                    print('Revoking...', bad_rule)
                    ec2.revoke_security_group_ingress(GroupId=g['GroupId'], IpPermissions=bad_rule)
                    print('SUCCESSFULLY REVOKED!')
                except Exception as e:
                    print('BOTO ERROR:', str(e))
                exit(0)
