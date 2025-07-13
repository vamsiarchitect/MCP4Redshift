import boto3

def update_security_groups():
    ec2 = boto3.client('ec2')
    redshift = boto3.client('redshift')
    
    try:
        # Get Redshift security group
        clusters = redshift.describe_clusters(ClusterIdentifier='salesdata')
        redshift_sg = clusters['Clusters'][0]['VpcSecurityGroups'][0]['VpcSecurityGroupId']
        
        # Cloud9 security group
        cloud9_sg = 'sg-0ac90f7fc1f089640'  # Your Cloud9 security group ID
        
        # Allow Cloud9 to access Redshift
        ec2.authorize_security_group_ingress(
            GroupId=redshift_sg,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 5439,
                    'ToPort': 5439,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': cloud9_sg
                        }
                    ]
                }
            ]
        )
        
        print(f"Added ingress rule to Redshift security group {redshift_sg}")
        print("Security groups updated successfully!")
        
    except Exception as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print("Rule already exists - continuing...")
        else:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    update_security_groups()