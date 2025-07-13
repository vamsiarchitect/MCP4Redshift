import boto3

def get_cloud9_info():
    ec2 = boto3.client('ec2')
    
    try:
        # Get Cloud9 instance
        instances = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:aws:cloud9:environment',
                    'Values': ['*']
                }
            ]
        )
        
        if instances['Reservations']:
            instance = instances['Reservations'][0]['Instances'][0]
            print("\nCloud9 Network Information:")
            print(f"VPC ID: {instance['VpcId']}")
            print(f"Subnet ID: {instance['SubnetId']}")
            print("\nSecurity Groups:")
            for sg in instance['SecurityGroups']:
                print(f"  ID: {sg['GroupId']}")
                print(f"  Name: {sg['GroupName']}")
            
            return instance['VpcId'], instance['SubnetId'], instance['SecurityGroups']
    except Exception as e:
        print(f"Error: {str(e)}")
        return None, None, None

if __name__ == "__main__":
    get_cloud9_info()