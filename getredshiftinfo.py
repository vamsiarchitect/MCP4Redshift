import boto3

def get_redshift_info():
    redshift = boto3.client('redshift')
    
    try:
        # Get cluster info
        clusters = redshift.describe_clusters()
        
        if clusters['Clusters']:
            cluster = clusters['Clusters'][0]
            print("\nRedshift Cluster Information:")
            print(f"Cluster Identifier: {cluster['ClusterIdentifier']}")
            print(f"Subnet Group: {cluster['ClusterSubnetGroupName']}")
            print(f"VPC ID: {cluster['VpcId']}")
            print(f"Subnet Group Name: {cluster['ClusterSubnetGroupName']}")
            print(f"Endpoint: {cluster['Endpoint']['Address']}")
            print(f"Port: {cluster['Endpoint']['Port']}")
            
            # Get subnet group details
            subnet_groups = redshift.describe_cluster_subnet_groups(
                ClusterSubnetGroupName=cluster['ClusterSubnetGroupName']
            )
            
            if subnet_groups['ClusterSubnetGroups']:
                subnet_group = subnet_groups['ClusterSubnetGroups'][0]
                print("\nSubnet Group Details:")
                print(f"Description: {subnet_group['Description']}")
                print("\nSubnets:")
                for subnet in subnet_group['Subnets']:
                    print(f"  Subnet ID: {subnet['SubnetIdentifier']}")
                    print(f"  Availability Zone: {subnet['SubnetAvailabilityZone']['Name']}")
                    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    get_redshift_info()