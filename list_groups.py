import os
import sys
from time import sleep
from boto.ec2 import connect_to_region
from boto.exception import EC2ResponseError

region = os.environ['REGION'] # required
vpc_id = os.environ.get('VPC_ID') # optional
profile = os.environ.get('PROFILE') # optional
ec2 = connect_to_region(region, profile_name=profile)
myria_groups = ec2.get_all_security_groups(filters={'tag:app': "myria"})
groups = myria_groups
if vpc_id:
    # In the EC2 API, filters can only express OR,
    # so we have to implement AND by intersecting results for each filter.
    groups_by_vpc = ec2.get_all_security_groups(filters={'vpc-id': vpc_id})
    groups = list(set(myria_groups) & set(groups_by_vpc))
group_names = [group.name for group in groups]
print '\n'.join(group_names)
