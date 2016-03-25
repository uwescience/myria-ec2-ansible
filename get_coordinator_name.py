import os
import sys
from time import sleep
from boto.ec2 import connect_to_region
from boto.exception import EC2ResponseError

region = os.environ['REGION'] # required
group_name = os.environ['GROUP_NAME'] # required
vpc_id = os.environ.get('VPC_ID') # optional
profile = os.environ.get('PROFILE') # optional
ec2 = connect_to_region(region, profile_name=(profile if profile else None)) # ignore empty string
groups_by_name = ec2.get_all_security_groups(filters={'group-name': group_name})
groups = groups_by_name
if vpc_id:
    # In the EC2 API, filters can only express OR,
    # so we have to implement AND by intersecting results for each filter.
    groups_by_vpc = ec2.get_all_security_groups(filters={'vpc-id': vpc_id})
    groups = list(set(groups_by_name) & set(groups_by_vpc))
if len(groups) == 0: # no groups found
    print >> sys.stderr, "No groups found with name '%s'" % group_name
    sys.exit(1)
elif len(groups) > 1: # multiple groups found
    print >> sys.stderr, "Multiple groups found with name '%s'" % group_name
    sys.exit(2)
group = groups[0]
# TODO: is there a way to do this (filters?) that doesn't require retrieving all instances in the group?
for instance in group.instances():
    if instance.tags.get('cluster-role') == "coordinator":
        print instance.public_dns_name
        break
