import os
import sys
from time import sleep
from boto.ec2 import connect_to_region
from boto.exception import EC2ResponseError

def start_cluster(security_group):
    instance_ids = [instance.id for instance in security_group.instances()]
    print >> sys.stderr, "Starting instances %s" % ', '.join(instance_ids)
    ec2.start_instances(instance_ids=instance_ids)
    while True:
        for instance in security_group.instances():
            instance.update(validate=True)
            if instance.state != "running":
                print >> sys.stderr, "Instance %s not started, retrying in 30 seconds..." % instance.id
                sleep(30)
                break # break out of for loop
        else: # all instances were started, so break out of while loop
            break

def stop_cluster(security_group):
    instance_ids = [instance.id for instance in security_group.instances()]
    print >> sys.stderr, "Stopping instances %s" % ', '.join(instance_ids)
    ec2.stop_instances(instance_ids=instance_ids)
    while True:
        for instance in security_group.instances():
            instance.update(validate=True)
            if instance.state != "stopped":
                print >> sys.stderr, "Instance %s not stopped, retrying in 30 seconds..." % instance.id
                sleep(30)
                break # break out of for loop
        else: # all instances were stopped, so break out of while loop
            break

def destroy_cluster(security_group):
    instance_ids = [instance.id for instance in security_group.instances()]
    print >> sys.stderr, "Terminating instances %s" % ', '.join(instance_ids)
    ec2.terminate_instances(instance_ids=instance_ids)
    print >> sys.stderr, "Deleting security group %s (%s)" % (security_group.name, security_group.id)
    # EC2 can take a while to update dependencies, so retry until we succeed
    while True:
        try:
            security_group.delete()
        except EC2ResponseError as e:
            if e.error_code == "DependencyViolation":
                print >> sys.stderr, "Security group state still converging, retrying in 5 seconds..."
                sleep(5)
            else:
                raise
        else:
            break

region = os.environ['REGION'] # required
group_name = os.environ['GROUP_NAME'] # required
action = os.environ['ACTION'] # required
vpc_id = os.environ.get('VPC_ID') # optional
profile = os.environ.get('PROFILE') # optional
ec2 = connect_to_region(region, profile_name=profile)
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
if action == "start":
    start_cluster(group)
elif action == "stop":
    stop_cluster(group)
elif action == "destroy":
    destroy_cluster(group)
else:
    raise ValueError("value of ACTION variable must be 'start', 'stop', or 'destroy'")
