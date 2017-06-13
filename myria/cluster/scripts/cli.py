#!/usr/bin/env python

import sys
import os
import os.path
import stat
import traceback
import subprocess
from time import sleep
from tempfile import mkdtemp
from collections import namedtuple
from copy import deepcopy
from string import ascii_lowercase
from operator import itemgetter, attrgetter
import click
import yaml
import json
import requests

import boto
import boto.ec2
import boto.vpc
import boto.iam
from boto.exception import EC2ResponseError
from boto.ec2.blockdevicemapping import BlockDeviceType, EBSBlockDeviceType, BlockDeviceMapping
from boto.ec2.networkinterface import NetworkInterfaceSpecification, NetworkInterfaceCollection

from myria.cluster.playbooks import playbooks_dir

from distutils.spawn import find_executable
from distutils.util import strtobool
import pkg_resources
VERSION = pkg_resources.get_distribution("myria-cluster").version
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

SCRIPT_NAME = os.path.basename(sys.argv[0])
# we want to use only the Ansible executable in our dependent package
ANSIBLE_EXECUTABLE_PATH = find_executable("ansible-playbook")

ANSIBLE_GLOBAL_VARS = yaml.load(file(os.path.join(playbooks_dir, "group_vars/all"), 'r'))
MAX_RETRIES_DEFAULT = 5

# Ansible configuration variables
os.environ['ANSIBLE_SSH_ARGS'] = "-o ControlMaster=auto -o ControlPersist=600s -o ControlPath=/tmp/ansible-ssh-%h-%p-%r -o UserKnownHostsFile=/dev/null"
os.environ['ANSIBLE_RECORD_HOST_KEYS'] = "False"
os.environ['ANSIBLE_HOST_KEY_CHECKING'] = "False"
os.environ['ANSIBLE_SSH_PIPELINING'] = "True"
os.environ['ANSIBLE_TIMEOUT'] = "30"
os.environ['ANSIBLE_SSH_RETRIES'] = "5"
os.environ['ANSIBLE_RETRY_FILES_ENABLED'] = "True"
os.environ['ANSIBLE_NOCOWS'] = "True"

USER = os.getenv('USER')
HOME = os.getenv('HOME')

# we need to fudge memory values a bit for floating-point comparison
MEMORY_EPSILON = 0.1

# valid log4j log levels (https://logging.apache.org/log4j/1.2/apidocs/org/apache/log4j/Level.html)
LOG_LEVELS = ['OFF', 'FATAL', 'ERROR', 'WARN', 'DEBUG', 'TRACE', 'ALL']

DEFAULTS = dict(
    key_pair="%s-myria" % USER,
    region='us-west-2',
    instance_type='t2.large',
    cluster_size=5,
    storage_type='ebs',
    data_volume_size_gb=20,
    data_volume_type='gp2',
    data_volume_count=1,
    driver_mem_gb=0.5,
    heap_mem_fraction=0.9,
    cluster_log_level='WARN',
)

PERFENFORCE_DEFAULTS = dict(
    cluster_size=13,
    instance_type='m4.xlarge',
    worker_mem_gb=12.0,
    worker_vcores=2,
    node_mem_gb=13.0,
    node_vcores=3,
    workers_per_node=1,
    unprovisioned=True,
)

# see http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions
ALL_REGIONS = [
    'us-west-2',
    'us-east-1',
    'us-west-1',
    'eu-west-1',
    'eu-central-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'ap-south-1',
    'sa-east-1'
]

# these mappings are taken from http://uec-images.ubuntu.com/query/trusty/server/released.txt
DEFAULT_STOCK_HVM_AMI_IDS = {
    'us-west-2': "ami-9abea4fb",
    'us-east-1': "ami-fce3c696",
    'us-west-1': "ami-06116566",
    'eu-west-1': "ami-f95ef58a",
    'eu-central-1': "ami-87564feb",
    'ap-northeast-1': "ami-a21529cc",
    'ap-northeast-2': "ami-09dc1267",
    'ap-southeast-1': "ami-25c00c46",
    'ap-southeast-2': "ami-6c14310f",
    'ap-south-1': "ami-ac5238c3",
    'sa-east-1': "ami-0fb83963",
}
assert set(DEFAULT_STOCK_HVM_AMI_IDS.keys()).issubset(set(ALL_REGIONS))

DEFAULT_STOCK_PV_AMI_IDS = {
    'us-west-2': "ami-9dbea4fc",
    'us-east-1': "ami-b2e3c6d8",
    'us-west-1': "ami-42116522",
    'eu-west-1': "ami-be5cf7cd",
    'eu-central-1': "ami-d0574ebc",
    'ap-northeast-1': "ami-d91428b7",
    'ap-northeast-2': "ami-1bc10f75",
    'ap-southeast-1': "ami-a2c10dc1",
    'ap-southeast-2': "ami-530b2e30",
    'sa-east-1': "ami-feb73692",
}
assert set(DEFAULT_STOCK_PV_AMI_IDS.keys()).issubset(set(ALL_REGIONS))

DEFAULT_PROVISIONED_HVM_AMI_IDS = {
    'us-west-2': "ami-f5973b95",
    'us-east-1': "ami-9be9de8c",
    'us-west-1': "ami-4e0d592e",
    'eu-west-1': "ami-26f0a255",
    'eu-central-1': "ami-c179bcae",
    'ap-northeast-1': "ami-da19acbb",
    'ap-northeast-2': "ami-f6a47398",
    'ap-southeast-1': "ami-0bbb1968",
    'ap-southeast-2': "ami-161f2175",
    'ap-south-1': "ami-0d364162",
    'sa-east-1': "ami-8cf56be0",
}
assert set(DEFAULT_PROVISIONED_HVM_AMI_IDS.keys()).issubset(set(ALL_REGIONS))

DEFAULT_PROVISIONED_PV_AMI_IDS = {
    'us-west-2': "ami-19872b79",
    'us-east-1': "ami-33241324",
    'us-west-1': "ami-2c1b4f4c",
    'eu-west-1': "ami-f6c19385",
    'eu-central-1': "ami-667db809",
    'ap-northeast-1': "ami-cb45f0aa",
    'ap-northeast-2': "ami-f9a77097",
    'ap-southeast-1': "ami-16ac0e75",
    'ap-southeast-2': "ami-822a14e1",
    'ap-south-1': "ami-4a364125",
    'sa-east-1': "ami-1ef66872",
}
assert set(DEFAULT_PROVISIONED_PV_AMI_IDS.keys()).issubset(set(ALL_REGIONS))

# this seems to be the rule on Ubuntu AMIs (rather than /dev/sd*)
DEVICE_PATH_PREFIX = "/dev/xvd"
# from https://aws.amazon.com/amazon-linux-ami/instance-type-matrix/
PV_INSTANCE_TYPE_FAMILIES = ['c1', 'hi1', 'hs1', 'm1', 'm2', 't1']
# from http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html
EPHEMERAL_VOLUMES_BY_INSTANCE_TYPE = {
    'c1.medium': 1,
    'c1.xlarge': 4,
    'c3.large': 2,
    'c3.xlarge': 2,
    'c3.2xlarge': 2,
    'c3.4xlarge': 2,
    'c3.8xlarge': 2,
    'cc2.8xlarge': 4,
    'i2.xlarge': 1,
    'i2.2xlarge': 2,
    'i2.4xlarge': 4,
    'i2.8xlarge': 8,
    'hi1.4xlarge': 2,
    'm1.small': 1,
    'm1.medium': 1,
    'm1.large': 2,
    'm1.xlarge': 4,
    'm2.xlarge': 1,
    'm2.2xlarge': 1,
    'm2.4xlarge': 2,
    'm3.medium': 1,
    'm3.large': 1,
    'm3.xlarge': 2,
    'm3.2xlarge': 2,
    'r3.large': 1,
    'r3.xlarge': 1,
    'r3.2xlarge': 1,
    'r3.4xlarge': 1,
    'r3.8xlarge': 2,
    'cr1.8xlarge': 2,
    'd2.xlarge': 3,
    'd2.2xlarge': 6,
    'd2.4xlarge': 12,
    'd2.8xlarge': 24,
    'hs1.8xlarge': 24,
}

# from http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html
EBS_OPTIMIZED_INSTANCE_TYPES = [
    'c1.xlarge',
    'c3.xlarge',
    'c3.2xlarge',
    'c3.4xlarge',
    'c4.large',
    'c4.xlarge',
    'c4.2xlarge',
    'c4.4xlarge',
    'c4.8xlarge',
    'd2.xlarge',
    'd2.2xlarge',
    'd2.4xlarge',
    'd2.8xlarge',
    'g2.2xlarge',
    'i2.xlarge',
    'i2.2xlarge',
    'i2.4xlarge',
    'm1.large',
    'm1.xlarge',
    'm2.2xlarge',
    'm2.4xlarge',
    'm3.xlarge',
    'm3.2xlarge',
    'm4.large',
    'm4.xlarge',
    'm4.2xlarge',
    'm4.4xlarge',
    'm4.10xlarge',
    'm4.16xlarge',
    'p2.xlarge',
    'p2.8xlarge',
    'p2.16xlarge',
    'r3.xlarge',
    'r3.2xlarge',
    'r3.4xlarge',
    'x1.16xlarge',
    'x1.32xlarge',
]


class InstanceTypeConfig(object):
    def __init__(self, node_vcores, node_mem_gb, driver_mem_gb=None,
                 workers_per_node=None, worker_vcores=None,
                 worker_mem_gb=None, coordinator_vcores=None,
                 coordinator_mem_gb=None):
        self.args = dict((k, v) for k, v in locals().iteritems() if k != 'self' and v is not None)
        self.driver_mem_gb = driver_mem_gb
        self.node_vcores = node_vcores
        self.node_mem_gb = node_mem_gb
        self.workers_per_node = workers_per_node
        self.worker_vcores = worker_vcores
        self.worker_mem_gb = worker_mem_gb
        self.coordinator_vcores = coordinator_vcores
        self.coordinator_mem_gb = coordinator_mem_gb
        if driver_mem_gb is None:
            self.driver_mem_gb = DEFAULTS['driver_mem_gb']
        if workers_per_node is None:
            self.workers_per_node = self.node_vcores - 1
        elif workers_per_node > self.node_vcores - 1:
            self.node_vcores = workers_per_node + 1
        if worker_vcores is None:
            self.worker_vcores = (self.node_vcores - 1) / self.workers_per_node
        if worker_mem_gb is None:
            self.worker_mem_gb = (
                self.node_mem_gb - self.driver_mem_gb - MEMORY_EPSILON) / self.workers_per_node
        if coordinator_vcores is None:
            self.coordinator_vcores = self.node_vcores - 1
        if coordinator_mem_gb is None:
            self.coordinator_mem_gb = self.node_mem_gb - self.driver_mem_gb - MEMORY_EPSILON
        # need at least 1 vcore available for randomly assigned driver
        assert self.worker_vcores * self.workers_per_node <= self.node_vcores - 1, \
            "Total worker vcores (%d) exceeds available node vcores (%d)" % (self.worker_vcores * self.workers_per_node, self.node_vcores - 1)
        # need enough memory available for randomly assigned driver
        assert self.worker_mem_gb * self.workers_per_node <= self.node_mem_gb - self.driver_mem_gb, \
            "Total worker memory (%f) exceeds available node memory (%f)" % (self.worker_mem_gb * self.workers_per_node, self.node_mem_gb - self.driver_mem_gb)
        # driver may be randomly assigned to coordinator node
        assert self.coordinator_vcores <= self.node_vcores - 1, \
            "Coordinator vcores (%d) exceeds available node vcores (%d)" % (self.coordinator_vcores, self.node_vcores - 1)
        assert self.coordinator_mem_gb <= self.node_mem_gb - self.driver_mem_gb, \
            "Coordinator memory (%f) exceeds available node memory (%f)" % (self.coordinator_mem_gb, self.node_mem_gb - self.driver_mem_gb)


    def update(self, **kwargs):
        args = self.args.copy()
        args.update(**kwargs)
        return InstanceTypeConfig(**args)

    def __str__(self):
        return str(self.__dict__)


INSTANCE_TYPE_DEFAULTS = {
    't2.medium': InstanceTypeConfig(node_mem_gb=3.0, node_vcores=2),
    't2.large': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=2),
    't2.xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=4),
    't2.2xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=8),
    'c1.medium': InstanceTypeConfig(node_mem_gb=1.2, node_vcores=2),
    'c1.xlarge': InstanceTypeConfig(node_mem_gb=5.5, node_vcores=8),
    'c3.large': InstanceTypeConfig(node_mem_gb=3.0, node_vcores=2),
    'c3.xlarge': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=4),
    'c3.2xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=8),
    'c3.4xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=16),
    'c3.8xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=32),
    'c4.large': InstanceTypeConfig(node_mem_gb=3.0, node_vcores=2),
    'c4.xlarge': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=4),
    'c4.2xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=8),
    'c4.4xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=16),
    'c4.8xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=36),
    'cc2.8xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=32),
    'i2.xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=4),
    'i2.2xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=8),
    'i2.4xlarge': InstanceTypeConfig(node_mem_gb=96.0, node_vcores=16),
    'i2.8xlarge': InstanceTypeConfig(node_mem_gb=192.0, node_vcores=32),
    'hi1.4xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=16),
    'm1.large': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=2),
    'm1.xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=4),
    'm2.xlarge': InstanceTypeConfig(node_mem_gb=14.0, node_vcores=2),
    'm2.2xlarge': InstanceTypeConfig(node_mem_gb=28.0, node_vcores=4),
    'm2.4xlarge': InstanceTypeConfig(node_mem_gb=56.0, node_vcores=8),
    'm3.large': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=2),
    'm3.xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=4),
    'm3.2xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=8),
    'm4.large': InstanceTypeConfig(node_mem_gb=6.0, node_vcores=2),
    'm4.xlarge': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=4),
    'm4.2xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=8),
    'm4.4xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=16),
    'm4.10xlarge': InstanceTypeConfig(node_mem_gb=120.0, node_vcores=40),
    'm4.16xlarge': InstanceTypeConfig(node_mem_gb=240.0, node_vcores=64),
    'r3.large': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=2),
    'r3.xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=4),
    'r3.2xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=8),
    'r3.4xlarge': InstanceTypeConfig(node_mem_gb=96.0, node_vcores=16),
    'r3.8xlarge': InstanceTypeConfig(node_mem_gb=192.0, node_vcores=32),
    'r4.large': InstanceTypeConfig(node_mem_gb=12.0, node_vcores=2),
    'r4.xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=4),
    'r4.2xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=8),
    'r4.4xlarge': InstanceTypeConfig(node_mem_gb=96.0, node_vcores=16),
    'r4.8xlarge': InstanceTypeConfig(node_mem_gb=192.0, node_vcores=32),
    'r4.16xlarge': InstanceTypeConfig(node_mem_gb=384.0, node_vcores=64),
    'cr1.8xlarge': InstanceTypeConfig(node_mem_gb=192.0, node_vcores=32),
    'x1.16xlarge': InstanceTypeConfig(node_mem_gb=800.0, node_vcores=64),
    'x1.32xlarge': InstanceTypeConfig(node_mem_gb=1600.0, node_vcores=128),
    'd2.xlarge': InstanceTypeConfig(node_mem_gb=24.0, node_vcores=4),
    'd2.2xlarge': InstanceTypeConfig(node_mem_gb=48.0, node_vcores=8),
    'd2.4xlarge': InstanceTypeConfig(node_mem_gb=96.0, node_vcores=16),
    'd2.8xlarge': InstanceTypeConfig(node_mem_gb=192.0, node_vcores=36),
    'hs1.8xlarge': InstanceTypeConfig(node_mem_gb=96.0, node_vcores=16),
}


SecurityGroupRule = namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group"])
ssh_port = 22
http_port = 80
https_port = 443
myria_rest_port = ANSIBLE_GLOBAL_VARS['myria_rest_port']
myria_web_port = ANSIBLE_GLOBAL_VARS['myria_web_port']
ganglia_web_port = ANSIBLE_GLOBAL_VARS['ganglia_web_port']
jupyter_web_port = ANSIBLE_GLOBAL_VARS['jupyter_web_port']
resourcemanager_web_port = ANSIBLE_GLOBAL_VARS['resourcemanager_web_port']
nodemanager_web_port = ANSIBLE_GLOBAL_VARS['nodemanager_web_port']
SECURITY_GROUP_RULES = [
    SecurityGroupRule("tcp", ssh_port, ssh_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", http_port, http_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", https_port, https_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", myria_rest_port, myria_rest_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", myria_web_port, myria_web_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", ganglia_web_port, ganglia_web_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", jupyter_web_port, jupyter_web_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", resourcemanager_web_port, resourcemanager_web_port, "0.0.0.0/0", None),
    SecurityGroupRule("tcp", nodemanager_web_port, nodemanager_web_port, "0.0.0.0/0", None),
]


CLUSTER_METADATA_KEYS = dict(
    instance_type=str,
    cluster_size=int,
    ami_id=str,
    # the bool() constructor doesn't work for stringified booleans like "True" or "False",
    # and strtobool() returns 1/0 instead of True/False
    unprovisioned=lambda s: bool(strtobool(s)),
    zone=str,
    subnet_id=str,
    role=str,
    spot_price=str,
    storage_type=str,
    data_volume_size_gb=int,
    data_volume_type=str,
    data_volume_iops=int,
    data_volume_count=int,
    node_mem_gb=float,
    driver_mem_gb=float,
    coordinator_mem_gb=float,
    worker_mem_gb=float,
    heap_mem_fraction=float,
    node_vcores=int,
    coordinator_vcores=int,
    worker_vcores=int,
    workers_per_node=int,
    cluster_log_level=str,
    state=str,
)


def get_cluster_metadata_tags_from_dict(d):
    return [(k.replace('_', '-'), str(d[k])) for k in CLUSTER_METADATA_KEYS if d.get(k) is not None]


def get_dict_from_cluster_metadata(group):
    d = {}
    for key, cons in CLUSTER_METADATA_KEYS.iteritems():
        val = group.tags.get(key.replace('_', '-'))
        d[key] = cons(val) if val is not None else None
    return d


class MyriaError(Exception):
    pass


def create_key_pair_and_private_key_file(key_pair, private_key_file, region, profile=None, verbosity=0):
    # First, check if private key file exists and is readable
    if verbosity > 0:
        click.echo("Checking for existence/readability of private key file '%s'..." % private_key_file)
    private_key_exists = (os.path.isfile(private_key_file) and os.access(private_key_file, os.R_OK))
    ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
    try:
        if verbosity > 0:
            click.echo("Checking for existence of key pair '%s'..." % key_pair)
        key = ec2.get_all_key_pairs(keynames=[key_pair])[0]
    except ec2.ResponseError as e:
        if e.code == 'InvalidKeyPair.NotFound':
            # Fail if key pair doesn't exist but private key file already exists
            if private_key_exists:
                click.secho("""
Key pair '{key_pair}' not found, but private key file '{private_key_file}' already exists!
Please delete or rename it, delete the key pair '{key_pair}' from the {region} region, and rerun the script.
""".format(key_pair=key_pair, private_key_file=private_key_file, region=region), fg='red')
                return False
            if verbosity > 0:
                click.echo("Key pair '%s' not found, creating..." % key_pair)
            key = ec2.create_key_pair(key_pair)
            if verbosity > 0:
                click.echo("Saving private key for key pair '%s' to file '%s'..." % (key_pair, private_key_file))
            key_dir = os.path.dirname(private_key_file)
            key.save(key_dir)
            # key.save() creates file with hardcoded name <key_pair>.pem
            os.rename(os.path.join(key_dir, "%s.pem" % key_pair), private_key_file)
        else:
            raise
    else:
        # Fail if key pair already exists but private key file is missing
        if not private_key_exists:
            click.secho("""
Key pair '{key_pair}' exists in the {region} region but private key file '{private_key_file}' is missing!
Either 1) use a different key pair, 2) copy the private key file for the key pair '{key_pair}' to '{private_key_file}',
or 3) delete the key pair '{key_pair}' from the {region} region, and rerun the script.
""".format(key_pair=key_pair, private_key_file=private_key_file, region=region), fg='red')
            return False
    return True


def write_secure_file(path, content):
    mode = stat.S_IRUSR | stat.S_IWUSR  # This is 0o600 in octal and 384 in decimal.
    umask_original = os.umask(0)
    try:
        handle = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, mode), 'w')
    finally:
        os.umask(umask_original)
    handle.write(content)
    handle.close()


def launch_cluster(cluster_name, app_name="myria", verbosity=0, **kwargs):
    group = get_security_group_for_cluster(cluster_name, region=kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
    target_cluster_size = kwargs['cluster_size']
    actual_cluster_size = len(group.instances())
    launch_count = 0
    state = group.tags['state']
    if state == "initializing":
        assert actual_cluster_size == 0
        current_cluster_size = 0
    elif state == "resizing":
        current_cluster_size = int(group.tags['cluster-size'])
    else:
        raise ValueError("Attempted to launch instances in cluster '%s' in unexpected state '%s'" % (cluster_name, state))
    assert current_cluster_size == actual_cluster_size, "Expected %d instances to be running, but found %d running instances!" % (current_cluster_size, actual_cluster_size)
    launch_count = target_cluster_size - current_cluster_size
    assert launch_count > 0
    # Launch instances
    if verbosity > 0:
        click.echo("Launching instances...")
    ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
    launch_args=dict(image_id=kwargs['ami_id'],
                     key_name=kwargs['key_pair'],
                     security_group_ids=[group.id],
                     instance_type=kwargs['instance_type'],
                     placement=kwargs['zone'],
                     block_device_map=kwargs.get('device_mapping'),
                     instance_profile_name=kwargs.get('role'),
                     ebs_optimized=(kwargs.get('storage_type') == 'ebs') and (kwargs['instance_type'] in EBS_OPTIMIZED_INSTANCE_TYPES))
    if kwargs.get('subnet_id'):
        interface = NetworkInterfaceSpecification(subnet_id=kwargs['subnet_id'],
                                                  groups=[group.id],
                                                  associate_public_ip_address=True)
        interfaces = NetworkInterfaceCollection(interface)
        launch_args.update(network_interfaces=interfaces, security_group_ids=None)
    launched_instances = []
    if kwargs.get('spot_price'):
        launched_instance_ids = []
        launch_args.update(price=kwargs['spot_price'],
                           count=launch_count,
                           launch_group="launch-group-%s" % cluster_name, # fate-sharing across instances
                           availability_zone_group="az-launch-group-%s" % cluster_name) # launch all instances in same AZ
        spot_requests = ec2.request_spot_instances(**launch_args)
        spot_request_ids = [req.id for req in spot_requests]
        try:
            while True:
                # Spot request objects won't auto-update, so we need to fetch them again on each iteration.
                try:
                    reqs = ec2.get_all_spot_instance_requests(request_ids=spot_request_ids)
                except ec2.ResponseError as e:
                    # Occasionally EC2 will not recognize a spot request ID it has just returned.
                    if e.code == 'InvalidSpotInstanceRequestID.NotFound':
                        pass
                    else:
                        raise
                else:
                    for req in reqs:
                        if req.state != "active":
                            break
                        else:
                            launched_instance_ids.append(req.instance_id)
                    else: # all requests fulfilled, so break out of while loop
                        break
                if verbosity > 0:
                    click.secho("Not all spot requests fulfilled, waiting 60 seconds...", fg='yellow')
                sleep(60)
            launched_instances = ec2.get_only_instances(launched_instance_ids)
        except:
            try:
                ec2.cancel_spot_instance_requests(spot_request_ids)
            except:
                pass # best-effort
    else:
        launch_args.update(min_count=launch_count, max_count=launch_count)
        reservation = ec2.run_instances(**launch_args)
        launched_instances = reservation.instances
    try:
        # Tag instances
        if verbosity > 0:
            click.echo("Tagging instances...")
        # We need to sort instances in a stable order that increases with time,
        # so worker IDs are stable and increase when new instances are launched.
        instances = sorted(launched_instances, key=attrgetter('ami_launch_index'))
        for idx, instance in enumerate(instances):
            instance_tags = {'app': app_name, 'cluster-name': cluster_name}
            if kwargs.get('iam_user'):
                instance_tags.update({'user:Name': kwargs['iam_user']})
            if kwargs.get('spot_price'):
                instance_tags.update({'spot-price': kwargs['spot_price']})
            # Tag volumes
            volumes = ec2.get_all_volumes(filters={'attachment.instance-id': instance.id})
            for volume in volumes:
                volume_tags = {'app': app_name, 'cluster-name': cluster_name}
                if kwargs.get('iam_user'):
                    volume_tags.update({'user:Name': kwargs['iam_user']})
                volume.add_tags(volume_tags)
            cluster_idx = current_cluster_size + idx
            # HACK: we zero-pad the `node-id` tag so we can alphabetically sort on it in Ansible (numeric sort is too difficult).
            instance_tags.update({'node-id': "%03d" % cluster_idx})
            if idx == 0 and state == "initializing":
                # Tag coordinator
                instance_tags.update({'Name': "%s-coordinator" % cluster_name, 'cluster-role': "coordinator", 'worker-id': "0"})
            else:
                # Tag workers
                instance_name_tag = "%s-worker-%d-%d" % (cluster_name, ((cluster_idx - 1) * kwargs['workers_per_node']) + 1, cluster_idx * kwargs['workers_per_node'])
                worker_id_tag = ','.join(map(str, range(((cluster_idx - 1) * kwargs['workers_per_node']) + 1, (cluster_idx  * kwargs['workers_per_node']) + 1)))
                instance_tags.update({'Name': instance_name_tag, 'cluster-role': "worker", 'worker-id': worker_id_tag})
            instance.add_tags(instance_tags)
        # poll instances for status until all are reachable
        if verbosity > 0:
            click.secho("Waiting for all instances to become reachable...", fg='yellow')
        wait_for_all_instances_reachable(cluster_name, kwargs['region'], profile=kwargs['profile'],
                vpc_id=kwargs['vpc_id'], verbosity=verbosity)
        # need to update instances to get public IP
        for i in instances:
            i.update()
    except (KeyboardInterrupt, Exception) as e:
        # If this is a new cluster, the caller is responsible for destroying it.
        if state == "resizing":
            instance_ids = [i.id for i in instances]
            click.secho("Unexpected error, terminating new instances...", fg='red')
            if verbosity > 1:
                click.echo("Terminating instances %s" % ', '.join(instance_ids))
            terminate_instances(kwargs['region'], instance_ids, profile=kwargs['profile'])
        raise

    # NB: callers that launch new instances in existing clusters are responsible for updating cluster size metadata!
    return instances


def get_security_group_for_cluster(cluster_name, region, profile=None, vpc_id=None):
    ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
    groups = []
    if vpc_id:
        # In the EC2 API, filters can only express OR,
        # so we have to implement AND by intersecting results for each filter.
        groups_in_vpc = ec2.get_all_security_groups(filters={'vpc-id': vpc_id})
        groups = [g for g in groups_in_vpc if g.name == cluster_name]
    else:
        try:
            groups = ec2.get_all_security_groups(groupnames=cluster_name)
        except ec2.ResponseError as e:
            if e.code == 'InvalidGroup.NotFound':
                return None
            else:
                raise
    if not groups:
        return None
    else:
        return groups[0]


def create_security_group_for_cluster(cluster_name, app_name="myria", verbosity=0, **kwargs):
    if verbosity > 0:
        click.echo("Creating security group '%s' in region '%s'..." % (cluster_name, kwargs['region']))
    ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
    group = ec2.create_security_group(cluster_name, "Myria security group", vpc_id=kwargs['vpc_id'])
    # We need to poll for availability after creation since as usual AWS is eventually consistent
    while True:
        try:
            ec2.get_all_security_groups(group_ids=[group.id])[0]
        except ec2.ResponseError as e:
            if e.code == 'InvalidGroup.NotFound':
                if verbosity > 0:
                    click.secho("Waiting for security group '%s' in region '%s' to become available..." % (cluster_name, kwargs['region']), fg='yellow')
                sleep(5)
            else:
                raise
        else:
            break
    # Tag security group to designate as Myria cluster
    group_tags = {'app': app_name, 'state': "initializing"}
    if kwargs['iam_user']:
        group_tags.update({'user:Name': kwargs['iam_user']})
    # Tag security group with all command-line arguments so we can provision future instances identically
    arg_tags = get_cluster_metadata_tags_from_dict(kwargs)
    group_tags.update(arg_tags)
    group.add_tags(group_tags)
    # Allow this group complete access to itself
    self_rules = [SecurityGroupRule(proto, 0, 65535, "0.0.0.0/0", group) for proto in ['tcp', 'udp']]
    rules = self_rules + SECURITY_GROUP_RULES
    # Add security group rules
    for rule in rules:
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=rule.src_group)
    return group


def terminate_cluster(cluster_name, region, profile=None, vpc_id=None):
    # the loop is necessary to resume execution after a user interrupt
    while True:
        try:
            group = get_security_group_for_cluster(cluster_name, region, profile=profile, vpc_id=vpc_id)
            if not group:
                click.secho("Security group '%s' not found" % cluster_name, fg='red')
                return
            instance_ids = [instance.id for instance in group.instances()]
            # we want to allow users to delete a security group with no instances
            if instance_ids:
                click.echo("Terminating instances %s" % ', '.join(instance_ids))
                ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
                ec2.terminate_instances(instance_ids=instance_ids)
            click.echo("Deleting security group '%s' (%s)" % (group.name, group.id))
            # EC2 can take a while to update dependencies, so retry until we succeed
            while True:
                try:
                    group.delete()
                except EC2ResponseError as e:
                    if e.error_code == "DependencyViolation":
                        click.secho("Security group state still converging...", fg='yellow')
                        sleep(5)
                    else:
                        raise
                else:
                    click.secho("Security group '%s' (%s) successfully deleted" % (group.name, group.id), fg='green')
                    break
        except KeyboardInterrupt:
            click.secho("Cannot interrupt execution while destroying cluster!", fg='yellow')
        else:
            break


def terminate_instances(region, instance_ids, profile=None):
    ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
    # the loop is necessary to resume execution after a user interrupt
    while True:
        try:
            ec2.terminate_instances(instance_ids=instance_ids)
        except KeyboardInterrupt:
            click.secho("Cannot interrupt execution while terminating instances!", fg='yellow')
        else:
            break


def get_coordinator_public_hostname(cluster_name, region, profile=None, vpc_id=None):
    coordinator_hostname = None
    group = get_security_group_for_cluster(cluster_name, region, profile=profile, vpc_id=vpc_id)
    if not group:
        return None
    for instance in group.instances():
        if instance.tags.get('cluster-role') == "coordinator":
            coordinator_hostname = instance.public_dns_name
            break
    return coordinator_hostname


def get_worker_public_hostnames(cluster_name, region, profile=None, vpc_id=None):
    worker_hostnames = []
    group = get_security_group_for_cluster(cluster_name, region, profile=profile, vpc_id=vpc_id)
    if not group:
        return None
    for instance in group.instances():
        if instance.tags.get('cluster-role') == "worker":
            worker_hostnames.append(instance.public_dns_name)
    return worker_hostnames


def wait_for_all_instances_reachable(cluster_name, region, profile=None, vpc_id=None, verbosity=0):
    group = get_security_group_for_cluster(cluster_name, region, profile=profile, vpc_id=vpc_id)
    if not group:
        raise ValueError("Security group '%s' not found" % cluster_name)
    instance_ids = [instance.id for instance in group.instances()]
    while True:
        ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
        statuses = ec2.get_all_instance_status(instance_ids=instance_ids, include_all_instances=True)
        for status in statuses:
            if status.state_name != "running":
                break
            if status.instance_status.status != "ok":
                break
            if status.instance_status.details['reachability'] != "passed":
                break
        else: # all instances reachable, so break out of while loop
            break
        if verbosity > 0:
            click.secho("Not all instances reachable, waiting 60 seconds...", fg='yellow')
        sleep(60)


def wait_for_all_workers_online(cluster_name, region, profile=None, vpc_id=None, verbosity=0):
    coordinator_hostname = get_coordinator_public_hostname(cluster_name, region, profile=profile, vpc_id=vpc_id)
    if not coordinator_hostname:
        raise ValueError("Couldn't resolve coordinator public DNS for cluster '%s'" % cluster_name)
    workers_url = "http://%(host)s:%(port)d/workers" % dict(host=coordinator_hostname, port=ANSIBLE_GLOBAL_VARS['myria_rest_port'])
    while True:
        try:
            workers_resp = requests.get(workers_url)
        except requests.ConnectionError:
            if verbosity > 0:
                click.secho("Myria service unavailable, waiting 60 seconds...", fg='yellow')
        else:
            if workers_resp.status_code == requests.codes.ok:
                workers = workers_resp.json()
                workers_alive_resp = requests.get(workers_url + "/alive")
                workers_alive = workers_alive_resp.json()
                if len(workers_alive) == len(workers):
                    break
                else:
                    if verbosity > 0:
                        click.secho("Not all Myria workers online (%d/%d), waiting 60 seconds..." % (
                            len(workers_alive), len(workers)), fg='yellow')
            else:
                raise MyriaError("Error response from Myria service (status code %d):\n%s" % (
                    workers_resp.status_code, workers_resp.text))
        sleep(60)


def instance_type_family_from_instance_type(instance_type):
    return instance_type.split('.')[0]


def default_key_file_from_key_pair(ctx, param, value):
    if value is None:
        qualified_key_pair = "%s_%s" % (ctx.params['key_pair'], ctx.params['region'])
        if ctx.params['profile']:
            qualified_key_pair = "%s_%s_%s" % (ctx.params['key_pair'], ctx.params['profile'], ctx.params['region'])
        return "%s/.ssh/%s.pem" % (HOME, qualified_key_pair)
    else:
        return value


def default_ami_id_from_region(ctx, param, value):
    if value is None:
        ami_id = None
        use_stock_ami = ctx.params['unprovisioned']
        instance_type_family = instance_type_family_from_instance_type(ctx.params['instance_type'])
        if instance_type_family in PV_INSTANCE_TYPE_FAMILIES:
            ami_id = DEFAULT_STOCK_PV_AMI_IDS.get(ctx.params['region']) if use_stock_ami else DEFAULT_PROVISIONED_PV_AMI_IDS.get(ctx.params['region'])
        else:
            ami_id = DEFAULT_STOCK_HVM_AMI_IDS.get(ctx.params['region']) if use_stock_ami else DEFAULT_PROVISIONED_HVM_AMI_IDS.get(ctx.params['region'])
        if ami_id is None:
            raise click.BadParameter("No default %s AMI found for instance type '%s' in region '%s'" % (
                ("unprovisioned" if use_stock_ami else "provisioned"), ctx.params['instance_type'], ctx.params['region']))
        return ami_id
    else:
        return value


def validate_subnet_id(ctx, param, value):
    if value is not None:
        if ctx.params.get('zone') is not None:
            raise click.BadParameter("Cannot specify --zone if --subnet-id is specified")
    return value


def validate_console_logging(ctx, param, value):
    if value is True:
        if ctx.params.get('silent') or ctx.params.get('verbose'):
            raise click.BadParameter("Cannot specify both --silent and --verbose")
    return value


def validate_aws_settings(region, profile=None, vpc_id=None, validate_default_vpc=True, prompt_for_credentials=False, verbosity=0):
    # abort if credentials are not available
    try:
        ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
    except Exception as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        # only prompt for credentials if no configuration exists
        config_exists = (os.path.isfile("/etc/boto.cfg") or
                os.path.isfile(os.path.join(HOME, ".boto")) or
                os.path.isfile(os.path.join(HOME, ".aws/credentials")))
        if config_exists:
            click.secho("""
AWS configuration exists but credentials for the profile '{profile}' are misconfigured.
""".format(profile=profile if profile else "default"), fg='red')
        else:
            click.secho("No AWS configuration found.", fg='red')
            if prompt_for_credentials:
                if click.confirm("Do you want to configure AWS credentials for future use?"):
                    profile_name = click.prompt("Please enter your desired profile name",
                        default=(profile if profile else "default"))
                    access_key = click.prompt("Please enter your AWS Access Key ID")
                    secret_key = click.prompt("Please enter your AWS Secret Key", hide_input=True)
                    aws_cred_file_content = """
[{profile_name}]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
""".format(profile_name=profile_name, access_key=access_key, secret_key=secret_key)
                    aws_dir = os.path.join(HOME, ".aws")
                    if not os.path.exists(aws_dir):
                        os.makedirs(aws_dir)
                    aws_cred_file = os.path.join(aws_dir, "credentials")
                    write_secure_file(aws_cred_file, aws_cred_file_content)
                    click.secho("""
Your AWS credentials for the profile '{profile_name}' have been written to `{aws_cred_file}`.
Continuing with new credentials...
""".format(profile_name=profile_name, aws_cred_file=aws_cred_file), fg='green')
                    return validate_aws_settings(region, profile=profile, vpc_id=vpc_id,
                        validate_default_vpc=validate_default_vpc, prompt_for_credentials=False, verbosity=verbosity)
        click.secho("""
Please ensure that your AWS credentials are correctly configured:

http://boto3.readthedocs.io/en/latest/guide/configuration.html
""",
                    fg='red')
        return False

    # abort if credentials exist but authN or authZ fails
    try:
        ec2.get_all_instances()
    except EC2ResponseError as e:
        if e.status in [401, 403]:
            click.secho("""
Your AWS credentials for profile {profile} are not authorized for EC2 access.
Please ask your administrator for authorization.
""".format(region=region, profile=profile, vpc_id=vpc_id), fg='red')
            return False

    vpc_conn = boto.vpc.connect_to_region(region, profile_name=profile)
    # abort if VPC is not specified and no default VPC exists
    if not vpc_id:
        if validate_default_vpc:
            default_vpcs = vpc_conn.get_all_vpcs(filters={'isDefault': "true"})
            if not default_vpcs:
                click.secho("""
No default VPC is configured for your AWS account in the '{region}' region.
Please ask your administrator to create a default VPC or specify a VPC using the `--vpc-id` or `--subnet-id` option.
""".format(region=region), fg='red')
                return False
    else:
        # verify that specified VPC exists
        try:
            vpc_conn.get_all_vpcs(vpc_ids=[vpc_id])
        except EC2ResponseError as e:
            if e.error_code == "InvalidVpcID.NotFound":
                click.secho("""
No VPC found with ID '{vpc_id}' in the '{region}' region.
""".format(region=region, vpc_id=vpc_id), fg='red')
                return False
    return True


def validate_region(ctx, param, value):
    if value is not None:
        if value not in ALL_REGIONS:
            raise click.BadParameter("Region must be one of the following:\n%s" % '\n'.join(ALL_REGIONS))
    return value


def validate_instance_type(ctx, param, value):
    if value is not None:
        if ctx.params.get('storage_type') == "local":
            if value not in EPHEMERAL_VOLUMES_BY_INSTANCE_TYPE:
                raise click.BadParameter("Instance type '%s' is incompatible with local storage" % value)
        if value in INSTANCE_TYPE_DEFAULTS:
            ctx.params['__instance_type_config'] = INSTANCE_TYPE_DEFAULTS[value]
    else:
        # HACK: callback shouldn't know about default
        value = DEFAULTS['instance_type']
        ctx.params['__instance_type_config'] = INSTANCE_TYPE_DEFAULTS[value]
    return value


def validate_storage_type(ctx, param, value):
    if value == "local" and 'instance_type' in ctx.params:
        if ctx.params['instance_type'] not in EPHEMERAL_VOLUMES_BY_INSTANCE_TYPE:
            raise click.BadParameter("Instance type '%s' is incompatible with local storage" % ctx.params['instance_type'])
    return value


def validate_data_volume_size(ctx, param, value):
    if value is not None:
        if ctx.params.get('storage_type') == "local":
            raise click.BadParameter("Cannot specify volume size with --storage-type=local")
    elif ctx.params.get('storage_type') == "ebs":
        value = DEFAULTS['data_volume_size_gb']
    return value


def validate_data_volume_type(ctx, param, value):
    if value is not None:
        if ctx.params.get('storage_type') == "local":
            raise click.BadParameter("Cannot specify volume type with --storage-type=local")
    elif ctx.params.get('storage_type') == "ebs":
        value = DEFAULTS['data_volume_type']
    return value


def validate_data_volume_iops(ctx, param, value):
    if value is not None:
        if ctx.params.get('data_volume_type') != "io1":
            raise click.BadParameter("--data-volume-iops can only be specified with 'io1' volume type")
    return value


def validate_data_volume_count(ctx, param, value):
    if value is not None:
        if ctx.params.get('storage_type') == "local":
            raise click.BadParameter("Cannot specify --data-volume-count with --storage-type=local")
        if value > ctx.params['workers_per_node']:
            raise click.BadParameter("--data-volume-count cannot exceed number of workers per node (%d)" % ctx.params['workers_per_node'])
    elif ctx.params.get('storage_type') == "ebs":
        value = DEFAULTS['data_volume_count']
    else:
        # local storage
        return 0
    return value


def validate_driver_mem(ctx, param, value):
    # HACK: callback shouldn't know about default
    real_val = value or DEFAULTS['driver_mem_gb']
    ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(driver_mem_gb=real_val)
    return value


def validate_node_vcores(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --node-vcores. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].node_vcores
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(node_vcores=value)
    return value


def validate_node_mem(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --node-mem-gb. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].node_mem_gb
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(node_mem_gb=value)
    return value


def validate_workers_per_node(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --workers-per-node. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].workers_per_node
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(workers_per_node=value)
    return value


def validate_worker_vcores(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --worker-vcores. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].worker_vcores
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(worker_vcores=value)
    return value


def validate_worker_mem(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --worker-mem-gb. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].worker_mem_gb
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(worker_mem_gb=value)
    return value


def validate_coordinator_vcores(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --coordinator-vcores. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].coordinator_vcores
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(coordinator_vcores=value)
    return value


def validate_coordinator_mem(ctx, param, value):
    if value is None:
        if ctx.params['instance_type'] not in INSTANCE_TYPE_DEFAULTS:
            raise click.BadParameter("Instance type '%s' has no default for --coordinator-mem-gb. You must supply a value." % ctx.params['instance_type'])
        else:
            value = ctx.params['__instance_type_config'].coordinator_mem_gb
    else:
        ctx.params['__instance_type_config'] = ctx.params['__instance_type_config'].update(coordinator_mem_gb=value)
    return value


def validate_perfenforce(ctx, param, value):
    if value:
        for p, v in PERFENFORCE_DEFAULTS.iteritems():
            ctx.params[p] = v
    return value


def get_vpc_from_subnet(subnet_id, region, profile=None, verbosity=0):
    vpc_conn = boto.vpc.connect_to_region(region, profile_name=profile)
    try:
        subnet = vpc_conn.get_all_subnets(subnet_ids=[subnet_id])[0]
        return subnet.vpc_id
    except Exception as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        return None


def get_iam_user(region, profile=None, verbosity=0):
    # extract IAM user name for resource tagging
    iam_conn = boto.iam.connect_to_region(region, profile_name=profile)
    iam_user = None
    try:
        # TODO: once we move to boto3, we can get better info on callling principal from boto3.sts.get_caller_identity()
        iam_user = iam_conn.get_user()['get_user_response']['get_user_result']['user']['user_name']
    except:
        pass
    if not iam_user and verbosity > 0:
        click.secho("Unable to find IAM user with credentials provided. IAM user tagging will be disabled.", fg='yellow')
    return iam_user


def get_block_device_mapping(**kwargs):
    # Create block device mapping
    device_mapping = BlockDeviceMapping()
    # Generate all local volume mappings
    num_local_volumes = EPHEMERAL_VOLUMES_BY_INSTANCE_TYPE.get(kwargs['instance_type'], 0)
    for local_dev_idx in xrange(num_local_volumes):
        local_dev = BlockDeviceType()
        local_dev.ephemeral_name = "%s%d" % ("ephemeral", local_dev_idx)
        local_dev_letter = ascii_lowercase[1+local_dev_idx]
        local_dev_name = "%s%s" % (DEVICE_PATH_PREFIX, local_dev_letter)
        device_mapping[local_dev_name] = local_dev
    # Generate all EBS volume mappings
    for ebs_dev_idx in xrange(kwargs['data_volume_count']):
        ebs_dev = EBSBlockDeviceType()
        ebs_dev.size = kwargs['data_volume_size_gb']
        ebs_dev.delete_on_termination = True
        ebs_dev.volume_type = kwargs['data_volume_type']
        ebs_dev.iops = kwargs['data_volume_iops']
        # We always have one root volume and 0 to 4 ephemeral volumes.
        ebs_dev_letter = ascii_lowercase[1+num_local_volumes+ebs_dev_idx]
        ebs_dev_name = "%s%s" % (DEVICE_PATH_PREFIX, ebs_dev_letter)
        device_mapping[ebs_dev_name] = ebs_dev
    return device_mapping


def run_playbook(playbook, private_key_file, extra_vars={}, tags=[], limit_hosts=[], max_retries=MAX_RETRIES_DEFAULT, verbosity=0):
    extra_vars = deepcopy(extra_vars) # don't mutate the caller's copy
    # this should be done in an env var but Ansible maintainers are too stupid to support it
    extra_vars.update(ansible_python_interpreter='/usr/bin/env python')
    cluster_name = extra_vars['CLUSTER_NAME']
    region = extra_vars['REGION']
    profile = extra_vars.get('PROFILE')
    vpc_id = extra_vars.get('VPC_ID')
    playbook_path = os.path.join(playbooks_dir, playbook)
    inventory = "localhost," # comma is not a typo, Ansible is just stupid
    # Override default retry files directory
    ansible_retry_tmpdir = mkdtemp()
    retry_filename = os.path.join(ansible_retry_tmpdir, os.path.splitext(os.path.basename(playbook))[0] + ".retry")
    env = dict(os.environ, ANSIBLE_RETRY_FILES_SAVE_PATH=ansible_retry_tmpdir)
    # see https://github.com/ansible/ansible/pull/9404/files
    retries = 0
    failed_hosts = []
    while True:
        if failed_hosts:
            limit_hosts = failed_hosts
        if limit_hosts:
            extra_vars['LIMIT_HOSTS'] = limit_hosts
        # TODO: --module-path is for 2.2 version of ec2_remote_facts.py, remove (along with myria/cluster/playbooks/ec2_remote_facts.py) when Ansible 2.2 is released
        ansible_args = [ANSIBLE_EXECUTABLE_PATH, playbook_path, "--inventory", inventory, "--extra-vars", json.dumps(extra_vars), "--private-key", private_key_file, "--module-path", playbooks_dir]
        if tags:
            ansible_args.extend(["--tags", ','.join(tags)])
        if verbosity > 0:
            ansible_args.append("-" + ('v' * verbosity))
        status = subprocess.call(ansible_args, env=env)
        # handle failure
        if status != 0:
            if verbosity > 0:
                click.secho("Ansible exited with status code %d" % status, fg='red')
            if status in [1, 2, 3]: # internal error, failed tasks, or unreachable hosts respectively
                if retries < max_retries:
                    retries += 1
                    failed_hosts = []
                    with open(retry_filename,'r') as f:
                        failed_hosts = f.read().splitlines() 
                    assert failed_hosts # should always have at least one failed host with these exit codes
                    click.secho("Playbook run failed on hosts %s, retrying (%d/%d)..." % (', '.join(failed_hosts), retries, max_retries), fg='yellow')
                    continue
                else:
                    click.secho("Exceeded maximum %d retries!" % max_retries, fg='red')
            else:
                click.secho("Unexpected Ansible error!", fg='red')
            return False
        else:
            return True


class CustomOption(click.Option):
    def full_process_value(self, ctx, value):
        if value is not None:
            if ctx.params.get('perfenforce') and self.name in PERFENFORCE_DEFAULTS:
                raise click.BadParameter("You may not specify the --%s option with --perfenforce" % self.name)
        else:
            # if this option has already been set by a callback, then keep it
            if self.name in ctx.params:
                value = ctx.params[self.name]
        return click.Option.full_process_value(self, ctx, value)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=VERSION)
def run():
    pass


@run.command('create')
@click.argument('cluster_name')
@click.option('--perfenforce', cls=CustomOption, is_flag=True, callback=validate_perfenforce,
    help="Enable PerfEnforce (will override default cluster configuration)")
@click.option('--unprovisioned', cls=CustomOption, is_flag=True,# callback=validate_unprovisioned,
    help="Install required software at deployment")
@click.option('--profile', cls=CustomOption, default=None,
    help="AWS credential profile used to launch your cluster")
@click.option('--region', cls=CustomOption, show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region to launch your cluster in")
@click.option('--zone', cls=CustomOption, show_default=True, default=None,
    help="AWS availability zone to launch your cluster in")
@click.option('--storage-type', cls=CustomOption, show_default=True, callback=validate_storage_type,
    type=click.Choice(['ebs', 'local']), default=DEFAULTS['storage_type'],
    help="Type of the block device where Myria data is stored")
@click.option('--instance-type', cls=CustomOption, callback=validate_instance_type, is_eager=True,
    help="EC2 instance type for your cluster")
@click.option('--verbose', cls=CustomOption, is_flag=True, callback=validate_console_logging)
@click.option('--silent', cls=CustomOption, is_flag=True, callback=validate_console_logging)
@click.option('--key-pair', cls=CustomOption, show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch your cluster")
@click.option('--private-key-file', cls=CustomOption, callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
@click.option('--cluster-size', cls=CustomOption, show_default=True, default=DEFAULTS['cluster_size'],
    type=click.IntRange(3, None), help="Number of EC2 instances in your cluster")
@click.option('--ami-id', cls=CustomOption, callback=default_ami_id_from_region,
    help="ID of the AMI (Amazon Machine Image) used for your EC2 instances [default: %s]" % DEFAULT_PROVISIONED_HVM_AMI_IDS[DEFAULTS['region']])
@click.option('--subnet-id', cls=CustomOption, default=None, callback=validate_subnet_id,
    help="ID of the VPC subnet in which to launch your EC2 instances")
@click.option('--role', cls=CustomOption, help="Name of an IAM role used to launch your EC2 instances")
@click.option('--spot-price', cls=CustomOption, help="Price in dollars of the maximum bid for an EC2 spot instance request")
@click.option('--data-volume-size-gb', cls=CustomOption, type=int, callback=validate_data_volume_size,
    help="Size of each EBS data volume in GB [default: %d]" % DEFAULTS['data_volume_size_gb'])
@click.option('--data-volume-type', cls=CustomOption, type=click.Choice(['gp2', 'io1', 'st1', 'sc1']), callback=validate_data_volume_type,
    help="EBS data volume type: General Purpose SSD (gp2), Provisioned IOPS SSD (io1), Throughput Optimized HDD (st1), Cold HDD (sc1) [default: %s]" % DEFAULTS['data_volume_type'])
@click.option('--data-volume-iops', cls=CustomOption, type=int, default=None, callback=validate_data_volume_iops,
    help="IOPS to provision for each EBS data volume (only applies to 'io1' volume type)")
@click.option('--data-volume-count', cls=CustomOption, type=click.IntRange(1, 8), callback=validate_data_volume_count,
    help="Number of EBS data volumes to attach to this instance [default: %d]" % DEFAULTS['data_volume_count'])
@click.option('--driver-mem-gb', cls=CustomOption, type=float, show_default=True, default=DEFAULTS['driver_mem_gb'], callback=validate_driver_mem,
    help="Physical memory (in GB) reserved for Myria driver")
@click.option('--workers-per-node', cls=CustomOption, type=int, callback=validate_workers_per_node,
    help="Number of Myria workers per cluster node [default: %d]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].workers_per_node)
@click.option('--node-vcores', cls=CustomOption, type=int, callback=validate_node_vcores,
    help="Number of virtual CPUs on each EC2 instance available for Myria processes [default: %d]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].node_vcores)
@click.option('--node-mem-gb', cls=CustomOption, type=float, callback=validate_node_mem,
    help="Physical memory (in GB) on each EC2 instance available for Myria processes [default: %s]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].node_mem_gb)
@click.option('--worker-vcores', cls=CustomOption, type=int, callback=validate_worker_vcores,
    help="Number of virtual CPUs reserved for each Myria worker [default: %d]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].worker_vcores)
@click.option('--worker-mem-gb', cls=CustomOption, type=float, callback=validate_worker_mem,
    help="Physical memory (in GB) reserved for each Myria worker [default: %s]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].worker_mem_gb)
@click.option('--coordinator-vcores', cls=CustomOption, type=int, callback=validate_coordinator_vcores,
    help="Number of virtual CPUs reserved for Myria coordinator [default: %d]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].coordinator_vcores)
@click.option('--coordinator-mem-gb', cls=CustomOption, type=float, callback=validate_coordinator_mem,
    help="Physical memory (in GB) reserved for Myria coordinator [default: %s]" % INSTANCE_TYPE_DEFAULTS[DEFAULTS['instance_type']].coordinator_mem_gb)
@click.option('--heap-mem-fraction', cls=CustomOption, type=float, show_default=True, default=DEFAULTS['heap_mem_fraction'],
    help="Fraction of container memory used for JVM heap")
@click.option('--cluster-log-level', cls=CustomOption, show_default=True,
    type=click.Choice(LOG_LEVELS), default=DEFAULTS['cluster_log_level'])
@click.option('--jupyter-password', cls=CustomOption, default=None,
    help="Login password for the Jupyter notebook server (defaults to no authentication)")
@click.pass_context
def create_cluster(ctx, cluster_name, **kwargs):
    verbosity = 3 if kwargs['verbose'] else 0 if kwargs['silent'] else 1
    # If perfenforce is enabled, we override the cluster configuration
    if kwargs['perfenforce']:
        if verbosity > 1:
            click.secho("Overriding cluster options for PerfEnforce:\n%s" % repr(PERFENFORCE_DEFAULTS), fg='yellow')
    try:
        # we need to validate first without the VPC since it hasn't been determined yet
        if not validate_aws_settings(kwargs['region'], profile=kwargs['profile'], vpc_id=None, validate_default_vpc=False, prompt_for_credentials=True, verbosity=verbosity):
            sys.exit(1)
        vpc_id = None
        kwargs['vpc_id'] = None
        if kwargs['subnet_id']:
            vpc_id = get_vpc_from_subnet(kwargs['subnet_id'], kwargs['region'], profile=kwargs['profile'], verbosity=verbosity)
            if not vpc_id:
                click.secho("Invalid subnet ID '%s', exiting..." % kwargs['subnet_id'], fg='red')
                sys.exit(1)
            # now revalidate with the VPC we just determined
            if not validate_aws_settings(kwargs['region'], kwargs['profile'], vpc_id, verbosity=verbosity):
                sys.exit(1)
        kwargs['vpc_id'] = vpc_id
        iam_user = get_iam_user(kwargs['region'], profile=kwargs['profile'], verbosity=verbosity)
        kwargs['iam_user'] = iam_user

        # for displaying example commands
        options_str = "--region %s" % kwargs['region']
        if kwargs['profile']:
            options_str += " --profile %s" % kwargs['profile']
        if kwargs['vpc_id']:
            options_str += " --vpc-id %s" % vpc_id

        # abort if cluster already exists
        if get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id']):
            click.secho("""
    Cluster '{cluster_name}' already exists in the '{region}' region. If you wish to create a new cluster with the same name, first run

    {script_name} destroy {cluster_name} {options}
    """.format(script_name=SCRIPT_NAME, cluster_name=cluster_name, region=kwargs['region'], options=options_str), fg='red')
            sys.exit(1)

        device_mapping = get_block_device_mapping(**kwargs)
        # We need to massage opaque BlockDeviceType objects into dicts we can pass to Ansible
        all_volumes = [dict(v.__dict__.iteritems(), device_name=k) for k, v in sorted(device_mapping.iteritems(), key=itemgetter(0))]
        # we need to special-case local-only because of list slicing behavior with index "-0"
        ephemeral_volumes = all_volumes if kwargs['storage_type'] == 'local' else all_volumes[0:-kwargs['data_volume_count']]
        ebs_volumes = [] if kwargs['storage_type'] == 'local' else all_volumes[-kwargs['data_volume_count']:]

        # Create EC2 key pair if absent
        if not create_key_pair_and_private_key_file(kwargs['key_pair'], kwargs['private_key_file'], kwargs['region'],
                                                    profile=kwargs['profile'], verbosity=verbosity):
            sys.exit(1)

        # create security group and apply tags
        group = create_security_group_for_cluster(cluster_name, verbosity=verbosity, **kwargs)
        # launch all instances in this cluster
        launch_cluster(cluster_name, device_mapping=device_mapping, verbosity=verbosity, **kwargs)

        # run remote playbook to provision EC2 instances
        extra_vars = dict((k.upper(), v) for k, v in kwargs.iteritems() if v is not None and not k.startswith('__'))
        extra_vars.update(CLUSTER_NAME=cluster_name)
        if vpc_id:
            extra_vars.update(VPC_ID=vpc_id)
        if iam_user:
            extra_vars.update(IAM_USER=iam_user)
        extra_vars.update(ALL_VOLUMES=all_volumes)
        extra_vars.update(EBS_VOLUMES=ebs_volumes)
        extra_vars.update(EPHEMERAL_VOLUMES=ephemeral_volumes)

        if verbosity > 2:
            click.echo(json.dumps(extra_vars))

        tags = ['provision', 'configure'] if kwargs['unprovisioned'] else ['configure']
        if not run_playbook("remote.yml", kwargs['private_key_file'], extra_vars=extra_vars, tags=tags, verbosity=verbosity):
            raise ValueError("Failed to provision instances for cluster '%s'" % cluster_name)

        # wait for all workers to become available
        if verbosity > 0:
            click.secho("Waiting for Myria service to become available...", fg='yellow')
        wait_for_all_workers_online(cluster_name, kwargs['region'], profile=kwargs['profile'],
            vpc_id=kwargs['vpc_id'], verbosity=verbosity)
        # mark cluster as running
        group.add_tags({'state': "running"})
        coordinator_public_hostname = get_coordinator_public_hostname(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not coordinator_public_hostname:
            raise ValueError("Couldn't resolve coordinator public DNS for cluster '%s'" % cluster_name)
    except MyriaError:
        click.secho("""
The Myria service on your cluster '{cluster_name}' in the '{region}' region returned an error.
Please refer to the error message above for diagnosis. Exiting (not destroying cluster).
""".format(cluster_name=cluster_name, region=kwargs['region']), fg='red')
        sys.exit(1)
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Unexpected error, destroying cluster...", fg='red')
        try:
            terminate_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        except:
            # cluster may or may not exist at this point
            if verbosity > 1:
                click.secho(traceback.format_exc(), fg='red')
            click.secho("Failed to terminate cluster, exiting...", fg='red')
        sys.exit(1)

    click.secho(("""
Your new Myria cluster '{cluster_name}' has been launched on Amazon EC2 in the '{region}' region.

View the Myria worker IDs and public hostnames of all nodes in this cluster (the coordinator has worker ID 0):
{script_name} list {cluster_name} {options}

View cluster configuration options:
{script_name} list {cluster_name} --metadata {options}

""" + (
"""Stop this cluster:
{script_name} stop {cluster_name} {options}

Start this cluster after stopping it:
{script_name} start {cluster_name} {options}
""" if not (kwargs.get('spot_price') or (kwargs['storage_type'] == "local")) else "") +
"""
Resize this cluster (cluster size can only increase!):
{script_name} resize {cluster_name} --increment 1 {options}
or
{script_name} resize {cluster_name} --cluster-size {new_cluster_size} {options}

Update Myria software on this cluster:
{script_name} update {cluster_name} {options}

Destroy this cluster:
{script_name} destroy {cluster_name} {options}

Log into the coordinator node:
{script_name} login {cluster_name} {options}

MyriaWeb interface:
http://{coordinator_public_hostname}:{myria_web_port}

MyriaX REST endpoint:
http://{coordinator_public_hostname}:{myria_rest_port}

Ganglia web interface:
http://{coordinator_public_hostname}:{ganglia_web_port}

Jupyter notebook interface:
http://{coordinator_public_hostname}:{jupyter_web_port}
""" + (
"""
PerfEnforce web interface:
http://{coordinator_public_hostname}:{myria_web_port}/perfenforce
""" if (kwargs.get('perfenforce')) else "")
).format(coordinator_public_hostname=coordinator_public_hostname, myria_web_port=ANSIBLE_GLOBAL_VARS['myria_web_port'],
           myria_rest_port=ANSIBLE_GLOBAL_VARS['myria_rest_port'], ganglia_web_port=ANSIBLE_GLOBAL_VARS['ganglia_web_port'],
           jupyter_web_port=ANSIBLE_GLOBAL_VARS['jupyter_web_port'], private_key_file=kwargs['private_key_file'],
           remote_user=ANSIBLE_GLOBAL_VARS['remote_user'], script_name=SCRIPT_NAME, cluster_name=cluster_name,
           new_cluster_size=kwargs['cluster_size']+1, region=kwargs['region'], options=options_str), fg='green')

    if click.confirm("Do you want to open the MyriaWeb interface in your browser?"):
        click.launch("http://%s:%d" % (coordinator_public_hostname, ANSIBLE_GLOBAL_VARS['myria_web_port']))


@run.command('login')
@click.argument('cluster_name')
@click.option('--verbose', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region your cluster was launched in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
def login_to_coordinator(cluster_name, **kwargs):
    coordinator_public_hostname = get_coordinator_public_hostname(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
    if not coordinator_public_hostname:
        raise ValueError("Couldn't resolve coordinator public DNS for cluster '%s' in region '%s'" % (cluster_name, kwargs['region']))
    user_host = "'%s@%s'" % (ANSIBLE_GLOBAL_VARS['remote_user'], coordinator_public_hostname)
    ssh_opts = ["ssh", "-i", kwargs['private_key_file'], "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    if kwargs['verbose']:
        ssh_opts.append("-vvv")
    ssh_args = ssh_opts + [user_host]
    ssh_arg_str = ' '.join(ssh_args)
    sys.exit(subprocess.call(ssh_arg_str, shell=True))

    if kwargs['perfenforce']:
        click.echo("""
PerfEnforce web interface:
http://{coordinator_public_hostname}:{myria_web_port}/perfenforce""".format(coordinator_public_hostname=coordinator_public_hostname,
    myria_web_port=ANSIBLE_GLOBAL_VARS['myria_web_port']))

@run.command('logs')
@click.argument('cluster_name')
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region your cluster was launched in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
def print_logs(cluster_name, **kwargs):
    coordinator_public_hostname = get_coordinator_public_hostname(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
    if not coordinator_public_hostname:
        raise ValueError("Couldn't resolve coordinator public DNS for cluster '%s' in region '%s'" % (cluster_name, kwargs['region']))
    user_host = "'%s@%s'" % (ANSIBLE_GLOBAL_VARS['remote_user'], coordinator_public_hostname)
    ssh_opts = ["ssh", "-T", "-i", kwargs['private_key_file'], "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    ssh_args = ssh_opts + [user_host]
    ssh_arg_str = ' '.join(ssh_args)
    cmdline = """
{ssh_arg_str} <<EOF
while read APP_ID APP_NAME; do
    if [ "\$APP_NAME" = "MyriaDriver" ]; then
        sudo -E -u {hadoop_user} {yarn_exe} logs -applicationId "\$APP_ID" -appOwner {myria_user}
    fi
done < <({yarn_exe} application -list -appStates FINISHED,FAILED,KILLED | awk 'FNR>=3 {{print \$1, \$2}}')
EOF
""".format(ssh_arg_str=ssh_arg_str, yarn_exe="%s/bin/yarn" % ANSIBLE_GLOBAL_VARS['hadoop_home'],
           hadoop_user=ANSIBLE_GLOBAL_VARS['hadoop_user'], myria_user=ANSIBLE_GLOBAL_VARS['myria_user'])
    sys.exit(subprocess.call(cmdline, shell=True))


@run.command('exec')
@click.argument('cluster_name')
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region your cluster was launched in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
@click.option('--command',
    help="Shell command to execute on all hosts in the cluster")
def exec_command(cluster_name, **kwargs):
    def exec_command_on_host(host, cmd):
        user_host = "'%s@%s'" % (ANSIBLE_GLOBAL_VARS['remote_user'], host)
        ssh_opts = ["ssh", "-T", "-i", kwargs['private_key_file'], "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        ssh_args = ssh_opts + [user_host]
        ssh_arg_str = ' '.join(ssh_args)
        cmdline = """
{ssh_arg_str} <<EOF
{cmd}
EOF
""".format(ssh_arg_str=ssh_arg_str, cmd=cmd)
        return subprocess.call(cmdline, shell=True)

    group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
    if not group:
        click.secho("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']), fg='red')
        sys.exit(1)
    public_ips = [instance.ip_address for instance in group.instances()]
    for public_ip in public_ips:
        click.secho("Executing command on %s" % public_ip, fg='green')
        ret = exec_command_on_host(public_ip, kwargs['command'])
        if ret != 0:
            click.secho("Command exited with error %d on host %s, exiting..." % (ret, public_ip), fg='red')
            sys.exit(ret)


@run.command('destroy')
@click.argument('cluster_name')
@click.option('--silent', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region to launch your cluster in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
def destroy_cluster(cluster_name, **kwargs):
    verbosity = 0 if kwargs['silent'] else 1
    if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id']):
        sys.exit(1)
    if click.confirm("Are you sure you want to destroy the cluster '%s' in the '%s' region?" % (cluster_name, kwargs['region'])):
        try:
            terminate_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        except Exception as e:
            if verbosity > 0:
                click.secho(str(e), fg='red')
            if verbosity > 1:
                click.secho(traceback.format_exc(), fg='red')
            click.secho("Unexpected error while destroying cluster, exiting...", fg='red')
            sys.exit(1)


@run.command('stop')
@click.argument('cluster_name')
@click.option('--silent', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'],
    help="AWS region to launch your cluster in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
def stop_cluster(cluster_name, **kwargs):
    verbosity = 0 if kwargs['silent'] else 1
    try:
        if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id'], verbosity=verbosity):
            sys.exit(1)
        group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not group:
            click.secho("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']), fg='red')
            sys.exit(1)
        if group.tags.get('storage-type') == "local":
            click.secho("Cluster '%s' has storage type 'local' and cannot be stopped." % cluster_name, fg='red')
            sys.exit(1)
        if group.tags.get('spot-price'):
            click.secho("Cluster '%s' has spot instances and cannot be stopped." % cluster_name, fg='red')
            sys.exit(1)
        instance_ids = [instance.id for instance in group.instances()]
        if verbosity > 0:
            click.echo("Stopping instances %s" % ', '.join(instance_ids))
        ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
        ec2.stop_instances(instance_ids=instance_ids)
        while True:
            for instance in group.instances():
                instance.update(validate=True)
                if instance.state != "stopped":
                    if verbosity > 0:
                        click.secho("Not all instances stopped, waiting 60 seconds...", fg='yellow')
                    sleep(60)
                    break # break out of for loop
            else: # all instances were stopped, so break out of while loop
                break
        # mark cluster as stopped
        group.add_tags({'state': "stopped"})
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Failed to stop cluster, exiting...", fg='red')
        sys.exit(1)

    options_str = "--region %s" % kwargs['region']
    if kwargs['profile']:
        options_str += " --profile %s" % kwargs['profile']
    if kwargs['vpc_id']:
        options_str += " --vpc-id %s" % kwargs['vpc_id']
    click.secho("""
Your Myria cluster '{cluster_name}' in the '{region}' region has been successfully stopped.
You can start this cluster again by running

{script_name} start {cluster_name} {options}
""".format(script_name=SCRIPT_NAME, cluster_name=cluster_name, region=kwargs['region'], options=options_str), fg='green')


@run.command('start')
@click.argument('cluster_name')
@click.option('--silent', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region to launch your cluster in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
def start_cluster(cluster_name, **kwargs):
    verbosity = 0 if kwargs['silent'] else 1
    try:
        if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id'], verbosity=verbosity):
            sys.exit(1)
        group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not group:
            click.secho("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']), fg='red')
            sys.exit(1)
        instance_ids = [instance.id for instance in group.instances()]
        if verbosity > 0:
            click.echo("Starting instances %s" % ', '.join(instance_ids))
        ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
        ec2.start_instances(instance_ids=instance_ids)
        if verbosity > 0:
            click.secho("Waiting for started instances to become available...", fg='yellow')
        wait_for_all_instances_reachable(cluster_name, kwargs['region'], profile=kwargs['profile'],
            vpc_id=kwargs['vpc_id'], verbosity=verbosity)
        if verbosity > 0:
            click.secho("Waiting for Myria service to become available...", fg='yellow')
        wait_for_all_workers_online(cluster_name, kwargs['region'], profile=kwargs['profile'],
            vpc_id=kwargs['vpc_id'], verbosity=verbosity)
        # mark cluster as running
        group.add_tags({'state': "running"})
        coordinator_public_hostname = get_coordinator_public_hostname(
            cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not coordinator_public_hostname:
            raise ValueError("Couldn't resolve coordinator public DNS for cluster '%s'" % cluster_name)
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Unexpected error, exiting (not destroying cluster)", fg='red')
        sys.exit(1)

    options_str = "--region %s" % kwargs['region']
    if kwargs['profile']:
        options_str += " --profile %s" % kwargs['profile']
    if kwargs['vpc_id']:
        options_str += " --vpc-id %s" % kwargs['vpc_id']
    click.secho("""
Your Myria cluster '{cluster_name}' in the '{region}' region has been successfully restarted.
The public hostnames of all nodes in this cluster have changed.
You can view the new values by running

{script_name} list {cluster_name} {options}

New public hostname of coordinator:
{coordinator_public_hostname}
""".format(script_name=SCRIPT_NAME, cluster_name=cluster_name, region=kwargs['region'], options=options_str,
    coordinator_public_hostname=coordinator_public_hostname), fg='green')


@run.command('update')
@click.argument('cluster_name')
@click.option('--silent', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region your cluster was launched in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
def update_cluster(cluster_name, **kwargs):
    verbosity = 3 if kwargs['verbose'] else 0 if kwargs['silent'] else 1
    try:
        if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id'], verbosity=verbosity):
            sys.exit(1)
        group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not group:
            click.secho("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']), fg='red')
            sys.exit(1)

        extra_vars = dict((k.upper(), v) for k, v in kwargs.iteritems() if v is not None)
        extra_vars.update(CLUSTER_NAME=cluster_name)

        if verbosity > 1:
            for k, v in extra_vars.iteritems():
                click.echo("%s: %s" % (k, v))

        # mark cluster as updating
        group.add_tags({'state': "updating"})

        # run remote playbook to update software on EC2 instances
        click.echo("Updating Myria software on cluster...")
        if not run_playbook("remote.yml", kwargs['private_key_file'], extra_vars=extra_vars,
                            tags=['update'], verbosity=verbosity):
            raise ValueError("Failed to execute playbook")
        wait_for_all_workers_online(cluster_name, kwargs['region'], profile=kwargs['profile'],
                                    vpc_id=kwargs['vpc_id'], verbosity=verbosity)
        click.secho("Myria software successfully updated.", fg='green')

        # mark cluster as running
        group.add_tags({'state': "running"})

    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("""
There was a problem updating Myria software.
""" + ("See previous error messages for details." if kwargs['verbose'] else "Rerun with the --verbose option for details."), fg='red')
        sys.exit(1)


def validate_list_options(ctx, param, value):
    if value is True:
        if ctx.params.get('coordinator') or ctx.params.get('workers'):
            raise click.BadParameter("Cannot specify both --coordinator and --workers")
        if not ctx.params.get('cluster_name'):
            raise click.BadParameter("Cluster name required with --coordinator or --workers")
    return value


@run.command('list')
@click.argument('cluster_name', required=False)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region to launch your cluster in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--metadata', is_flag=True,
    help="Output cluster configuration keys and values")
@click.option('--coordinator', is_flag=True, callback=validate_list_options,
    help="Output public DNS name of coordinator node")
@click.option('--workers', is_flag=True, callback=validate_list_options,
    help="Output public DNS names of worker nodes")
def list_cluster(cluster_name, **kwargs):
    if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id']):
        sys.exit(1)
    if cluster_name is not None:
        if kwargs['metadata']:
            group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
            md = get_dict_from_cluster_metadata(group)
            print(json.dumps(md, sort_keys=True, indent=4, separators=(',', ': ')))
        elif kwargs['coordinator']:
            print(get_coordinator_public_hostname(
                cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id']))
        elif kwargs['workers']:
            print('\n'.join(get_worker_public_hostnames(
                cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])))
        else:
            group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
            if not group:
                click.secho("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']), fg='red')
                sys.exit(1)
            format_str = "{: <7} {: <10} {: <50}"
            print(format_str.format('NODE_ID', 'WORKER_IDS', 'HOST'))
            print(format_str.format('-------', '----------', '----'))
            instances = sorted(group.instances(), key=lambda i: int(i.tags.get('node-id')))
            for instance in instances:
                print(format_str.format(int(instance.tags.get('node-id')), instance.tags.get('worker-id'), instance.public_dns_name))
    else:
        ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
        myria_groups = ec2.get_all_security_groups(filters={'tag:app': "myria"})
        groups = myria_groups
        if kwargs['vpc_id']:
            groups_in_vpc = ec2.get_all_security_groups(filters={'vpc-id': kwargs['vpc_id']})
            groups_in_vpc_ids = [g.id for g in groups_in_vpc]
            # In the EC2 API, filters can only express OR,
            # so we have to implement AND by intersecting results for each filter.
            groups = [g for g in myria_groups if g.id in groups_in_vpc_ids]
        format_str = "{: <20} {: <5} {: <50} {: <10}"
        print(format_str.format('CLUSTER', 'NODES', 'COORDINATOR', 'STATE'))
        print(format_str.format('-------', '-----', '-----------', '-----'))
        for group in groups:
            coordinator = get_coordinator_public_hostname(
                group.name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
            print(format_str.format(group.name, len(group.instances()), coordinator, group.tags.get('state', "unknown")))


def validate_resize_command(ctx, param, value):
    if value is not None:
        if ctx.params.get('cluster_size') or ctx.params.get('increment'):
            raise click.BadParameter("Cannot specify both --cluster-size and --increment")
    return value


@run.command('resize')
@click.argument('cluster_name')
@click.option('--silent', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.option('--profile', default=None,
    help="Boto profile used to launch your cluster")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region your cluster was launched in")
@click.option('--vpc-id', default=None,
    help="ID of the VPC (Virtual Private Cloud) used for your EC2 instances")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
@click.option('--cluster-size', type=int, default=None, callback=validate_resize_command,
    help="New number of nodes in this cluster")
@click.option('--increment', type=click.IntRange(1, None), default=None, callback=validate_resize_command,
    help="Number of nodes to add to this cluster")
def resize_cluster(cluster_name, **kwargs):
    verbosity = 3 if kwargs['verbose'] else 0 if kwargs['silent'] else 1
    instances = None
    try:
        if not validate_aws_settings(kwargs['region'], kwargs['profile'], kwargs['vpc_id'], verbosity=verbosity):
            sys.exit(1)
        group = get_security_group_for_cluster(cluster_name, kwargs['region'], profile=kwargs['profile'], vpc_id=kwargs['vpc_id'])
        if not group:
            raise ValueError("No cluster with name '%s' exists in region '%s'." % (cluster_name, kwargs['region']))
        # mark cluster as resizing
        group.add_tags({'state': "resizing"})
        iam_user = get_iam_user(kwargs['region'], profile=kwargs['profile'], verbosity=verbosity)
        kwargs['iam_user'] = iam_user

        md = get_dict_from_cluster_metadata(group)
        # save target cluster size before it's overwritten by cluster metadata
        target_cluster_size = kwargs['cluster_size'] if kwargs.get('cluster_size') else md['cluster_size'] + kwargs['increment']
        kwargs.update(md)
        current_cluster_size = kwargs['cluster_size']
        if target_cluster_size <= current_cluster_size:
            click.secho("You must specify a target cluster size greater than the current cluster size (%d)!" % current_cluster_size, fg='red')
            sys.exit(1)
        # overwrite parameter to launch_cluster() with desired cluster size
        kwargs.update(cluster_size=target_cluster_size)

        device_mapping = get_block_device_mapping(**kwargs)
        # We need to massage opaque BlockDeviceType objects into dicts we can pass to Ansible
        all_volumes = [dict(v.__dict__.iteritems(), device_name=k) for k, v in sorted(device_mapping.iteritems(), key=itemgetter(0))]
        # we need to special-case local-only because of list slicing behavior with index "-0"
        ephemeral_volumes = all_volumes if kwargs['storage_type'] == 'local' else all_volumes[0:-kwargs['data_volume_count']]
        ebs_volumes = [] if kwargs['storage_type'] == 'local' else all_volumes[-kwargs['data_volume_count']:]

        # launch the new instances
        instances = launch_cluster(cluster_name, device_mapping=device_mapping, verbosity=verbosity, **kwargs)
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        # launch_cluster() will terminate the new instances
        click.secho("Unexpected error, exiting...", fg='red')
        sys.exit(1)

    instance_ids = [i.id for i in instances]
    try:
        ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])

        # run remote playbook to provision EC2 instances
        extra_vars = dict((k.upper(), v) for k, v in kwargs.iteritems() if v is not None)
        extra_vars.update(CLUSTER_NAME=cluster_name)
        extra_vars.update(ALL_VOLUMES=all_volumes)
        extra_vars.update(EBS_VOLUMES=ebs_volumes)
        extra_vars.update(EPHEMERAL_VOLUMES=ephemeral_volumes)

        if verbosity > 2:
            click.echo(json.dumps(extra_vars))

        # provision new instances
        tags = ['provision', 'configure'] if kwargs['unprovisioned'] else ['configure']
        if not run_playbook("remote.yml", kwargs['private_key_file'], extra_vars=extra_vars, tags=tags, limit_hosts=[i.ip_address for i in instances], verbosity=verbosity):
            click.secho("Failed to provision new instances, terminating...", fg='red')
            if verbosity > 1:
                click.echo("Terminating instances %s" % ', '.join(instance_ids))
            terminate_instances(kwargs['region'], instance_ids, profile=kwargs['profile'])
            sys.exit(1)

        # update configuration on coordinator
        tags = ['update-workers']
        if not run_playbook("remote.yml", kwargs['private_key_file'], extra_vars=extra_vars, tags=tags, verbosity=verbosity):
            raise ValueError("Failed to configure cluster for new instances")

        # wait for all workers to become available
        if verbosity > 0:
            click.secho("Waiting for Myria service to become available...", fg='yellow')
        wait_for_all_workers_online(cluster_name, kwargs['region'], profile=kwargs['profile'],
                                    vpc_id=kwargs['vpc_id'], verbosity=verbosity)

        # update cluster metadata and state
        group.add_tags({'cluster-size': target_cluster_size, 'state': "running"})

    except MyriaError:
        click.secho("""
The Myria service on your cluster '{cluster_name}' in the '{region}' region returned an error.
Please refer to the error message above for diagnosis. Exiting (not terminating new instances).
""".format(cluster_name=cluster_name, region=kwargs['region']), fg='red')
        sys.exit(1)
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Unexpected error, terminating new instances...", fg='red')
        if verbosity > 1:
            click.echo("Terminating instances %s" % ', '.join(instance_ids))
        terminate_instances(kwargs['region'], instance_ids, profile=kwargs['profile'])
        sys.exit(1)

    click.secho("%d new nodes successfully added to cluster '%s'." % (target_cluster_size - current_cluster_size, cluster_name), fg='green')


def default_base_ami_id_from_region(ctx, param, value):
    if value is None:
        ami_id = None
        instance_type_family = instance_type_family_from_instance_type(ctx.params['instance_type'])
        if instance_type_family in PV_INSTANCE_TYPE_FAMILIES:
            ami_id = DEFAULT_STOCK_PV_AMI_IDS.get(ctx.params['region'])
        else:
            ami_id = DEFAULT_STOCK_HVM_AMI_IDS.get(ctx.params['region'])
        if ami_id is None:
            raise click.BadParameter("No default AMI found for instance type '%s' in region '%s'" % (
                ctx.params['instance_type'], ctx.params['region']))
        return ami_id
    else:
        ctx.params['explicit_base_ami_id'] = True
        if ctx.params.get('virt_type') is not None:
            raise click.BadParameter("Cannot specify --%s if --base-ami-id is specified" % ctx.params['virt_type'])
        return value


def validate_virt_type(ctx, param, value):
    if value is not None:
        if ctx.params.get('explicit_base_ami_id'):
            raise click.BadParameter("Cannot specify --%s if --base-ami-id is specified" % value)
        if value == 'hvm':
            instance_type_family = instance_type_family_from_instance_type(ctx.params['instance_type'])
            if instance_type_family in PV_INSTANCE_TYPE_FAMILIES:
                raise click.BadParameter("Instance type %s is incompatible with HVM virtualization" % ctx.params['instance_type'])
            ctx.params['base_ami_id'] = DEFAULT_STOCK_HVM_AMI_IDS[ctx.params['region']]
        elif value == 'pv':
            instance_type_family = instance_type_family_from_instance_type(ctx.params['instance_type'])
            if instance_type_family not in PV_INSTANCE_TYPE_FAMILIES:
                raise click.BadParameter("Instance type %s is incompatible with PV virtualization" % ctx.params['instance_type'])
            ctx.params['base_ami_id'] = DEFAULT_STOCK_PV_AMI_IDS[ctx.params['region']]
    return value


def validate_regions(ctx, param, value):
    if value is not None:
        for region in value:
            if region not in ALL_REGIONS:
                raise click.BadParameter("Region must be one of the following:\n%s" % '\n'.join(ALL_REGIONS))
    return value


def wait_until_image_available(ami_id, region, profile=None, verbosity=0):
    ec2 = boto.ec2.connect_to_region(region, profile_name=profile)
    image = ec2.get_image(ami_id)
    if verbosity > 0:
        click.secho("Waiting for AMI %s in region '%s' to become available..." % (ami_id, region), fg='yellow')
    while image.state == 'pending':
        sleep(5)
        image.update()
    if image.state == 'available':
        return
    else:
        raise ValueError("Unexpected image status '%s' for AMI %s in region '%s'" % (image.state, ami_id, region))


@run.command('create-image')
@click.argument('ami_name')
@click.option('--verbose', is_flag=True, callback=validate_console_logging)
@click.option('--silent', is_flag=True, callback=validate_console_logging)
@click.option('--private', is_flag=True,
    help="Allow only this AWS account to use the new AMI to launch an EC2 instance")
@click.option('--overwrite', is_flag=True,
    help="Automatically deregister any existing AMI with the same name as new AMI")
@click.option('--force-terminate', is_flag=True,
    help="Automatically terminate any AMI builder instance with the same name as new AMI")
@click.option('--hvm', 'virt_type', flag_value='hvm', callback=validate_virt_type,
    help="Hardware Virtual Machine virtualization type (for current-generation EC2 instance types)")
@click.option('--pv', 'virt_type', flag_value='pv', callback=validate_virt_type,
    help="Paravirtual virtualization type (for previous-generation EC2 instance types)")
@click.option('--profile', default=None,
    help="Boto profile used to launch AMI builder instance")
@click.option('--key-pair', show_default=True, default=DEFAULTS['key_pair'],
    help="EC2 key pair used to launch AMI builder instance")
@click.option('--private-key-file', callback=default_key_file_from_key_pair,
    help="Private key file for your EC2 key pair [default: %s]" % ("%s/.ssh/%s-myria_%s.pem" % (HOME, USER, DEFAULTS['region'])))
@click.option('--instance-type', show_default=True, default=DEFAULTS['instance_type'],
    help="EC2 instance type for AMI builder instance")
@click.option('--region', show_default=True, default=DEFAULTS['region'], callback=validate_region,
    help="AWS region to launch AMI builder instance")
@click.option('--zone', show_default=True, default=None,
    help="AWS availability zone to launch AMI builder instance in")
@click.option('--subnet-id', default=None, callback=validate_subnet_id,
    help="ID of the VPC (Virtual Private Cloud) subnet used to launch AMI builder instance")
@click.option('--base-ami-id', callback=default_base_ami_id_from_region,
    help="ID of AMI (Amazon Machine Image) used to create new AMI [default: %s]" % DEFAULT_STOCK_HVM_AMI_IDS[DEFAULTS['region']])
@click.option('--description', default=None,
    help="Description of new AMI (\"Name\" in AWS console)")
@click.option('--copy-to-region', default=None, multiple=True, callback=validate_regions,
    help="Region to copy new AMI (can be specified multiple times)")
def create_image(ami_name, **kwargs):
    verbosity = 3 if kwargs['verbose'] else 0 if kwargs['silent'] else 1
    vpc_id = kwargs.get('vpc_id')
    iam_user = get_iam_user(kwargs['region'], profile=kwargs['profile'], verbosity=verbosity)
    if not validate_aws_settings(kwargs['region'], kwargs['profile'], vpc_id, verbosity=verbosity):
        sys.exit(1)
    # abort or deregister if AMI with the same name already exists
    regions = kwargs['copy_to_region'] + (kwargs['region'],)
    for region in regions:
        ec2 = boto.ec2.connect_to_region(region, profile_name=kwargs['profile'])
        images = ec2.get_all_images(filters={'name': ami_name})
        if images:
            if kwargs['overwrite']:
                click.echo("Deregistering existing AMI with name '%s' (ID: %s) in region '%s'..." % (ami_name, images[0].id, region))
                images[0].deregister(delete_snapshot=True)
                # TODO: wait here for image to become unavailable, or we can hit a race at image creation
            else:
                click.secho("""
AMI '{ami_name}' already exists in the '{region}' region.
If you wish to create a new AMI with the same name,
first deregister the existing AMI from the AWS console or
run this command with the `--overwrite` option.
""".format(ami_name=ami_name, region=region), fg='red')
                sys.exit(1)

    # abort or delete group if group already exists
    group = get_security_group_for_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
    if group:
        group_id = group.id
        if kwargs['force_terminate']:
            click.echo("Destroying old AMI builder instance...")
            terminate_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
        else:
            if group.instances():
                instance_id = group.instances()[0].id
            instance_str = "first terminate instance '{instance_id}' and then " if instance_id else ""
            click.secho("""
A builder instance for the AMI name '{ami_name}' already exists in the '{region}' region.
If you wish to create a new AMI with this name, please rerun this command with the `--force-terminate` switch or """ +
instance_str + """delete security group '{ami_name}' (ID: {group_id}) from the AWS console or AWS CLI.
""".format(ami_name=ami_name, region=kwargs['region'], group_id=group_id, instance_id=instance_id), fg='red')
            sys.exit(1)

    extra_vars = dict((k.upper(), v) for k, v in kwargs.iteritems() if v is not None)
    extra_vars.update(CLUSTER_NAME=ami_name)
    if vpc_id:
        extra_vars.update(VPC_ID=vpc_id)
    if iam_user:
        extra_vars.update(IAM_USER=iam_user)

    if verbosity > 1:
        for k, v in extra_vars.iteritems():
            click.echo("%s: %s" % (k, v))

    try:
        # create security group for AMI builder instance
        create_security_group_for_cluster(ami_name, app_name="myria-ami-builder",
            iam_user=iam_user, vpc_id=vpc_id, verbosity=verbosity, **kwargs)
        # launch AMI builder instance
        launch_cluster(ami_name, app_name="myria-ami-builder", iam_user=iam_user, vpc_id=vpc_id,
            ami_id=kwargs['base_ami_id'], cluster_size=1, verbosity=verbosity, **kwargs)

        # run remote playbook to provision EC2 instances
        click.echo("Provisioning AMI builder instance...")
        if not run_playbook("remote.yml", kwargs['private_key_file'], extra_vars=extra_vars, tags=['provision'], verbosity=verbosity):
            click.secho("Unexpected error provisioning AMI builder instance, destroying instance...", fg='red')
            terminate_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
            sys.exit(1)

        click.echo("Bundling image...")
        image_ids_by_region = {}
        group = get_security_group_for_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
        instance_id = group.instances()[0].id
        ec2 = boto.ec2.connect_to_region(kwargs['region'], profile_name=kwargs['profile'])
        ami_id = ec2.create_image(instance_id=instance_id, name=ami_name, description=kwargs['description'])
        image_ids_by_region[kwargs['region']] = ami_id
        wait_until_image_available(ami_id, kwargs['region'], profile=kwargs['profile'], verbosity=verbosity)
        click.echo("Copying image to other regions...")
        for copy_region in kwargs['copy_to_region']:
            ec2 = boto.ec2.connect_to_region(copy_region, profile_name=kwargs['profile'])
            copy_image = ec2.copy_image(kwargs['region'], ami_id, name=ami_name, description=kwargs['description'])
            image_ids_by_region[copy_region] = copy_image.image_id
            wait_until_image_available(copy_image.image_id, copy_region, profile=kwargs['profile'], verbosity=verbosity)
        click.echo("Tagging images...")
        for region, ami_id in image_ids_by_region.iteritems():
            ec2 = boto.ec2.connect_to_region(region, profile_name=kwargs['profile'])
            image = ec2.get_image(ami_id)
            tags = {
                'Name': kwargs['description'],
                'base-image': kwargs['base_ami_id'],
                'app': "myria",
            }
            if iam_user:
                tags.update({'user:Name': iam_user})
            image.add_tags(tags)
            if not kwargs['private']:
                # make AMI public
                image.set_launch_permissions(group_names='all')
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Unexpected error, destroying AMI builder instance...", fg='red')
        terminate_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
        sys.exit(1)

    click.echo("Shutting down AMI builder instance...")
    try:
        terminate_cluster(ami_name, kwargs['region'], profile=kwargs['profile'], vpc_id=vpc_id)
    except Exception as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Failed to properly shut down AMI builder instance. Please delete all instances in security group '%s'." % ami_name, fg='red')

    click.secho("Successfully created images in regions %s:" % ', '.join(image_ids_by_region.keys()), fg='green')
    format_str = "{: <20} {: <20}"
    print(format_str.format('REGION', 'AMI_ID'))
    print(format_str.format('------', '------'))
    for region, ami_id in image_ids_by_region.iteritems():
        print(format_str.format(region, ami_id))


def validate_vpc_ids(ctx, param, value):
    if value is not None:
        if len(value) != len(ctx.params['region']):
            raise click.BadParameter("--vpc-id must be specified as many times as --region if it is specified at all")
    return value


@run.command('delete-image')
@click.argument('ami_name')
@click.option('--profile', default=None,
    help="Boto profile used to create AMI")
@click.option('--region', multiple=True, callback=validate_regions,
    help="Region in which AMI was created (can be specified multiple times)")
@click.option('--vpc-id', default=None, callback=validate_vpc_ids,
    help="ID of the VPC (Virtual Private Cloud) in which AMI was created (can be specified multiple times, in same order as regions)")
def delete_image(ami_name, **kwargs):
    regions = kwargs['region']
    if click.confirm("Are you sure you want to delete the AMI '%s' in the %s regions?" % (ami_name, ', '.join(regions))):
        try:
            for i, region in enumerate(regions):
                vpc_id = kwargs['vpc_id'][i] if kwargs['vpc_id'] else None
                if not validate_aws_settings(region, kwargs['profile'], vpc_id):
                    sys.exit(1)
                ec2 = boto.ec2.connect_to_region(region, profile_name=kwargs['profile'])
                # In the EC2 API, filters can only express OR,
                # so we have to implement AND by intersecting results for each filter.
                if kwargs['vpc_id']:
                    vpc_id = kwargs['vpc_id'][i]
                    images_by_vpc = ec2.get_all_images(filters={'vpc-id': vpc_id})
                    images = [img for img in images_by_vpc if img.name == ami_name]
                else:
                    images = ec2.get_all_images(filters={'name': ami_name})
                if images:
                    click.echo("Deregistering AMI with name '%s' (ID: %s) in region '%s'..." % (ami_name, images[0].id, region))
                    images[0].deregister(delete_snapshot=True)
                    # TODO: wait here for image to become unavailable
                else:
                    click.secho("No AMI found in region '%s' with name '%s'" % (region, ami_name), fg='red')
        except (KeyboardInterrupt, Exception) as e:
            if verbosity > 0:
                click.secho(str(e), fg='red')
            if verbosity > 1:
                click.secho(traceback.format_exc(), fg='red')
            click.secho("Unexpected error, exiting...", fg='red')
            sys.exit(1)


@run.command('list-images')
@click.option('--profile', default=None,
    help="Boto profile used to create AMI")
@click.option('--region', multiple=True, callback=validate_regions,
    help="Region in which AMI was created (can be specified multiple times)")
@click.option('--vpc-id', default=None, callback=validate_vpc_ids,
    help="ID of the VPC (Virtual Private Cloud) in which AMI was created (can be specified multiple times, in same order as regions)")
def list_images(**kwargs):
    try:
        all_region_images = []
        regions = kwargs['region']
        for i, region in enumerate(regions):
            vpc_id = kwargs['vpc_id'][i] if kwargs['vpc_id'] else None
            if not validate_aws_settings(region, kwargs['profile'], vpc_id):
                sys.exit(1)
            ec2 = boto.ec2.connect_to_region(region, profile_name=kwargs['profile'])
            all_images = ec2.get_all_images(filters={'tag:app': "myria"})
            all_image_ids = [img.id for img in all_images]
            images = all_images
            if kwargs['vpc_id']:
                # In the EC2 API, filters can only express OR,
                # so we have to implement AND by intersecting results for each filter.
                images_in_vpc = ec2.get_all_images(filters={'vpc-id': kwargs['vpc_id']})
                images = [img for img in images_in_vpc if img.id in all_image_ids]
            all_region_images.extend(images)

        format_str = "{: <20} {: <20} {: <20} {: <30} {: <100}"
        print(format_str.format('REGION', 'AMI_ID', 'VIRTUALIZATION_TYPE', 'NAME', 'DESCRIPTION'))
        print(format_str.format('------', '------', '-------------------', '----', '-----------'))
        for image in all_region_images:
            print(format_str.format(image.region.name, image.id, image.virtualization_type, image.name, image.description))
    except (KeyboardInterrupt, Exception) as e:
        if verbosity > 0:
            click.secho(str(e), fg='red')
        if verbosity > 1:
            click.secho(traceback.format_exc(), fg='red')
        click.secho("Unexpected error, exiting...", fg='red')
        sys.exit(1)


# IMAGE ATTRIBUTES
# root_device_type
# ramdisk_id
# id
# owner_alias
# billing_products
# tags
# platform
# state
# location
# type
# virtualization_type
# sriov_net_support
# architecture
# description
# block_device_mapping
# kernel_id
# owner_id
# is_public
# instance_lifecycle
# creationDate
# name
# hypervisor
# region
# item
# connection
# root_device_name
# ownerId
# product_codes


if __name__ == '__main__':
    run()
