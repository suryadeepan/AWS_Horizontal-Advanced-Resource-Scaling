import boto3
import botocore
import os
import requests
import time
import json
import configparser
from dateutil.parser import parse
from datetime import datetime, timezone

########################################
# Constants
########################################
with open('horizontal-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']

TPZ_USERNAME = os.environ['TPZ_USERNAME']
TPZ_PASSWORD = os.environ['TPZ_PASSWORD']

ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')

########################################
# Tags
########################################
tag_pairs = [("Project", "2.1"), ]
TAGS = [{'Key': k, 'Value': v} for k, v in tag_pairs]


########################################
# Utility functions
########################################
def create_instance(ami, sg_id):
    # Given AMI, create and return an AWS EC2 instance object
    response = ec2_resource.create_instances(ImageId=ami,
                                             InstanceType=INSTANCE_TYPE,
                                             MaxCount=1,
                                             MinCount=1,
                                             SecurityGroupIds=[sg_id],
                                             TagSpecifications=[
                                                 {'ResourceType': 'instance',
                                                  'Tags': TAGS}]
                                             )
    instance = response[0]
    instance.wait_until_running()
    instance.load()
    return instance


def start_test(lg_dns, first_web_service_dns):
    # Start the horizontal scaling test
    add_ws_string = 'http://{}/test/horizontal?dns={}'.\
        format(lg_dns, first_web_service_dns)
    while True:
        response = requests.get(add_ws_string)
        if response.status_code == 200:
            for line in response.text.splitlines():
                a = line.split("<a href='/log?name=", 1)
                b = a[1].split("'>Test</a>", 1)
                logFileName = b[0]
            break
    return logFileName


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(lg_dns, log_name):
    """
    Check if the horizontal scaling test has finished
    :param lg_dns: load generator DNS
    :param log_name: name of the log file
    :return: True if Horizontal Scaling test is complete and False otherwise.
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    return '[Test End]' in requests.get(log_string).text


def add_web_service_instance(lg_dns, sg2_id, log_name):
    """
    Launch a new WS (Web Server) instance and add to the test
    :param lg_dns: load generator DNS
    :param sg2_id: id of WS security group
    :param log_name: name of the log file
    """
    ins = create_instance(WEB_SERVICE_AMI, sg2_id)
    print("New WS launched. id={}, dns={}".format(
        ins.instance_id,
        ins.public_dns_name)
    )
    add_req = 'http://{}/test/horizontal/add?dns={}'.format(
        lg_dns,
        ins.public_dns_name
    )
    while True:
        if requests.get(add_req).status_code == 200:
            print("New WS submitted to LG.")
            break
        elif is_test_complete(lg_dns, log_name):
            print("New WS not submitted because test already completed.")
            break


def authenticate(lg_dns, tpz_password, tpz_username):
    """
    Authentication on LG
    :param lg_dns: LG DNS
    :param tpz_password: TPZ_PASSWORD
    :param tpz_username: TPZ_USERNAME
    :return: None
    """
    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        lg_dns, tpz_password, tpz_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass


def get_rps(lg_dns, log_name):
    """
    Return the current RPS as a floating point number
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: latest RPS value
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    config = configparser.ConfigParser(strict=False)
    config.read_string(requests.get(log_string).text)
    sections = config.sections()
    sections.reverse()
    rps = 0
    for sec in sections:
        if 'Current rps=' in sec:
            rps = float(sec[len('Current rps='):])
            break
    return rps


def get_test_start_time(lg_dns, log_name):
    """
    Return the test start time in UTC
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: datetime object of the start time in UTC
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    start_time = None
    while start_time is None:
        config = configparser.ConfigParser(strict=False)
        config.read_string(requests.get(log_string).text)
        # By default, options names in a section are converted
        # to lower case by configparser
        start_time = dict(config.items('Test')).get('starttime', None)
    return parse(start_time)


########################################
# Main routine
########################################
def main():
    print_section('1 - create two security groups')
    sg_permissions = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # Creating two separate security groups and obtain the group ids
    sg1_id_response = ec2_client.create_security_group(
        GroupName='Load_Generator_SG',
        Description='Created & Managed by boto3')
    sg1_id = sg1_id_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=sg1_id,
                                                IpPermissions=sg_permissions)

    sg2_id_response = ec2_client.create_security_group(
        GroupName='Web_Service_SG',
        Description='Created & Managed by boto3')
    sg2_id = sg2_id_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=sg2_id,
                                                IpPermissions=sg_permissions)

    print_section('2 - create LG')
    lg = create_instance(LOAD_GENERATOR_AMI, sg_id=sg1_id)
    lg_id = lg.instance_id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Authenticate with the load generator')
    authenticate(lg_dns, TPZ_PASSWORD, TPZ_USERNAME)

    print_section('4. Create WS')
    ws = create_instance(WEB_SERVICE_AMI, sg_id=sg2_id)
    web_service_dns = ws.public_dns_name

    print_section('5. Submit the first WS instance DNS to LG, starting test.')
    log_name = start_test(lg_dns, web_service_dns)
    last_launch_time = get_test_start_time(lg_dns, log_name)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)
        now = datetime.now(timezone.utc)
        if ((now - last_launch_time).total_seconds() > 100):
            rps = get_rps(lg_dns, log_name)
            if rps < 50:
                add_web_service_instance(lg_dns, sg2_id, log_name)
                last_launch_time = datetime.now(timezone.utc)

    print_section('End Test')
    # TODO: Terminate Resources


if __name__ == '__main__':
    main()
