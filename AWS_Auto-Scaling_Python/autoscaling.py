import boto3
import botocore
import os
import requests
import time
import json

########################################
# Constants
########################################
with open('auto-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
ASG_MAX_SIZE = configuration['asg_max_size']
ASG_MIN_SIZE = configuration['asg_min_size']
ASG_DESIRED_SIZE = configuration['asg_desired_size']
ASG_HEALTH_CHECK_GARCE_PERIOD = configuration['asd_health_check_grace_period']
COOL_DOWN_PERIOD_SCALE_IN = configuration['cool_down_period_scale_in']
COOL_DOWN_PERIOD_SCALE_OUT = configuration['cool_down_period_scale_out']
SCALE_OUT_ADJUSTMENT = configuration['scale_out_adjustment']
SCALE_IN_ADJUSTMENT = configuration['scale_in_adjustment']
ASG_DEFAULT_COOL_DOWN_PERIOD = configuration['asg_default_cool_down_period']
ALARM_PERIOD = configuration['alarm_period']
CPU_LOWER_THRESHOLD = configuration['cpu_lower_threshold']
CPU_UPPER_THRESHOLD = configuration['cpu_upper_threshold']
ALARM_EVAL_PERIODS_SCALE_OUT = configuration['alarm_eval_periods_scale_out']
ALARM_EVAL_PERIODS_SCALE_IN = configuration['alarm_eval_periods_scale_in']

TPZ_USERNAME = os.environ['TPZ_USERNAME']
TPZ_PASSWORD = os.environ['TPZ_PASSWORD']

ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')
autoscaling_client = boto3.client('autoscaling')
elb_client = boto3.client('elbv2')
cloudwatch_client = boto3.client('cloudwatch')

subnets = list(ec2_resource.subnets.filter(
    Filters=[
        {'Name': 'availabilityZone', 'Values': ['us-east-1a', 'us-east-1b']}]))

subnetID = []
for subnet in subnets:
    subnetID.append(subnet.id)

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


def start_test(load_generator_dns, first_web_service_dns):
    # Start the horizontal scaling test
    add_ws_string = 'http://{}/autoscaling?dns={}'. \
        format(load_generator_dns, first_web_service_dns)
    while True:
        response = requests.get(add_ws_string)
        if response.status_code == 200:
            a = response.text.split("<a href='/log?name=", 1)
            b = a[1].split("'>Test</a>", 1)
            log_file = b[0]
            break
    log_url = 'http://{}/log?name={}'.format(load_generator_dns, log_file)
    print(log_url)
    return log_file


def start_warmup(load_generator_dns, load_balancer_dns):
    # Start the warm up test
    add_ws_string = 'http://{}/warmup?dns={}'. \
        format(load_generator_dns, load_balancer_dns)
    while True:
        response = requests.get(add_ws_string)
        if response.status_code == 200:
            a = response.text.split("<a href='/log?name=", 1)
            b = a[1].split("'>Test</a>", 1)
            log_file = b[0]
            break
    log_url = 'http://{}/log?name={}'.format(load_generator_dns, log_file)
    print(log_url)
    return log_file


# Destroyed all resources launched
def destroy_resources(listener_arn, lb_arn, tg_arn, sg1_id, sg2_id):
    response = autoscaling_client.update_auto_scaling_group(
        AutoScalingGroupName="CMUProject21-ASG",
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
    )
    print("Auto Scaling Group Updated")
    InstanceIdList = []
    ImageIdList = [LOAD_GENERATOR_AMI, WEB_SERVICE_AMI]
    instances_data = ec2_client.describe_instances()
    for reservation in instances_data['Reservations']:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] != "terminated":
                if instance["ImageId"] in ImageIdList:
                    InstanceIdList.append(instance["InstanceId"])
    if len(InstanceIdList) != 0:
        instance_delete_response = ec2_resource.instances.filter(
            InstanceIds=InstanceIdList).terminate()
        print('The following Instances are deleted: {}'.format(InstanceIdList))
    else:
        print('No Instance deleted')

    list_response = elb_client.delete_listener(ListenerArn=listener_arn)
    lb_response = elb_client.delete_load_balancer(LoadBalancerArn=lb_arn)
    tg_response = elb_client.delete_target_group(TargetGroupArn=tg_arn)
    print("LB, TG & Listener are deleted")

    # deleting ASG deletes the policies and alarms linked with it.
    response = autoscaling_client.delete_auto_scaling_group(
        AutoScalingGroupName='CMUProject21-ASG',
        ForceDelete=True)
    response = autoscaling_client.delete_launch_configuration(
        LaunchConfigurationName='CMUProject21-LC')
    print("ASG & LC are deleted")

    while True:
        InstanceIdList = []
        instances_data = ec2_client.describe_instances()
        for reservation in instances_data['Reservations']:
            for instance in reservation["Instances"]:
                if instance["ImageId"] in ImageIdList:
                    if instance["State"]["Name"] != "terminated":
                        InstanceIdList.append(instance["InstanceId"])
        if len(InstanceIdList) == 0:
            response = ec2_client.delete_security_group(GroupId=sg1_id)
            response = ec2_client.delete_security_group(GroupId=sg2_id)
            break
        else:
            print("Waiting for instance to terminate completely")
            time.sleep(30)
    print("Security groups are deleted")


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(load_generator_dns, log_name):
    """
    Check if test is complete
    :param load_generator_dns: lg dns
    :param log_name: log file name
    :return: True if Auto Scaling test is complete and False otherwise.
    """
    log_string = 'http://{}/log?name={}'.format(load_generator_dns, log_name)
    return '[Test End]' in requests.get(log_string).text


def authenticate(load_generator_dns, tpz_password, tpz_username):
    """
    Authentication on LG
    :param load_generator_dns: LG DNS
    :param tpz_password: TPZ_PASSWORD
    :param tpz_username: TPZ_USERNAME
    :return: None
    """
    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        load_generator_dns, tpz_password, tpz_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass


########################################
# Main routine
########################################
def main():
    print_section('1 - create two security groups')

    permissions = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # security group 1: LG
    sg1_id_response = ec2_client.create_security_group(
        GroupName='Load_Generator_SG',
        Description='Created & Managed by boto3')
    sg1_id = sg1_id_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=sg1_id,
                                                IpPermissions=permissions)

    # security group 2: ASG, ELB
    sg2_id_response = ec2_client.create_security_group(
        GroupName='Web_Service_SG',
        Description='Created & Managed by boto3')
    sg2_id = sg2_id_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=sg2_id,
                                                IpPermissions=permissions)

    print_section('2 - create LG')
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    lg_id = lg.instance_id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    # Create Launch Config
    print_section('3. Create LC (Launch Config)')
    response = autoscaling_client.create_launch_configuration(
        LaunchConfigurationName='CMUProject21-LC',
        ImageId=WEB_SERVICE_AMI,
        InstanceType=INSTANCE_TYPE,
        InstanceMonitoring={'Enabled': True},
        SecurityGroups=[sg2_id]
    )

    # Create Target Group
    print_section('4. Create TG (Target Group)')
    VpcId_response = ec2_client.describe_security_groups(GroupIds=[sg2_id])
    VpcId = VpcId_response['SecurityGroups'][0]['VpcId']
    response = elb_client.create_target_group(Name='CMUProject21-TG',
                                              Protocol='HTTP',
                                              Port=80,
                                              HealthCheckProtocol='HTTP',
                                              HealthCheckPort='80',
                                              HealthCheckEnabled=True,
                                              HealthCheckPath='/',
                                              HealthCheckIntervalSeconds=30,
                                              HealthCheckTimeoutSeconds=5,
                                              HealthyThresholdCount=5,
                                              UnhealthyThresholdCount=2,
                                              Matcher={'HttpCode': '200'},
                                              VpcId=VpcId,
                                              TargetType='instance'
                                              )
    tg_arn = response["TargetGroups"][0]["TargetGroupArn"]

    # Create Load Balancer
    print_section('5. Create ELB (Elastic/Application Load Balancer)')
    response = elb_client.create_load_balancer(Name='CMUProject21-LBL',
                                               Subnets=subnetID,
                                               SecurityGroups=[sg2_id],
                                               Scheme='internet-facing',
                                               Tags=TAGS,
                                               Type='application',
                                               IpAddressType='ipv4'
                                               )
    lb_arn = response["LoadBalancers"][0]["LoadBalancerArn"]
    lb_dns = response["LoadBalancers"][0]["DNSName"]
    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))

    # Adding listener to ELB
    print_section('6. Associate ELB with target group')
    response = elb_client.create_listener(LoadBalancerArn=lb_arn,
                                          Protocol='HTTP',
                                          Port=80,
                                          DefaultActions=[
                                              {
                                                  'Type': 'forward',
                                                  'TargetGroupArn': tg_arn,
                                              }
                                          ]
                                          )
    listener_arn = response["Listeners"][0]["ListenerArn"]

    # Create Autoscaling groupCOOL_DOWN_PERIOD_SCALE_IN
    print_section('7. Create ASG (Auto Scaling Group)')
    response = autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='CMUProject21-ASG',
        LaunchConfigurationName='CMUProject21-LC',
        MinSize=ASG_MIN_SIZE,
        MaxSize=ASG_MAX_SIZE,
        DesiredCapacity=ASG_DESIRED_SIZE,
        DefaultCooldown=ASG_DEFAULT_COOL_DOWN_PERIOD,
        AvailabilityZones=['us-east-1a', 'us-east-1b'],
        TargetGroupARNs=[tg_arn],
        HealthCheckType='ELB',
        HealthCheckGracePeriod=ASG_HEALTH_CHECK_GARCE_PERIOD,
        NewInstancesProtectedFromScaleIn=False,
        Tags=[{'Key': 'Project', 'Value': '2.1', 'PropagateAtLaunch': True}]
    )

    response = autoscaling_client.enable_metrics_collection(
        AutoScalingGroupName='CMUProject21-ASG',
        Granularity='1Minute'
    )

    # Creating Policy and Attaching it to ASG
    print_section('8. Create policy and attached to ASG')
    CPU_ScaleOut_response = autoscaling_client.put_scaling_policy(
        AutoScalingGroupName='CMUProject21-ASG',
        PolicyName='CPUScaleOut',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=SCALE_OUT_ADJUSTMENT,
        Cooldown=COOL_DOWN_PERIOD_SCALE_OUT
    )
    CPU_ScaleIn_response = autoscaling_client.put_scaling_policy(
        AutoScalingGroupName='CMUProject21-ASG',
        PolicyName='CPUScaleIn',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=SCALE_IN_ADJUSTMENT,
        Cooldown=COOL_DOWN_PERIOD_SCALE_IN
    )
    CPUScaleOutPolicyARN = CPU_ScaleOut_response["PolicyARN"]
    CPUScaleInPolicyARN = CPU_ScaleIn_response["PolicyARN"]

    # Link the CloudWatch Alarms to policies
    print_section('9. Create Cloud Watch alarm. Action is to invoke policy.')
    ScaleOutPolicy_response = cloudwatch_client.put_metric_alarm(
        AlarmName='CPU_OUT_Alarm',
        ActionsEnabled=True,
        AlarmActions=[CPUScaleOutPolicyARN],
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[
            {'Name': 'AutoScalingGroupName', 'Value': 'CMUProject21-ASG'}],
        Period=ALARM_PERIOD,
        EvaluationPeriods=ALARM_EVAL_PERIODS_SCALE_OUT,
        Threshold=CPU_UPPER_THRESHOLD,
        ComparisonOperator='GreaterThanOrEqualToThreshold',
        TreatMissingData="ignore",
        Tags=TAGS
    )
    ScaleInPolicy_response = cloudwatch_client.put_metric_alarm(
        AlarmName='CPU_IN_Alarm',
        ActionsEnabled=True,
        AlarmActions=[CPUScaleInPolicyARN],
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[
            {'Name': 'AutoScalingGroupName', 'Value': 'CMUProject21-ASG'}],
        Period=ALARM_PERIOD,
        EvaluationPeriods=ALARM_EVAL_PERIODS_SCALE_IN,
        Threshold=CPU_LOWER_THRESHOLD,
        ComparisonOperator='LessThanOrEqualToThreshold',
        TreatMissingData="ignore",
        Tags=TAGS
    )

    # Testing Resources
    print_section('10. Testing the Created Resources.')
    # Testing Load Balancer
    while True:
        response = elb_client.describe_load_balancers(
            LoadBalancerArns=[lb_arn])
        elb_Status = response["LoadBalancers"][0]["State"]["Code"]
        if (elb_Status == "active"):
            print("LB is in Active state!!")
            break
        else:
            print("LB is provisioning...")
            time.sleep(20)

    # Testing Alarm
    while True:
        response = cloudwatch_client.describe_alarms(
            AlarmNames=["CPU_OUT_Alarm"])
        if response["MetricAlarms"][0]["StateValue"] == "INSUFFICIENT_DATA":
            print("CPU_OUT_Alarm is in InSufficient Data Stage")
            time.sleep(20)
        else:
            print("CPU_OUT_Alarm_1 is in OK Stage")
            break
    while True:
        response = cloudwatch_client.describe_alarms(
            AlarmNames=["CPU_IN_Alarm"])
        if response["MetricAlarms"][0]["StateValue"] == "INSUFFICIENT_DATA":
            print("CPU_IN_Alarm is in InSufficient Data Stage")
            time.sleep(20)
        else:
            print("CPU_OUT_Alarm_1 is in OK Stage")
            break

    print_section('10. Authenticate with the load generator')
    authenticate(lg_dns, TPZ_PASSWORD, TPZ_USERNAME)

    print_section('11. Submit ELB DNS to LG, starting warm up test.')
    warmup_log_name = start_warmup(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, warmup_log_name):
        time.sleep(1)

    print_section('12. Submit ELB DNS to LG, starting actual test.')
    log_name = start_test(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)

    print_section('13. Deleting Resources')
    destroy_resources(listener_arn, lb_arn, tg_arn, sg1_id, sg2_id)

    print_section('Program Completed')


if __name__ == "__main__":
    main()
