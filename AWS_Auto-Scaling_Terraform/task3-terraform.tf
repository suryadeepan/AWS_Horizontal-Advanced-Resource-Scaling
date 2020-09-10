###########################################################################
# Template for P2 AWS Autoscaling Test                                    #
# Do not edit the first section                                           #
# Only edit the second section to configure appropriate scaling policies  #
###########################################################################

############################
# FIRST SECTION BEGINS     #
# DO NOT EDIT THIS SECTION #
############################
locals {
  common_tags = {
    Project = "2.1"
  }
  asg_tags = [
    {
      key                 = "Project"
      value               = "2.1"
      propagate_at_launch = true
    }
  ]
}

provider "aws" {
  region                      = "us-east-1"

  # These lines are required by the submitter. 
  # Comment these out if you want to run your terraform locally
  # But make sure you add them back before submitting else you will not receive a score 
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "cmu_cc"
  secret_key                  = "cmu_cc"
}


resource "aws_security_group" "lg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${local.common_tags}"
}

resource "aws_security_group" "elb_asg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${local.common_tags}"
}

######################
# FIRST SECTION ENDS #
######################

############################
# SECOND SECTION BEGINS    #
# PLEASE EDIT THIS SECTION #
############################

# Step 1: Add missing values below 
# ================================
resource "aws_launch_configuration" "lc" {
  image_id      = "ami-0120179ee1facd28b"
  instance_type = "m5.large"
  security_groups = ["${aws_security_group.elb_asg.id}"]
}

resource "aws_autoscaling_group" "asg" {
  availability_zones = ["us-east-1a"]
  max_size             = 5
  min_size             = 2
  desired_capacity     = 2
  default_cooldown     = 30
  health_check_grace_period = 120
  health_check_type    = "ELB"
  launch_configuration = "${aws_launch_configuration.lc.name}"
  load_balancers       = ["${aws_lb.CMUProject21-LBL.name}"]

  tags  = "${local.asg_tags}"
}

# Step 2: Create an Application Load Balancer with appropriate listeners and target groups
# ========================================================================================
resource "aws_lb_target_group" "CMUProject21-TG" {
  name     = "CMUProject21-TG"
  protocol = "HTTP"
  port     = 80
  health_check {
	enabled = true
	interval = 30
    path = "/"
    port = 80
	protocol = "HTTP"
	timeout = 5
    healthy_threshold = 5
    unhealthy_threshold = 5
    matcher = "200"
  }
}

resource "aws_default_subnet" "default_subnet" {
  availability_zone = "us-east-1a"
}

resource "aws_lb" "CMUProject21-LBL" {
  name = "CMUProject21-LBL"
  subnets = ["${aws_default_subnet.default_subnet.id}"]
  security_groups = ["${aws_security_group.elb_asg.id}"]
  internal = false
  load_balancer_type = "application"
  ip_address_type = "ipv4"
}

resource "aws_lb_listener" "CMUProject21-Listener" {
  load_balancer_arn = "${aws_lb.CMUProject21-LBL.arn}"
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.CMUProject21-TG.arn}"
  }
}

# Step 3: Create 2 policies: 1 for scaling out and another for scaling in
# =======================================================================
resource "aws_autoscaling_policy" "CPUScaleOut" {
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
  name = "CPUScaleOut"
  policy_type = "SimpleScaling"
  adjustment_type = "ChangeInCapacity"
  scaling_adjustment = 1
  cooldown = 100
}
resource "aws_autoscaling_policy" "CPUScaleIn" {
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
  name = "CPUScaleIn"
  policy_type = "SimpleScaling"
  adjustment_type = "ChangeInCapacity"
  scaling_adjustment = -1
  cooldown = 60
}

# Step 4: Create 2 cloudwatch alarms: 1 for scaling out and another for scaling in
# ===============================================================================
resource "aws_cloudwatch_metric_alarm" "CPU_OUT_Alarm" {
  alarm_name          = "CPU_OUT_Alarm"
  actions_enabled = true
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }
  period              = "60"
  evaluation_periods  = "1"
  threshold           = "80"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions     = ["${aws_autoscaling_policy.CPUScaleOut.arn}"]
}
resource "aws_cloudwatch_metric_alarm" "CPU_IN_Alarm" {
  alarm_name          = "CPU_IN_Alarm"
  actions_enabled = true
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }
  period              = "60"
  evaluation_periods  = "1"
  threshold           = "40"
  comparison_operator = "LessThanOrEqualToThreshold"
  alarm_actions     = ["${aws_autoscaling_policy.CPUScaleIn.arn}"]
}

######################################
# SECOND SECTION ENDS                #
# MAKE SURE YOU COMPLETE ALL 3 STEPS #
######################################
