# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import (
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_ecs as ecs,
    aws_rds as rds,
    aws_iam as iam,
    aws_secretsmanager as sm,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticloadbalancingv2 as elbv2,
    aws_sagemaker as sagemaker,
    aws_kms as kms,
    App, Stack, CfnParameter, CfnOutput, Aws, RemovalPolicy, Duration

)
from constructs import Construct
import boto3


class DeploymentStack(Stack):
    export_vpc: ec2.Vpc
    export_sg: str

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        # ==============================
        # ======= CFN PARAMETERS =======
        # ==============================
        environment = CfnParameter(scope=self, id='Environment', type='String')
        db_name = 'mlflowdb'
        port = 3306
        username = 'master'
        bucket_name = f'mlflow-artifacts-{Aws.ACCOUNT_ID}'
        container_repo_name = 'mlflow-containers'
        cluster_name = 'mlflow'
        service_name = 'mlflow'

        # ==================================================
        # ================= IAM ROLE =======================
        # ==================================================
        role = iam.Role(scope=self, id='TASKROLE', assumed_by=iam.ServicePrincipal(service='ecs-tasks.amazonaws.com'))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3FullAccess'))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonECS_FullAccess'))

        # ==================================================
        # ================== SECRET ========================
        # ==================================================
        db_password_secret = sm.Secret(
            scope=self,
            id='DBSECRET',
            secret_name='dbPassword',
            generate_secret_string=sm.SecretStringGenerator(password_length=20, exclude_punctuation=True)
        )

        # ==================================================
        # ==================== VPC =========================
        # ==================================================
        public_subnet = ec2.SubnetConfiguration(name='Public', subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=28)
        private_subnet = ec2.SubnetConfiguration(
            name='Private',
            subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
            cidr_mask=26)
        isolated_subnet = ec2.SubnetConfiguration(name='DB', subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=28)

        vpc = ec2.Vpc(
            scope=self,
            id='VPC',
            cidr='10.0.0.0/24',
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[public_subnet, private_subnet, isolated_subnet]
        )
        self.export_vpc = vpc

        # ==================================================
        # ==================== Sagemaker Config =========================
        # ==================================================
        sg_sagemaker = ec2.SecurityGroup(scope=self, id='SGSAGEMAKER', vpc=vpc, security_group_name='sg_sagemaker')
        # NFS traffic
        sg_sagemaker.add_ingress_rule(peer=ec2.Peer.ipv4('10.0.0.0/24'), connection=ec2.Port.tcp(2049))
        # All TCP traffic within security group
        sg_sagemaker.add_ingress_rule(peer=sg_sagemaker, connection=ec2.Port.all_tcp())
        self.export_sg = sg_sagemaker.security_group_id

        vpc.add_gateway_endpoint('S3Endpoint', service=ec2.GatewayVpcEndpointAwsService.S3)

        # ==================================================
        # ================= S3 BUCKET ======================
        # ==================================================
        artifact_bucket = s3.Bucket(
            scope=self,
            id='ARTIFACTBUCKET',
            bucket_name=bucket_name,
            public_read_access=False,
            encryption=s3.BucketEncryption.KMS_MANAGED
        )
        # # ==================================================
        # # ================== DATABASE  =====================
        # # ==================================================
        # Creates a security group for AWS RDS
        sg_rds = ec2.SecurityGroup(scope=self, id='SGRDS', vpc=vpc, security_group_name='sg_rds')
        # Adds an ingress rule which allows resources in the VPC's CIDR to access the database.
        sg_rds.add_ingress_rule(peer=ec2.Peer.ipv4('10.0.0.0/24'), connection=ec2.Port.tcp(port))

        database = rds.DatabaseInstance(
            scope=self,
            id='MYSQL',
            database_name=db_name,
            port=port,
            credentials=rds.Credentials.from_username(username=username, password=db_password_secret.secret_value),
            engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_26),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
            vpc=vpc,
            security_groups=[sg_rds],
            vpc_subnets=ec2.SubnetSelection(subnet_group_name='DB'),
            # multi_az=True,
            removal_policy=RemovalPolicy.DESTROY,
            deletion_protection=False
        )
        # ==================================================
        # =============== FARGATE SERVICE ==================
        # ==================================================
        cluster = ecs.Cluster(scope=self, id='CLUSTER', cluster_name=cluster_name, vpc=vpc)

        task_definition = ecs.FargateTaskDefinition(
            scope=self,
            id='MLflow',
            task_role=role
        )

        container = task_definition.add_container(
            id='Container',
            image=ecs.ContainerImage.from_asset(directory='container'),
            environment={
                'BUCKET': f's3://{artifact_bucket.bucket_name}',
                'HOST': database.db_instance_endpoint_address,
                'PORT': str(port),
                'DATABASE': db_name,
                'USERNAME': username
            },
            secrets={
                'PASSWORD': ecs.Secret.from_secrets_manager(db_password_secret)
            },
            logging=ecs.LogDriver.aws_logs(stream_prefix='mlflow')
        )
        port_mapping = ecs.PortMapping(container_port=5000, host_port=5000, protocol=ecs.Protocol.TCP)
        container.add_port_mappings(port_mapping)

        vpc_subnets = ec2.SubnetSelection(subnet_group_name=private_subnet.name, one_per_az=True)

        lb = elbv2.NetworkLoadBalancer(scope=self, id="MLFLOWInternalLB", vpc=vpc, vpc_subnets=vpc_subnets)

        fargate_service = ecs_patterns.NetworkLoadBalancedFargateService(
            scope=self,
            id='MLFLOW',
            service_name=service_name,
            cluster=cluster,
            task_definition=task_definition,
            load_balancer=lb,
            task_subnets=vpc_subnets,
            public_load_balancer=False
        )

        # Setup security group
        fargate_service.service.connections.security_groups[0].add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(5000),
            description='Allow inbound from VPC for mlflow'
        )

        fargate_service.service.connections.security_groups.append(sg_sagemaker)

        # Setup autoscaling policy
        scaling = fargate_service.service.auto_scale_task_count(max_capacity=2)
        scaling.scale_on_cpu_utilization(
            id='AUTOSCALING',
            target_utilization_percent=70,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60)
        )
        # ==================================================
        # =================== OUTPUTS ======================
        # ==================================================
        CfnOutput(scope=self, id='LoadBalancerDNS', value=fargate_service.load_balancer.load_balancer_dns_name)


class SagemakerStack(Stack):
    def __init__(self, scope: Construct, id: str, vpc: ec2.Vpc, security_group: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        environment = CfnParameter(scope=self, id='Environment', type='String')
        auth_mode = "SSO"
        subnet_ids = [subnet.subnet_id for subnet in vpc.private_subnets]
        # subnet_ids = ec2.Vpc.fromLookup(scope=self, id="VPC", vpc_id=vpc_id).private_subnets
        security_groups = [security_group]
        aws_client = boto3.client('iam')
        roles = aws_client.list_roles()['Roles']
        sagemaker_roles = [role for role in roles if 'SageMaker' in role['RoleName']]
        execution_roles = [role for role in sagemaker_roles if 'ExecutionRole' in role['RoleName']]
        if len(execution_roles) > 0:
            execution_role = iam.Role.from_role_arn(self, id='SM_EXECUTION_ROLE', role_arn=execution_roles[0]['Arn'])
        else:
            execution_policy_document = iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:ListBucket"],
                        resources=["arn:aws:s3:::SageMaker"]
                    ),
                    iam.PolicyStatement(
                        actions=["s3.GetObject", "s3:PutObject", "s3:DeleteObject"],
                        resources=["arn:aws:s3:::SageMaker/*"]
                    )
                ]
            )
            managed_policy = iam.ManagedPolicy.from_managed_policy_arn("arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
            execution_role = iam.Role(inline_policies=execution_policy_document, managed_policies=managed_policy)
        user_settings_property = sagemaker.CfnDomain.UserSettingsProperty(
            security_groups=security_groups,
            execution_role=execution_role.role_arn
        )
        app_network_access_type = "VpcOnly"
        encryption_key = kms.Key(scope=self, id="SagemakerKey", enable_key_rotation=True)
        vpc_id = vpc.vpc_id
        cfn_domain = sagemaker.CfnDomain(scope=self, id="SagemakerDomain",
                                         auth_mode=auth_mode,
                                         default_user_settings=user_settings_property,
                                         domain_name=environment.value_as_string,
                                         subnet_ids=subnet_ids,
                                         vpc_id=vpc_id,
                                         app_network_access_type=app_network_access_type,
                                         kms_key_id=encryption_key.key_id
                                         )
        CfnOutput(scope=self, id='Sagemaker Domain Name', value=cfn_domain.domain_name)
        CfnOutput(scope=self, id='Sagemaker Domain ID', value=cfn_domain.attr_domain_id)


app = App()
mlflow = DeploymentStack(app, "MLFlowDeploymentStack")
SagemakerStack(app, "SagemakerStudioStack", vpc=mlflow.export_vpc, security_group=mlflow.export_sg)
app.synth()
