# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from aws_cdk import core, aws_codebuild as codebuild, aws_iam as iam, aws_ec2 as ec2, aws_efs as efs
from util.iam_policies import code_build_batch_policy_in_json, ecr_pull_only_policy_in_json
from util.metadata import AWS_ACCOUNT, AWS_REGION, GITHUB_REPO_OWNER, GITHUB_REPO_NAME
from util.yml_loader import YmlLoader


class AwsLcGitHubFuzzCIStack(core.Stack):
    """Define a stack used to batch execute AWS-LC tests in GitHub."""

    def __init__(self,
                 scope: core.Construct,
                 id: str,
                 x86_ecr_repo_name: str,
                 arm_ecr_repo_name: str,
                 spec_file_path: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Define CodeBuild resource.
        git_hub_source = codebuild.Source.git_hub(
            owner=GITHUB_REPO_OWNER,
            repo=GITHUB_REPO_NAME,
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PULL_REQUEST_CREATED,
                    codebuild.EventAction.PULL_REQUEST_UPDATED,
                    codebuild.EventAction.PULL_REQUEST_REOPENED)
            ],
            clone_depth=1)

        # Define a IAM role for this stack.
        code_build_batch_policy = iam.PolicyDocument.from_json(
            code_build_batch_policy_in_json([id])
        )
        ecr_pull_only_policy = iam.PolicyDocument.from_json(
            ecr_pull_only_policy_in_json([x86_ecr_repo_name, arm_ecr_repo_name])
        )
        inline_policies = {"code_build_batch_policy": code_build_batch_policy,
                           "ecr_pull_only_policy": ecr_pull_only_policy,
                           "fuzz_policy": ecr_pull_only_policy}
        role = iam.Role(scope=self,
                        id="{}-role".format(id),
                        assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
                        inline_policies=inline_policies)

        # Create the VPC for EFS and CodeBuild
        public_subnet = ec2.SubnetConfiguration(name="PublicFuzzingSubnet", subnet_type=ec2.SubnetType.PUBLIC)
        private_subnet = ec2.SubnetConfiguration(name="PrivateFuzzingSubnet", subnet_type=ec2.SubnetType.PRIVATE)

        # Create a VPC with a single public and private subnet in a single AZ. This is to avoid the elastic IP limit
        # being used up by a bunch of idle NAT gateways
        fuzz_vpc = ec2.Vpc(
            scope=self,
            id="FuzzingVPC",
            subnet_configuration=[public_subnet, private_subnet],
            max_azs=1
        )
        build_security_group = ec2.SecurityGroup(
            scope=self,
            id="FuzzingSecurityGroup",
            vpc=fuzz_vpc
        )

        efs_subnet_selection = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)

        # Create the EFS to store the corpus and logs
        fuzz_filesystem = efs.FileSystem(
            scope=self,
            id="FuzzingEFS",
            file_system_name="AWS-LC-Fuzz-Corpus",
            enable_automatic_backups=True,
            encrypted=True,
            security_group=build_security_group,
            vpc=fuzz_vpc,
            vpc_subnets=efs_subnet_selection
        )

        # Create build spec.
        placeholder_map = {"AWS_ACCOUNT_ID_PLACEHOLDER": AWS_ACCOUNT, "AWS_REGION_PLACEHOLDER": AWS_REGION,
                           "X86_ECR_REPO_PLACEHOLDER": x86_ecr_repo_name, "ARM_ECR_REPO_PLACEHOLDER": arm_ecr_repo_name}
        build_spec_content = YmlLoader.load(spec_file_path, placeholder_map)

        # Define CodeBuild.
        fuzz_codebuild = codebuild.Project(
            scope=self,
            id="FuzzingCodeBuild",
            project_name=id,
            source=git_hub_source,
            role=role,
            timeout=core.Duration.minutes(120),
            environment=codebuild.BuildEnvironment(compute_type=codebuild.ComputeType.LARGE,
                                                   privileged=True,
                                                   build_image=codebuild.LinuxBuildImage.STANDARD_4_0),
            build_spec=codebuild.BuildSpec.from_object(build_spec_content),
            vpc=fuzz_vpc)

        # TODO: add build type BUILD_BATCH when CFN finishes the feature release. See CryptoAlg-575.

        # Add 'BuildBatchConfig' property, which is not supported in CDK.
        # CDK raw overrides: https://docs.aws.amazon.com/cdk/latest/guide/cfn_layer.html#cfn_layer_raw
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#aws-resource-codebuild-project-properties
        cfn_codebuild = fuzz_codebuild.node.default_child
        cfn_codebuild.add_override("Properties.BuildBatchConfig", {
            "ServiceRole": role.role_arn,
            "TimeoutInMins": 120
        })

        # The EFS identifier needs to match tests/ci/common_fuzz.sh, CodeBuild defines an environment variable named
        # codebuild_$identifier.
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-projectfilesystemlocation.html
        # TODO: add this to the CDK project above when it supports EfsFileSystemLocation
        cfn_codebuild.add_override("Properties.FileSystemLocations", [{
          "Identifier": "fuzzing_root",
          "Location": "%s.efs.%s.amazonaws.com:/" % (fuzz_filesystem.file_system_id, AWS_REGION),
          "MountPoint": "/efs_fuzzing_root",
          "Type": "EFS"
        }])
