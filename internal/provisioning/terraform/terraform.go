package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	provisioningtypes "github.com/subinc/subinc-backend/internal/provisioningtypes"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cpTypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetype "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const (
	provisionStatusPrefix = "provision:status:"
	terraformStateDir     = "/var/lib/subinc/terraform-state" // Must be writable, secure, and tenant-isolated
)

// TerraformProvisioner implements provisioning.Provisioner using Terraform as the backend.
type TerraformProvisioner struct {
	redis  *redis.Client
	logger *logger.Logger
}

func NewTerraformProvisioner(redis *redis.Client, logger *logger.Logger) *TerraformProvisioner {
	return &TerraformProvisioner{redis: redis, logger: logger}
}

func (p *TerraformProvisioner) Provision(ctx context.Context, req *provisioningtypes.ProvisionRequest) (*provisioningtypes.ProvisionStatus, error) {
	if req == nil || req.TenantID == "" || req.OrgID == "" || req.ProjectID == "" || req.Provider == "" || req.Resource == "" {
		return nil, fmt.Errorf("invalid provision request: missing required fields")
	}
	id := generateProvisionID(req)
	status := &provisioningtypes.ProvisionStatus{
		ID:        id,
		Request:   *req,
		Status:    "pending",
		Message:   "Queued for provisioning",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := p.SaveStatus(ctx, status); err != nil {
		return nil, err
	}
	return status, nil
}

func (p *TerraformProvisioner) GetStatus(ctx context.Context, id string) (*provisioningtypes.ProvisionStatus, error) {
	if id == "" {
		return nil, fmt.Errorf("missing provision id")
	}
	data, err := p.redis.Get(ctx, provisionStatusPrefix+id).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("provision status not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get provision status: %w", err)
	}
	var status provisioningtypes.ProvisionStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to decode provision status: %w", err)
	}
	return &status, nil
}

func (p *TerraformProvisioner) List(ctx context.Context, tenantID, orgID, projectID string) ([]*provisioningtypes.ProvisionStatus, error) {
	pattern := fmt.Sprintf("%s%s:%s:%s:*", provisionStatusPrefix, tenantID, orgID, projectID)
	keys, err := p.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list provision statuses: %w", err)
	}
	var statuses []*provisioningtypes.ProvisionStatus
	for _, key := range keys {
		data, err := p.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}
		var status provisioningtypes.ProvisionStatus
		if err := json.Unmarshal(data, &status); err == nil {
			statuses = append(statuses, &status)
		}
	}
	return statuses, nil
}

func (p *TerraformProvisioner) Cancel(ctx context.Context, id string) error {
	status, err := p.GetStatus(ctx, id)
	if err != nil {
		return err
	}
	if status.Status == "success" || status.Status == "failed" {
		return fmt.Errorf("cannot cancel completed provision")
	}
	// Mark as cancelled
	status.Status = "cancelled"
	status.Message = "Provisioning cancelled by user"
	status.UpdatedAt = time.Now().UTC()
	return p.SaveStatus(ctx, status)
}

func (p *TerraformProvisioner) SaveStatus(ctx context.Context, status *provisioningtypes.ProvisionStatus) error {
	if status == nil {
		return fmt.Errorf("nil status")
	}
	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}
	key := provisionStatusPrefix + status.ID
	return p.redis.Set(ctx, key, data, 30*24*time.Hour).Err() // 30d retention
}

func generateProvisionID(req *provisioningtypes.ProvisionRequest) string {
	return fmt.Sprintf("%s:%s:%s:%s:%d", req.TenantID, req.OrgID, req.ProjectID, req.Resource, time.Now().UnixNano())
}

// --- ASYNQ JOB HANDLER (to be registered in main.go or jobs package) ---
// func HandleTerraformProvisionJob(ctx context.Context, task *asynq.Task) error { ... }

// --- TERRAFORM EXECUTION LOGIC ---

// Replace all Terraform CLI logic with Go SDK resource creation
func (p *TerraformProvisioner) runProvisioning(ctx context.Context, req *provisioningtypes.ProvisionRequest) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(req.Config["region"]))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	switch req.Provider {
	case "aws":
		switch req.Resource {
		case "ec2":
			err = createEC2(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create EC2 instance: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "s3":
			s3Client := s3.NewFromConfig(cfg)
			bucket := req.Config["bucket_name"]
			_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
			if err != nil {
				return "", fmt.Errorf("failed to create S3 bucket: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "rds":
			rdsClient := rds.NewFromConfig(cfg)
			_, err = rdsClient.CreateDBInstance(ctx, &rds.CreateDBInstanceInput{
				DBInstanceIdentifier: aws.String(req.Config["db_instance_identifier"]),
				AllocatedStorage:     aws.Int32(20),
				DBInstanceClass:      aws.String(req.Config["db_instance_class"]),
				Engine:               aws.String(req.Config["engine"]),
				MasterUsername:       aws.String(req.Config["master_username"]),
				MasterUserPassword:   aws.String(req.Config["master_user_password"]),
			})
			if err != nil {
				return "", fmt.Errorf("failed to create RDS instance: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "lambda":
			lambdaClient := lambda.NewFromConfig(cfg)
			_, err = lambdaClient.CreateFunction(ctx, &lambda.CreateFunctionInput{
				FunctionName: aws.String(req.Config["function_name"]),
				Role:         aws.String(req.Config["role_arn"]),
				Handler:      aws.String(req.Config["handler"]),
				Runtime:      lambdatypes.Runtime(req.Config["runtime"]),
				Code: &lambdatypes.FunctionCode{
					S3Bucket: aws.String(req.Config["code_s3_bucket"]),
					S3Key:    aws.String(req.Config["code_s3_key"]),
				},
			})
			if err != nil {
				return "", fmt.Errorf("failed to create Lambda function: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "dynamodb":
			dynamoClient := dynamodb.NewFromConfig(cfg)
			_, err = dynamoClient.CreateTable(ctx, &dynamodb.CreateTableInput{
				TableName: aws.String(req.Config["table_name"]),
				AttributeDefinitions: []ddbtypes.AttributeDefinition{{
					AttributeName: aws.String(req.Config["hash_key"]),
					AttributeType: ddbtypes.ScalarAttributeType(req.Config["hash_key_type"]),
				}},
				KeySchema: []ddbtypes.KeySchemaElement{{
					AttributeName: aws.String(req.Config["hash_key"]),
					KeyType:       ddbtypes.KeyTypeHash,
				}},
				ProvisionedThroughput: &ddbtypes.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(1),
					WriteCapacityUnits: aws.Int64(1),
				},
			})
			if err != nil {
				return "", fmt.Errorf("failed to create DynamoDB table: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "vpc":
			err = createVPC(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create VPC: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "subnet":
			err = createSubnet(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Subnet: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "security_group":
			err = createSecurityGroup(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Security Group: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "iam_role":
			err = createIAMRole(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create IAM Role: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "sqs":
			err = createSQS(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create SQS queue: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "sns":
			err = createSNS(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create SNS topic: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "efs":
			err = createEFS(ctx, cfg)
			if err != nil {
				return "", fmt.Errorf("failed to create EFS: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "eks":
			err = createEKS(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create EKS cluster: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "cloudfront":
			err = createCloudFront(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CloudFront distribution: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "route53_zone":
			err = createRoute53Zone(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Route53 zone: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "alb":
			err = createALB(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create ALB: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "elasticache":
			err = createElasticache(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Elasticache: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "redshift":
			err = createRedshift(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Redshift: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "kinesis":
			err = createKinesis(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Kinesis: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "log_group":
			err = createLogGroup(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CloudWatch Log Group: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "ssm_parameter":
			err = createSSMParameter(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create SSM Parameter: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "secret":
			err = createSecret(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Secret: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "autoscaling_group":
			err = createAutoScalingGroup(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Auto Scaling Group: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "eni":
			err = createENI(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create ENI: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "eip":
			err = createEIP(ctx, cfg)
			if err != nil {
				return "", fmt.Errorf("failed to create EIP: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "efs_mount_target":
			err = createEFSMountTarget(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create EFS Mount Target: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "step_function":
			err = createStepFunction(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Step Function: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "glue_job":
			err = createGlueJob(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Glue Job: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "athena_workgroup":
			err = createAthenaWorkgroup(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Athena Workgroup: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "s3_bucket_policy":
			err = createS3BucketPolicy(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create S3 Bucket Policy: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "cloudtrail":
			err = createCloudTrail(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CloudTrail: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "cloudformation_stack":
			err = createCloudFormationStack(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CloudFormation Stack: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "codebuild_project":
			err = createCodeBuildProject(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CodeBuild Project: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "codepipeline":
			err = createCodePipeline(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CodePipeline: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "codedeploy":
			err = createCodeDeploy(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create CodeDeploy: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "elastic_beanstalk":
			err = createElasticBeanstalk(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create Elastic Beanstalk: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		case "appconfig":
			err = createAppConfig(ctx, cfg, req)
			if err != nil {
				return "", fmt.Errorf("failed to create AppConfig: %w", err)
			}
			hcl := generateTerraformConfig(req)
			return hcl, nil
		// Add more AWS resources here (VPC, Subnet, Security Group, etc.)
		default:
			return "", fmt.Errorf("unsupported AWS resource: %s", req.Resource)
		}
	default:
		return "", fmt.Errorf("unsupported provider: %s", req.Provider)
	}
}

// Update RunTerraformJob to RunProvisionJob
func (p *TerraformProvisioner) RunProvisionJob(ctx context.Context, id string, req *provisioningtypes.ProvisionRequest) error {
	hcl, err := p.runProvisioning(ctx, req)
	if err != nil {
		return err
	}
	status, err := p.GetStatus(ctx, id)
	if err != nil {
		return err
	}
	status.Status = "success"
	status.Message = "Provisioning complete"
	status.UpdatedAt = time.Now().UTC()
	status.TerraformHCL = hcl
	return p.SaveStatus(ctx, status)
}

func generateTerraformConfig(req *provisioningtypes.ProvisionRequest) string {
	// Real implementation: use templates, modules, and req.Config for resource
	// This is a minimal, real-world example for AWS EC2 (expand for other providers/resources)
	if req.Provider == "aws" && req.Resource == "ec2" {
		return fmt.Sprintf(`
provider "aws" {
  region = "%s"
}
resource "aws_instance" "example" {
  ami           = "%s"
  instance_type = "%s"
  tags = {
    Name = "%s"
  }
}
`, req.Config["region"], req.Config["ami"], req.Config["instance_type"], req.Config["name"])
	}
	return "" // Unsupported provider/resource
}

// Modularize resource creation for maintainability
func createEC2(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(req.Config["ami"]),
		InstanceType: types.InstanceType(req.Config["instance_type"]),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
	}
	if v, ok := req.Config["key_name"]; ok {
		input.KeyName = aws.String(v)
	}
	if v, ok := req.Config["user_data"]; ok {
		input.UserData = aws.String(v)
	}
	if v, ok := req.Config["subnet_id"]; ok {
		input.SubnetId = aws.String(v)
	}
	if v, ok := req.Config["security_group_ids"]; ok {
		input.SecurityGroupIds = strings.Split(v, ",")
	}
	if v, ok := req.Config["block_device_mappings"]; ok {
		// Expecting JSON array of mappings
		var mappings []types.BlockDeviceMapping
		_ = json.Unmarshal([]byte(v), &mappings)
		input.BlockDeviceMappings = mappings
	}
	if v, ok := req.Config["tags"]; ok {
		// Expecting JSON object of tags
		var tagsMap map[string]string
		_ = json.Unmarshal([]byte(v), &tagsMap)
		tags := make([]types.Tag, 0, len(tagsMap))
		for k, v := range tagsMap {
			tags = append(tags, types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		input.TagSpecifications = []types.TagSpecification{{
			ResourceType: types.ResourceTypeInstance,
			Tags:         tags,
		}}
	}
	_, err := ec2Client.RunInstances(ctx, input)
	return err
}

func createVPC(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	vpcClient := ec2.NewFromConfig(cfg)
	input := &ec2.CreateVpcInput{
		CidrBlock: aws.String(req.Config["cidr_block"]),
	}
	_, err := vpcClient.CreateVpc(ctx, input)
	return err
}

func createSubnet(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.CreateSubnetInput{
		VpcId:            aws.String(req.Config["vpc_id"]),
		CidrBlock:        aws.String(req.Config["cidr_block"]),
		AvailabilityZone: aws.String(req.Config["availability_zone"]),
	}
	_, err := ec2Client.CreateSubnet(ctx, input)
	return err
}

func createSecurityGroup(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(req.Config["group_name"]),
		Description: aws.String(req.Config["description"]),
		VpcId:       aws.String(req.Config["vpc_id"]),
	}
	_, err := ec2Client.CreateSecurityGroup(ctx, input)
	return err
}

func createIAMRole(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	iamClient := iam.NewFromConfig(cfg)
	input := &iam.CreateRoleInput{
		RoleName:                 aws.String(req.Config["role_name"]),
		AssumeRolePolicyDocument: aws.String(req.Config["assume_role_policy"]),
	}
	_, err := iamClient.CreateRole(ctx, input)
	return err
}

func createSQS(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	sqsClient := sqs.NewFromConfig(cfg)
	input := &sqs.CreateQueueInput{
		QueueName: aws.String(req.Config["queue_name"]),
	}
	_, err := sqsClient.CreateQueue(ctx, input)
	return err
}

func createSNS(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	snsClient := sns.NewFromConfig(cfg)
	input := &sns.CreateTopicInput{
		Name: aws.String(req.Config["topic_name"]),
	}
	_, err := snsClient.CreateTopic(ctx, input)
	return err
}

func createEFS(ctx context.Context, cfg aws.Config) error {
	efsClient := efs.NewFromConfig(cfg)
	input := &efs.CreateFileSystemInput{}
	_, err := efsClient.CreateFileSystem(ctx, input)
	return err
}

func createEKS(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	eksClient := eks.NewFromConfig(cfg)
	input := &eks.CreateClusterInput{
		Name:    aws.String(req.Config["cluster_name"]),
		RoleArn: aws.String(req.Config["role_arn"]),
		ResourcesVpcConfig: &ekstypes.VpcConfigRequest{
			SubnetIds:        strings.Split(req.Config["subnet_ids"], ","),
			SecurityGroupIds: strings.Split(req.Config["security_group_ids"], ","),
		},
	}
	_, err := eksClient.CreateCluster(ctx, input)
	return err
}

func createCloudFront(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	cfClient := cloudfront.NewFromConfig(cfg)
	input := &cloudfront.CreateDistributionInput{
		DistributionConfig: &cloudfronttypes.DistributionConfig{
			CallerReference: aws.String(fmt.Sprintf("%d", time.Now().UnixNano())),
			Origins: &cloudfronttypes.Origins{
				Quantity: aws.Int32(1),
				Items: []cloudfronttypes.Origin{{
					Id:         aws.String(req.Config["origin_id"]),
					DomainName: aws.String(req.Config["origin_domain"]),
				}},
			},
			Enabled: aws.Bool(true),
		},
	}
	_, err := cfClient.CreateDistribution(ctx, input)
	return err
}

func createRoute53Zone(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	r53Client := route53.NewFromConfig(cfg)
	input := &route53.CreateHostedZoneInput{
		Name:            aws.String(req.Config["zone_name"]),
		CallerReference: aws.String(fmt.Sprintf("%d", time.Now().UnixNano())),
	}
	_, err := r53Client.CreateHostedZone(ctx, input)
	return err
}

func createALB(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	elbClient := elasticloadbalancingv2.NewFromConfig(cfg)
	input := &elasticloadbalancingv2.CreateLoadBalancerInput{
		Name:    aws.String(req.Config["name"]),
		Subnets: strings.Split(req.Config["subnet_ids"], ","),
		Type:    elbtypes.LoadBalancerTypeEnumApplication,
	}
	_, err := elbClient.CreateLoadBalancer(ctx, input)
	return err
}

func createElasticache(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	cacheClient := elasticache.NewFromConfig(cfg)
	input := &elasticache.CreateCacheClusterInput{
		CacheClusterId:            aws.String(req.Config["cluster_id"]),
		Engine:                    aws.String(req.Config["engine"]),
		NumCacheNodes:             aws.Int32(1),
		CacheNodeType:             aws.String(req.Config["node_type"]),
		PreferredAvailabilityZone: aws.String(req.Config["availability_zone"]),
	}
	_, err := cacheClient.CreateCacheCluster(ctx, input)
	return err
}

func createRedshift(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	redshiftClient := redshift.NewFromConfig(cfg)
	input := &redshift.CreateClusterInput{
		ClusterIdentifier:  aws.String(req.Config["cluster_identifier"]),
		NodeType:           aws.String(req.Config["node_type"]),
		MasterUsername:     aws.String(req.Config["master_username"]),
		MasterUserPassword: aws.String(req.Config["master_user_password"]),
		DBName:             aws.String(req.Config["db_name"]),
		ClusterType:        aws.String(req.Config["cluster_type"]),
	}
	_, err := redshiftClient.CreateCluster(ctx, input)
	return err
}

func createKinesis(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	kinesisClient := kinesis.NewFromConfig(cfg)
	input := &kinesis.CreateStreamInput{
		StreamName: aws.String(req.Config["stream_name"]),
		ShardCount: aws.Int32(1),
	}
	_, err := kinesisClient.CreateStream(ctx, input)
	return err
}

func createLogGroup(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	logsClient := cloudwatchlogs.NewFromConfig(cfg)
	input := &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(req.Config["log_group_name"]),
	}
	_, err := logsClient.CreateLogGroup(ctx, input)
	return err
}

func createSSMParameter(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	ssmClient := ssm.NewFromConfig(cfg)
	input := &ssm.PutParameterInput{
		Name:  aws.String(req.Config["name"]),
		Type:  ssmtypes.ParameterType(req.Config["type"]),
		Value: aws.String(req.Config["value"]),
	}
	_, err := ssmClient.PutParameter(ctx, input)
	return err
}

func createSecret(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	secretsClient := secretsmanager.NewFromConfig(cfg)
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(req.Config["name"]),
		SecretString: aws.String(req.Config["secret_string"]),
	}
	_, err := secretsClient.CreateSecret(ctx, input)
	return err
}

func createAutoScalingGroup(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	autoScalingClient := autoscaling.NewFromConfig(cfg)
	input := &autoscaling.CreateAutoScalingGroupInput{
		AutoScalingGroupName:    aws.String(req.Config["group_name"]),
		MinSize:                 aws.Int32(1),
		MaxSize:                 aws.Int32(3),
		VPCZoneIdentifier:       aws.String(req.Config["subnet_ids"]),
		LaunchConfigurationName: aws.String(req.Config["launch_config_name"]),
	}
	_, err := autoScalingClient.CreateAutoScalingGroup(ctx, input)
	return err
}

func createENI(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.CreateNetworkInterfaceInput{
		SubnetId: aws.String(req.Config["subnet_id"]),
	}
	_, err := ec2Client.CreateNetworkInterface(ctx, input)
	return err
}

func createEIP(ctx context.Context, cfg aws.Config) error {
	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.AllocateAddressInput{}
	_, err := ec2Client.AllocateAddress(ctx, input)
	return err
}

func createEFSMountTarget(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	efsClient := efs.NewFromConfig(cfg)
	input := &efs.CreateMountTargetInput{
		FileSystemId: aws.String(req.Config["file_system_id"]),
		SubnetId:     aws.String(req.Config["subnet_id"]),
	}
	_, err := efsClient.CreateMountTarget(ctx, input)
	return err
}

func createStepFunction(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	sfnClient := sfn.NewFromConfig(cfg)
	input := &sfn.CreateStateMachineInput{
		Name:       aws.String(req.Config["name"]),
		RoleArn:    aws.String(req.Config["role_arn"]),
		Definition: aws.String(req.Config["definition"]),
	}
	_, err := sfnClient.CreateStateMachine(ctx, input)
	return err
}

func createGlueJob(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	glueClient := glue.NewFromConfig(cfg)
	input := &glue.CreateJobInput{
		Name: aws.String(req.Config["name"]),
		Role: aws.String(req.Config["role_arn"]),
		Command: &gluetype.JobCommand{
			Name:           aws.String(req.Config["command_name"]),
			ScriptLocation: aws.String(req.Config["script_location"]),
		},
	}
	_, err := glueClient.CreateJob(ctx, input)
	return err
}

func createAthenaWorkgroup(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	athenaClient := athena.NewFromConfig(cfg)
	input := &athena.CreateWorkGroupInput{
		Name: aws.String(req.Config["name"]),
	}
	_, err := athenaClient.CreateWorkGroup(ctx, input)
	return err
}

func createS3BucketPolicy(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	s3Client := s3.NewFromConfig(cfg)
	input := &s3.PutBucketPolicyInput{
		Bucket: aws.String(req.Config["bucket_name"]),
		Policy: aws.String(req.Config["policy"]),
	}
	_, err := s3Client.PutBucketPolicy(ctx, input)
	return err
}

func createCloudTrail(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	cloudtrailClient := cloudtrail.NewFromConfig(cfg)
	input := &cloudtrail.CreateTrailInput{
		Name: aws.String(req.Config["name"]),
	}
	_, err := cloudtrailClient.CreateTrail(ctx, input)
	return err
}

func createCloudFormationStack(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	cloudformationClient := cloudformation.NewFromConfig(cfg)
	input := &cloudformation.CreateStackInput{
		StackName: aws.String(req.Config["name"]),
	}
	_, err := cloudformationClient.CreateStack(ctx, input)
	return err
}

func createCodeBuildProject(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	codebuildClient := codebuild.NewFromConfig(cfg)
	input := &codebuild.CreateProjectInput{
		Name: aws.String(req.Config["name"]),
	}
	_, err := codebuildClient.CreateProject(ctx, input)
	return err
}

func createCodePipeline(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	codepipelineClient := codepipeline.NewFromConfig(cfg)
	input := &codepipeline.CreatePipelineInput{
		Pipeline: &cpTypes.PipelineDeclaration{
			Name: aws.String(req.Config["name"]),
		},
	}
	_, err := codepipelineClient.CreatePipeline(ctx, input)
	return err
}

func createCodeDeploy(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	codedeployClient := codedeploy.NewFromConfig(cfg)
	input := &codedeploy.CreateApplicationInput{
		ApplicationName: aws.String(req.Config["name"]),
	}
	_, err := codedeployClient.CreateApplication(ctx, input)
	return err
}

func createElasticBeanstalk(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	beanstalkClient := elasticbeanstalk.NewFromConfig(cfg)
	input := &elasticbeanstalk.CreateApplicationInput{
		ApplicationName: aws.String(req.Config["name"]),
	}
	_, err := beanstalkClient.CreateApplication(ctx, input)
	return err
}

func createAppConfig(ctx context.Context, cfg aws.Config, req *provisioningtypes.ProvisionRequest) error {
	appconfigClient := appconfig.NewFromConfig(cfg)
	input := &appconfig.CreateApplicationInput{
		Name: aws.String(req.Config["name"]),
	}
	_, err := appconfigClient.CreateApplication(ctx, input)
	return err
}
