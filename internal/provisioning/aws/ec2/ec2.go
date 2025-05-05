package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2Service provides modular, production-grade EC2 resource management for SaaS infra.
type EC2Service struct {
	client *ec2.Client
}

func NewEC2Service(cfg aws.Config) *EC2Service {
	return &EC2Service{client: ec2.NewFromConfig(cfg)}
}

// CreateInstance provisions a new EC2 instance with advanced options.
func (s *EC2Service) CreateInstance(ctx context.Context, params *CreateInstanceParams) (*ec2types.Instance, error) {
	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(params.AMI),
		InstanceType: ec2types.InstanceType(params.InstanceType),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
	}
	if params.KeyName != "" {
		input.KeyName = aws.String(params.KeyName)
	}
	if params.UserData != "" {
		input.UserData = aws.String(params.UserData)
	}
	if len(params.SecurityGroupIDs) > 0 {
		input.SecurityGroupIds = params.SecurityGroupIDs
	}
	if params.SubnetID != "" {
		input.SubnetId = aws.String(params.SubnetID)
	}
	if len(params.BlockDeviceMappings) > 0 {
		input.BlockDeviceMappings = params.BlockDeviceMappings
	}
	if len(params.Tags) > 0 {
		tags := make([]ec2types.Tag, 0, len(params.Tags))
		for k, v := range params.Tags {
			tags = append(tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		input.TagSpecifications = []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags:         tags,
		}}
	}
	output, err := s.client.RunInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC2 instance: %w", err)
	}
	if len(output.Instances) == 0 {
		return nil, fmt.Errorf("no instance returned by AWS")
	}
	return &output.Instances[0], nil
}

// CreateVolume provisions a new EBS volume.
func (s *EC2Service) CreateVolume(ctx context.Context, params *CreateVolumeParams) (*ec2.CreateVolumeOutput, error) {
	input := &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(params.AvailabilityZone),
		Size:             aws.Int32(params.SizeGiB),
		VolumeType:       ec2types.VolumeType(params.VolumeType),
	}
	if params.Encrypted {
		input.Encrypted = aws.Bool(true)
	}
	if params.KmsKeyID != "" {
		input.KmsKeyId = aws.String(params.KmsKeyID)
	}
	output, err := s.client.CreateVolume(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create EBS volume: %w", err)
	}
	return output, nil
}

// Add more EC2 resource methods here (Snapshot, ENI, EIP, NAT Gateway, IGW, Route Table, etc)

// --- Types ---
type CreateInstanceParams struct {
	AMI                 string
	InstanceType        string
	KeyName             string
	UserData            string
	SubnetID            string
	SecurityGroupIDs    []string
	BlockDeviceMappings []ec2types.BlockDeviceMapping
	Tags                map[string]string
}

type CreateVolumeParams struct {
	AvailabilityZone string
	SizeGiB          int32
	VolumeType       string
	Encrypted        bool
	KmsKeyID         string
}
