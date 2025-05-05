package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// CreateENI provisions a new Elastic Network Interface (ENI) in a VPC subnet.
func (s *EC2Service) CreateENI(ctx context.Context, subnetID string, desc string, sgIDs []string, tags map[string]string) (*ec2types.NetworkInterface, error) {
	input := &ec2.CreateNetworkInterfaceInput{
		SubnetId: aws.String(subnetID),
	}
	if desc != "" {
		input.Description = aws.String(desc)
	}
	if len(sgIDs) > 0 {
		input.Groups = sgIDs
	}
	if len(tags) > 0 {
		tagsList := make([]ec2types.Tag, 0, len(tags))
		for k, v := range tags {
			tagsList = append(tagsList, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		input.TagSpecifications = []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeNetworkInterface,
			Tags:         tagsList,
		}}
	}
	output, err := s.client.CreateNetworkInterface(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create ENI: %w", err)
	}
	return output.NetworkInterface, nil
}

// AttachENI attaches an ENI to an EC2 instance.
func (s *EC2Service) AttachENI(ctx context.Context, eniID, instanceID string, deviceIndex int32) (string, error) {
	input := &ec2.AttachNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(eniID),
		InstanceId:         aws.String(instanceID),
		DeviceIndex:        aws.Int32(deviceIndex),
	}
	output, err := s.client.AttachNetworkInterface(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to attach ENI: %w", err)
	}
	return aws.ToString(output.AttachmentId), nil
}

// DetachENI detaches an ENI from an EC2 instance.
func (s *EC2Service) DetachENI(ctx context.Context, attachmentID string, force bool) error {
	input := &ec2.DetachNetworkInterfaceInput{
		AttachmentId: aws.String(attachmentID),
		Force:        aws.Bool(force),
	}
	_, err := s.client.DetachNetworkInterface(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to detach ENI: %w", err)
	}
	return nil
}

// DeleteENI deletes an ENI by its ID.
func (s *EC2Service) DeleteENI(ctx context.Context, eniID string) error {
	input := &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(eniID),
	}
	_, err := s.client.DeleteNetworkInterface(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete ENI: %w", err)
	}
	return nil
}

// DescribeENIs lists ENIs matching filters (empty for all in VPC/account).
func (s *EC2Service) DescribeENIs(ctx context.Context, filters []ec2types.Filter) ([]ec2types.NetworkInterface, error) {
	input := &ec2.DescribeNetworkInterfacesInput{}
	if len(filters) > 0 {
		input.Filters = filters
	}
	output, err := s.client.DescribeNetworkInterfaces(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe ENIs: %w", err)
	}
	return output.NetworkInterfaces, nil
}
