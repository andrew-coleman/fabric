// Copyright the Hyperledger Fabric contributors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.3
// source: msp/msp_principal.proto

package msp

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type MSPPrincipal_Classification int32

const (
	MSPPrincipal_ROLE MSPPrincipal_Classification = 0 // Represents the one of the dedicated MSP roles, the
	// one of a member of MSP network, and the one of an
	// administrator of an MSP network
	MSPPrincipal_ORGANIZATION_UNIT MSPPrincipal_Classification = 1 // Denotes a finer grained (affiliation-based)
	// groupping of entities, per MSP affiliation
	// E.g., this can well be represented by an MSP's
	// Organization unit
	MSPPrincipal_IDENTITY MSPPrincipal_Classification = 2 // Denotes a principal that consists of a single
	// identity
	MSPPrincipal_ANONYMITY MSPPrincipal_Classification = 3 // Denotes a principal that can be used to enforce
	// an identity to be anonymous or nominal.
	MSPPrincipal_COMBINED MSPPrincipal_Classification = 4 // Denotes a combined principal
)

// Enum value maps for MSPPrincipal_Classification.
var (
	MSPPrincipal_Classification_name = map[int32]string{
		0: "ROLE",
		1: "ORGANIZATION_UNIT",
		2: "IDENTITY",
		3: "ANONYMITY",
		4: "COMBINED",
	}
	MSPPrincipal_Classification_value = map[string]int32{
		"ROLE":              0,
		"ORGANIZATION_UNIT": 1,
		"IDENTITY":          2,
		"ANONYMITY":         3,
		"COMBINED":          4,
	}
)

func (x MSPPrincipal_Classification) Enum() *MSPPrincipal_Classification {
	p := new(MSPPrincipal_Classification)
	*p = x
	return p
}

func (x MSPPrincipal_Classification) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MSPPrincipal_Classification) Descriptor() protoreflect.EnumDescriptor {
	return file_msp_msp_principal_proto_enumTypes[0].Descriptor()
}

func (MSPPrincipal_Classification) Type() protoreflect.EnumType {
	return &file_msp_msp_principal_proto_enumTypes[0]
}

func (x MSPPrincipal_Classification) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MSPPrincipal_Classification.Descriptor instead.
func (MSPPrincipal_Classification) EnumDescriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{0, 0}
}

type MSPRole_MSPRoleType int32

const (
	MSPRole_MEMBER  MSPRole_MSPRoleType = 0 // Represents an MSP Member
	MSPRole_ADMIN   MSPRole_MSPRoleType = 1 // Represents an MSP Admin
	MSPRole_CLIENT  MSPRole_MSPRoleType = 2 // Represents an MSP Client
	MSPRole_PEER    MSPRole_MSPRoleType = 3 // Represents an MSP Peer
	MSPRole_ORDERER MSPRole_MSPRoleType = 4 // Represents an MSP Orderer
)

// Enum value maps for MSPRole_MSPRoleType.
var (
	MSPRole_MSPRoleType_name = map[int32]string{
		0: "MEMBER",
		1: "ADMIN",
		2: "CLIENT",
		3: "PEER",
		4: "ORDERER",
	}
	MSPRole_MSPRoleType_value = map[string]int32{
		"MEMBER":  0,
		"ADMIN":   1,
		"CLIENT":  2,
		"PEER":    3,
		"ORDERER": 4,
	}
)

func (x MSPRole_MSPRoleType) Enum() *MSPRole_MSPRoleType {
	p := new(MSPRole_MSPRoleType)
	*p = x
	return p
}

func (x MSPRole_MSPRoleType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MSPRole_MSPRoleType) Descriptor() protoreflect.EnumDescriptor {
	return file_msp_msp_principal_proto_enumTypes[1].Descriptor()
}

func (MSPRole_MSPRoleType) Type() protoreflect.EnumType {
	return &file_msp_msp_principal_proto_enumTypes[1]
}

func (x MSPRole_MSPRoleType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MSPRole_MSPRoleType.Descriptor instead.
func (MSPRole_MSPRoleType) EnumDescriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{2, 0}
}

type MSPIdentityAnonymity_MSPIdentityAnonymityType int32

const (
	MSPIdentityAnonymity_NOMINAL   MSPIdentityAnonymity_MSPIdentityAnonymityType = 0 // Represents a nominal MSP Identity
	MSPIdentityAnonymity_ANONYMOUS MSPIdentityAnonymity_MSPIdentityAnonymityType = 1 // Represents an anonymous MSP Identity
)

// Enum value maps for MSPIdentityAnonymity_MSPIdentityAnonymityType.
var (
	MSPIdentityAnonymity_MSPIdentityAnonymityType_name = map[int32]string{
		0: "NOMINAL",
		1: "ANONYMOUS",
	}
	MSPIdentityAnonymity_MSPIdentityAnonymityType_value = map[string]int32{
		"NOMINAL":   0,
		"ANONYMOUS": 1,
	}
)

func (x MSPIdentityAnonymity_MSPIdentityAnonymityType) Enum() *MSPIdentityAnonymity_MSPIdentityAnonymityType {
	p := new(MSPIdentityAnonymity_MSPIdentityAnonymityType)
	*p = x
	return p
}

func (x MSPIdentityAnonymity_MSPIdentityAnonymityType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MSPIdentityAnonymity_MSPIdentityAnonymityType) Descriptor() protoreflect.EnumDescriptor {
	return file_msp_msp_principal_proto_enumTypes[2].Descriptor()
}

func (MSPIdentityAnonymity_MSPIdentityAnonymityType) Type() protoreflect.EnumType {
	return &file_msp_msp_principal_proto_enumTypes[2]
}

func (x MSPIdentityAnonymity_MSPIdentityAnonymityType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MSPIdentityAnonymity_MSPIdentityAnonymityType.Descriptor instead.
func (MSPIdentityAnonymity_MSPIdentityAnonymityType) EnumDescriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{3, 0}
}

// MSPPrincipal aims to represent an MSP-centric set of identities.
// In particular, this structure allows for definition of
//  - a group of identities that are member of the same MSP
//  - a group of identities that are member of the same organization unit
//    in the same MSP
//  - a group of identities that are administering a specific MSP
//  - a specific identity
// Expressing these groups is done given two fields of the fields below
//  - Classification, that defines the type of classification of identities
//    in an MSP this principal would be defined on; Classification can take
//    three values:
//     (i)  ByMSPRole: that represents a classification of identities within
//          MSP based on one of the two pre-defined MSP rules, "member" and "admin"
//     (ii) ByOrganizationUnit: that represents a classification of identities
//          within MSP based on the organization unit an identity belongs to
//     (iii)ByIdentity that denotes that MSPPrincipal is mapped to a single
//          identity/certificate; this would mean that the Principal bytes
//          message
type MSPPrincipal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Classification describes the way that one should process
	// Principal. An Classification value of "ByOrganizationUnit" reflects
	// that "Principal" contains the name of an organization this MSP
	// handles. A Classification value "ByIdentity" means that
	// "Principal" contains a specific identity. Default value
	// denotes that Principal contains one of the groups by
	// default supported by all MSPs ("admin" or "member").
	PrincipalClassification MSPPrincipal_Classification `protobuf:"varint,1,opt,name=principal_classification,json=principalClassification,proto3,enum=common.MSPPrincipal_Classification" json:"principal_classification,omitempty"`
	// Principal completes the policy principal definition. For the default
	// principal types, Principal can be either "Admin" or "Member".
	// For the ByOrganizationUnit/ByIdentity values of Classification,
	// PolicyPrincipal acquires its value from an organization unit or
	// identity, respectively.
	// For the Combined Classification type, the Principal is a marshalled
	// CombinedPrincipal.
	Principal []byte `protobuf:"bytes,2,opt,name=principal,proto3" json:"principal,omitempty"`
}

func (x *MSPPrincipal) Reset() {
	*x = MSPPrincipal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msp_msp_principal_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MSPPrincipal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MSPPrincipal) ProtoMessage() {}

func (x *MSPPrincipal) ProtoReflect() protoreflect.Message {
	mi := &file_msp_msp_principal_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MSPPrincipal.ProtoReflect.Descriptor instead.
func (*MSPPrincipal) Descriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{0}
}

func (x *MSPPrincipal) GetPrincipalClassification() MSPPrincipal_Classification {
	if x != nil {
		return x.PrincipalClassification
	}
	return MSPPrincipal_ROLE
}

func (x *MSPPrincipal) GetPrincipal() []byte {
	if x != nil {
		return x.Principal
	}
	return nil
}

// OrganizationUnit governs the organization of the Principal
// field of a policy principal when a specific organization unity members
// are to be defined within a policy principal.
type OrganizationUnit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// MSPIdentifier represents the identifier of the MSP this organization unit
	// refers to
	MspIdentifier string `protobuf:"bytes,1,opt,name=msp_identifier,json=mspIdentifier,proto3" json:"msp_identifier,omitempty"`
	// OrganizationUnitIdentifier defines the organizational unit under the
	// MSP identified with MSPIdentifier
	OrganizationalUnitIdentifier string `protobuf:"bytes,2,opt,name=organizational_unit_identifier,json=organizationalUnitIdentifier,proto3" json:"organizational_unit_identifier,omitempty"`
	// CertifiersIdentifier is the hash of certificates chain of trust
	// related to this organizational unit
	CertifiersIdentifier []byte `protobuf:"bytes,3,opt,name=certifiers_identifier,json=certifiersIdentifier,proto3" json:"certifiers_identifier,omitempty"`
}

func (x *OrganizationUnit) Reset() {
	*x = OrganizationUnit{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msp_msp_principal_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OrganizationUnit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OrganizationUnit) ProtoMessage() {}

func (x *OrganizationUnit) ProtoReflect() protoreflect.Message {
	mi := &file_msp_msp_principal_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OrganizationUnit.ProtoReflect.Descriptor instead.
func (*OrganizationUnit) Descriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{1}
}

func (x *OrganizationUnit) GetMspIdentifier() string {
	if x != nil {
		return x.MspIdentifier
	}
	return ""
}

func (x *OrganizationUnit) GetOrganizationalUnitIdentifier() string {
	if x != nil {
		return x.OrganizationalUnitIdentifier
	}
	return ""
}

func (x *OrganizationUnit) GetCertifiersIdentifier() []byte {
	if x != nil {
		return x.CertifiersIdentifier
	}
	return nil
}

// MSPRole governs the organization of the Principal
// field of an MSPPrincipal when it aims to define one of the
// two dedicated roles within an MSP: Admin and Members.
type MSPRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// MSPIdentifier represents the identifier of the MSP this principal
	// refers to
	MspIdentifier string `protobuf:"bytes,1,opt,name=msp_identifier,json=mspIdentifier,proto3" json:"msp_identifier,omitempty"`
	// MSPRoleType defines which of the available, pre-defined MSP-roles
	// an identiy should posess inside the MSP with identifier MSPidentifier
	Role MSPRole_MSPRoleType `protobuf:"varint,2,opt,name=role,proto3,enum=common.MSPRole_MSPRoleType" json:"role,omitempty"`
}

func (x *MSPRole) Reset() {
	*x = MSPRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msp_msp_principal_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MSPRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MSPRole) ProtoMessage() {}

func (x *MSPRole) ProtoReflect() protoreflect.Message {
	mi := &file_msp_msp_principal_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MSPRole.ProtoReflect.Descriptor instead.
func (*MSPRole) Descriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{2}
}

func (x *MSPRole) GetMspIdentifier() string {
	if x != nil {
		return x.MspIdentifier
	}
	return ""
}

func (x *MSPRole) GetRole() MSPRole_MSPRoleType {
	if x != nil {
		return x.Role
	}
	return MSPRole_MEMBER
}

// MSPIdentityAnonymity can be used to enforce an identity to be anonymous or nominal.
type MSPIdentityAnonymity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AnonymityType MSPIdentityAnonymity_MSPIdentityAnonymityType `protobuf:"varint,1,opt,name=anonymity_type,json=anonymityType,proto3,enum=common.MSPIdentityAnonymity_MSPIdentityAnonymityType" json:"anonymity_type,omitempty"`
}

func (x *MSPIdentityAnonymity) Reset() {
	*x = MSPIdentityAnonymity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msp_msp_principal_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MSPIdentityAnonymity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MSPIdentityAnonymity) ProtoMessage() {}

func (x *MSPIdentityAnonymity) ProtoReflect() protoreflect.Message {
	mi := &file_msp_msp_principal_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MSPIdentityAnonymity.ProtoReflect.Descriptor instead.
func (*MSPIdentityAnonymity) Descriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{3}
}

func (x *MSPIdentityAnonymity) GetAnonymityType() MSPIdentityAnonymity_MSPIdentityAnonymityType {
	if x != nil {
		return x.AnonymityType
	}
	return MSPIdentityAnonymity_NOMINAL
}

// CombinedPrincipal governs the organization of the Principal
// field of a policy principal when principal_classification has
// indicated that a combined form of principals is required
type CombinedPrincipal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Principals refer to combined principals
	Principals []*MSPPrincipal `protobuf:"bytes,1,rep,name=principals,proto3" json:"principals,omitempty"`
}

func (x *CombinedPrincipal) Reset() {
	*x = CombinedPrincipal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msp_msp_principal_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CombinedPrincipal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CombinedPrincipal) ProtoMessage() {}

func (x *CombinedPrincipal) ProtoReflect() protoreflect.Message {
	mi := &file_msp_msp_principal_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CombinedPrincipal.ProtoReflect.Descriptor instead.
func (*CombinedPrincipal) Descriptor() ([]byte, []int) {
	return file_msp_msp_principal_proto_rawDescGZIP(), []int{4}
}

func (x *CombinedPrincipal) GetPrincipals() []*MSPPrincipal {
	if x != nil {
		return x.Principals
	}
	return nil
}

var File_msp_msp_principal_proto protoreflect.FileDescriptor

var file_msp_msp_principal_proto_rawDesc = []byte{
	0x0a, 0x17, 0x6d, 0x73, 0x70, 0x2f, 0x6d, 0x73, 0x70, 0x5f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69,
	0x70, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x22, 0xea, 0x01, 0x0a, 0x0c, 0x4d, 0x53, 0x50, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70,
	0x61, 0x6c, 0x12, 0x5e, 0x0a, 0x18, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f,
	0x63, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4d, 0x53,
	0x50, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x43, 0x6c, 0x61, 0x73, 0x73,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x17, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x22, 0x5c, 0x0a, 0x0e, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x08, 0x0a, 0x04, 0x52, 0x4f, 0x4c, 0x45, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11,
	0x4f, 0x52, 0x47, 0x41, 0x4e, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x49,
	0x54, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x49, 0x44, 0x45, 0x4e, 0x54, 0x49, 0x54, 0x59, 0x10,
	0x02, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x4e, 0x4f, 0x4e, 0x59, 0x4d, 0x49, 0x54, 0x59, 0x10, 0x03,
	0x12, 0x0c, 0x0a, 0x08, 0x43, 0x4f, 0x4d, 0x42, 0x49, 0x4e, 0x45, 0x44, 0x10, 0x04, 0x22, 0xb4,
	0x01, 0x0a, 0x10, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x55,
	0x6e, 0x69, 0x74, 0x12, 0x25, 0x0a, 0x0e, 0x6d, 0x73, 0x70, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6d, 0x73, 0x70,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x44, 0x0a, 0x1e, 0x6f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x75, 0x6e, 0x69,
	0x74, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x1c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x55, 0x6e, 0x69, 0x74, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72,
	0x12, 0x33, 0x0a, 0x15, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x73, 0x5f, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x14, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x73, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x66, 0x69, 0x65, 0x72, 0x22, 0xaa, 0x01, 0x0a, 0x07, 0x4d, 0x53, 0x50, 0x52, 0x6f, 0x6c,
	0x65, 0x12, 0x25, 0x0a, 0x0e, 0x6d, 0x73, 0x70, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6d, 0x73, 0x70, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x2f, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x4d, 0x53, 0x50, 0x52, 0x6f, 0x6c, 0x65, 0x2e, 0x4d, 0x53, 0x50, 0x52, 0x6f, 0x6c, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x22, 0x47, 0x0a, 0x0b, 0x4d, 0x53, 0x50,
	0x52, 0x6f, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x4d, 0x45, 0x4d, 0x42,
	0x45, 0x52, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x41, 0x44, 0x4d, 0x49, 0x4e, 0x10, 0x01, 0x12,
	0x0a, 0x0a, 0x06, 0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x50,
	0x45, 0x45, 0x52, 0x10, 0x03, 0x12, 0x0b, 0x0a, 0x07, 0x4f, 0x52, 0x44, 0x45, 0x52, 0x45, 0x52,
	0x10, 0x04, 0x22, 0xac, 0x01, 0x0a, 0x14, 0x4d, 0x53, 0x50, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x69, 0x74, 0x79, 0x12, 0x5c, 0x0a, 0x0e, 0x61,
	0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x69, 0x74, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4d, 0x53, 0x50,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x69, 0x74,
	0x79, 0x2e, 0x4d, 0x53, 0x50, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x41, 0x6e, 0x6f,
	0x6e, 0x79, 0x6d, 0x69, 0x74, 0x79, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0d, 0x61, 0x6e, 0x6f, 0x6e,
	0x79, 0x6d, 0x69, 0x74, 0x79, 0x54, 0x79, 0x70, 0x65, 0x22, 0x36, 0x0a, 0x18, 0x4d, 0x53, 0x50,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x69, 0x74,
	0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x4e, 0x4f, 0x4d, 0x49, 0x4e, 0x41, 0x4c,
	0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x4e, 0x4f, 0x4e, 0x59, 0x4d, 0x4f, 0x55, 0x53, 0x10,
	0x01, 0x22, 0x49, 0x0a, 0x11, 0x43, 0x6f, 0x6d, 0x62, 0x69, 0x6e, 0x65, 0x64, 0x50, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x12, 0x34, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69,
	0x70, 0x61, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x4d, 0x53, 0x50, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x52, 0x0a, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x73, 0x42, 0x53, 0x0a, 0x24,
	0x6f, 0x72, 0x67, 0x2e, 0x68, 0x79, 0x70, 0x65, 0x72, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e,
	0x66, 0x61, 0x62, 0x72, 0x69, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x68, 0x79, 0x70, 0x65, 0x72, 0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2f, 0x66, 0x61, 0x62,
	0x72, 0x69, 0x63, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2d, 0x67, 0x6f, 0x2f, 0x6d, 0x73,
	0x70, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_msp_msp_principal_proto_rawDescOnce sync.Once
	file_msp_msp_principal_proto_rawDescData = file_msp_msp_principal_proto_rawDesc
)

func file_msp_msp_principal_proto_rawDescGZIP() []byte {
	file_msp_msp_principal_proto_rawDescOnce.Do(func() {
		file_msp_msp_principal_proto_rawDescData = protoimpl.X.CompressGZIP(file_msp_msp_principal_proto_rawDescData)
	})
	return file_msp_msp_principal_proto_rawDescData
}

var file_msp_msp_principal_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_msp_msp_principal_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_msp_msp_principal_proto_goTypes = []interface{}{
	(MSPPrincipal_Classification)(0),                   // 0: common.MSPPrincipal.Classification
	(MSPRole_MSPRoleType)(0),                           // 1: common.MSPRole.MSPRoleType
	(MSPIdentityAnonymity_MSPIdentityAnonymityType)(0), // 2: common.MSPIdentityAnonymity.MSPIdentityAnonymityType
	(*MSPPrincipal)(nil),                               // 3: common.MSPPrincipal
	(*OrganizationUnit)(nil),                           // 4: common.OrganizationUnit
	(*MSPRole)(nil),                                    // 5: common.MSPRole
	(*MSPIdentityAnonymity)(nil),                       // 6: common.MSPIdentityAnonymity
	(*CombinedPrincipal)(nil),                          // 7: common.CombinedPrincipal
}
var file_msp_msp_principal_proto_depIdxs = []int32{
	0, // 0: common.MSPPrincipal.principal_classification:type_name -> common.MSPPrincipal.Classification
	1, // 1: common.MSPRole.role:type_name -> common.MSPRole.MSPRoleType
	2, // 2: common.MSPIdentityAnonymity.anonymity_type:type_name -> common.MSPIdentityAnonymity.MSPIdentityAnonymityType
	3, // 3: common.CombinedPrincipal.principals:type_name -> common.MSPPrincipal
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_msp_msp_principal_proto_init() }
func file_msp_msp_principal_proto_init() {
	if File_msp_msp_principal_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_msp_msp_principal_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MSPPrincipal); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msp_msp_principal_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OrganizationUnit); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msp_msp_principal_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MSPRole); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msp_msp_principal_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MSPIdentityAnonymity); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msp_msp_principal_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CombinedPrincipal); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_msp_msp_principal_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_msp_msp_principal_proto_goTypes,
		DependencyIndexes: file_msp_msp_principal_proto_depIdxs,
		EnumInfos:         file_msp_msp_principal_proto_enumTypes,
		MessageInfos:      file_msp_msp_principal_proto_msgTypes,
	}.Build()
	File_msp_msp_principal_proto = out.File
	file_msp_msp_principal_proto_rawDesc = nil
	file_msp_msp_principal_proto_goTypes = nil
	file_msp_msp_principal_proto_depIdxs = nil
}
