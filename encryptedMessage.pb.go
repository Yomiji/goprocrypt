// Code generated by protoc-gen-go. DO NOT EDIT.
// source: encryptedMessage.proto

package goprocrypt

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type EncryptedMessage struct {
	Signature            []byte   `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	Digest               []byte   `protobuf:"bytes,3,opt,name=digest,proto3" json:"digest,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EncryptedMessage) Reset()         { *m = EncryptedMessage{} }
func (m *EncryptedMessage) String() string { return proto.CompactTextString(m) }
func (*EncryptedMessage) ProtoMessage()    {}
func (*EncryptedMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_encryptedMessage_3a1c9b85b7feb154, []int{0}
}
func (m *EncryptedMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EncryptedMessage.Unmarshal(m, b)
}
func (m *EncryptedMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EncryptedMessage.Marshal(b, m, deterministic)
}
func (dst *EncryptedMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EncryptedMessage.Merge(dst, src)
}
func (m *EncryptedMessage) XXX_Size() int {
	return xxx_messageInfo_EncryptedMessage.Size(m)
}
func (m *EncryptedMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_EncryptedMessage.DiscardUnknown(m)
}

var xxx_messageInfo_EncryptedMessage proto.InternalMessageInfo

func (m *EncryptedMessage) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *EncryptedMessage) GetDigest() []byte {
	if m != nil {
		return m.Digest
	}
	return nil
}

func init() {
	proto.RegisterType((*EncryptedMessage)(nil), "goprocrypt.EncryptedMessage")
}

func init() {
	proto.RegisterFile("encryptedMessage.proto", fileDescriptor_encryptedMessage_3a1c9b85b7feb154)
}

var fileDescriptor_encryptedMessage_3a1c9b85b7feb154 = []byte{
	// 112 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x4b, 0xcd, 0x4b, 0x2e,
	0xaa, 0x2c, 0x28, 0x49, 0x4d, 0xf1, 0x4d, 0x2d, 0x2e, 0x4e, 0x4c, 0x4f, 0xd5, 0x2b, 0x28, 0xca,
	0x2f, 0xc9, 0x17, 0xe2, 0x4a, 0xcf, 0x2f, 0x28, 0xca, 0x07, 0x4b, 0x29, 0x79, 0x70, 0x09, 0xb8,
	0xa2, 0xa9, 0x12, 0x92, 0xe1, 0xe2, 0x2c, 0xce, 0x4c, 0xcf, 0x4b, 0x2c, 0x29, 0x2d, 0x4a, 0x95,
	0x60, 0x54, 0x60, 0xd4, 0xe0, 0x09, 0x42, 0x08, 0x08, 0x89, 0x71, 0xb1, 0xa5, 0x64, 0xa6, 0xa7,
	0x16, 0x97, 0x48, 0x30, 0x83, 0xa5, 0xa0, 0x3c, 0x27, 0x9e, 0x28, 0x24, 0x73, 0x93, 0xd8, 0xc0,
	0x56, 0x19, 0x03, 0x02, 0x00, 0x00, 0xff, 0xff, 0xb4, 0xf2, 0x41, 0x20, 0x84, 0x00, 0x00, 0x00,
}