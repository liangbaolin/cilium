// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/listener/v3/api_listener.proto

package envoy_config_listener_v3

import (
	fmt "fmt"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Describes a type of API listener, which is used in non-proxy clients. The type of API
// exposed to the non-proxy application depends on the type of API listener.
type ApiListener struct {
	// The type in this field determines the type of API listener. At present, the following
	// types are supported:
	// envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager (HTTP)
	// [#next-major-version: In the v3 API, replace this Any field with a oneof containing the
	// specific config message for each type of API listener. We could not do this in v2 because
	// it would have caused circular dependencies for go protos: lds.proto depends on this file,
	// and http_connection_manager.proto depends on rds.proto, which is in the same directory as
	// lds.proto, so lds.proto cannot depend on this file.]
	ApiListener          *any.Any `protobuf:"bytes,1,opt,name=api_listener,json=apiListener,proto3" json:"api_listener,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ApiListener) Reset()         { *m = ApiListener{} }
func (m *ApiListener) String() string { return proto.CompactTextString(m) }
func (*ApiListener) ProtoMessage()    {}
func (*ApiListener) Descriptor() ([]byte, []int) {
	return fileDescriptor_9fd48717df5cccf7, []int{0}
}

func (m *ApiListener) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ApiListener.Unmarshal(m, b)
}
func (m *ApiListener) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ApiListener.Marshal(b, m, deterministic)
}
func (m *ApiListener) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ApiListener.Merge(m, src)
}
func (m *ApiListener) XXX_Size() int {
	return xxx_messageInfo_ApiListener.Size(m)
}
func (m *ApiListener) XXX_DiscardUnknown() {
	xxx_messageInfo_ApiListener.DiscardUnknown(m)
}

var xxx_messageInfo_ApiListener proto.InternalMessageInfo

func (m *ApiListener) GetApiListener() *any.Any {
	if m != nil {
		return m.ApiListener
	}
	return nil
}

func init() {
	proto.RegisterType((*ApiListener)(nil), "envoy.config.listener.v3.ApiListener")
}

func init() {
	proto.RegisterFile("envoy/config/listener/v3/api_listener.proto", fileDescriptor_9fd48717df5cccf7)
}

var fileDescriptor_9fd48717df5cccf7 = []byte{
	// 213 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4e, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0xcf, 0xc9, 0x2c, 0x2e, 0x49, 0xcd, 0x4b,
	0x2d, 0xd2, 0x2f, 0x33, 0xd6, 0x4f, 0x2c, 0xc8, 0x8c, 0x87, 0xf1, 0xf5, 0x0a, 0x8a, 0xf2, 0x4b,
	0xf2, 0x85, 0x24, 0xc0, 0x8a, 0xf5, 0x20, 0x8a, 0xf5, 0xe0, 0x92, 0x65, 0xc6, 0x52, 0x92, 0xe9,
	0xf9, 0xf9, 0xe9, 0x39, 0xa9, 0xfa, 0x60, 0x75, 0x49, 0xa5, 0x69, 0xfa, 0x89, 0x79, 0x95, 0x10,
	0x4d, 0x52, 0x8a, 0xa5, 0x29, 0x05, 0x89, 0xfa, 0x89, 0x79, 0x79, 0xf9, 0x25, 0x89, 0x25, 0x99,
	0xf9, 0x79, 0xc5, 0xfa, 0x65, 0xa9, 0x45, 0xc5, 0x99, 0xf9, 0x79, 0x99, 0x79, 0xe9, 0x10, 0x25,
	0x4a, 0xc5, 0x5c, 0xdc, 0x8e, 0x05, 0x99, 0x3e, 0x50, 0xf3, 0x84, 0xcc, 0xb9, 0x78, 0x90, 0x2d,
	0x97, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x36, 0x12, 0xd1, 0x83, 0xd8, 0xa1, 0x07, 0xb3, 0x43, 0xcf,
	0x31, 0xaf, 0x32, 0x88, 0x3b, 0x11, 0xa1, 0xd1, 0x4a, 0x7b, 0xd6, 0xd1, 0x0e, 0x39, 0x35, 0x2e,
	0x15, 0x1c, 0xce, 0x34, 0xd2, 0x43, 0xb2, 0xc5, 0xc9, 0x86, 0x4b, 0x2d, 0x33, 0x5f, 0x0f, 0xac,
	0xb4, 0xa0, 0x28, 0xbf, 0xa2, 0x52, 0x0f, 0x97, 0xe7, 0x9c, 0x04, 0x90, 0xb4, 0x05, 0x80, 0x2c,
	0x0f, 0x60, 0x4c, 0x62, 0x03, 0xbb, 0xc2, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0x0b, 0xbf, 0xb0,
	0x01, 0x40, 0x01, 0x00, 0x00,
}
