// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/metrics/v3/metrics_service.proto

package envoy_config_metrics_v3

import (
	fmt "fmt"
	v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
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

// Metrics Service is configured as a built-in *envoy.stat_sinks.metrics_service* :ref:`StatsSink
// <envoy_api_msg_config.metrics.v3.StatsSink>`. This opaque configuration will be used to create
// Metrics Service.
// [#extension: envoy.stat_sinks.metrics_service]
type MetricsServiceConfig struct {
	// The upstream gRPC cluster that hosts the metrics service.
	GrpcService          *v3.GrpcService `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService,proto3" json:"grpc_service,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *MetricsServiceConfig) Reset()         { *m = MetricsServiceConfig{} }
func (m *MetricsServiceConfig) String() string { return proto.CompactTextString(m) }
func (*MetricsServiceConfig) ProtoMessage()    {}
func (*MetricsServiceConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_10f80b3d56cf3c1b, []int{0}
}

func (m *MetricsServiceConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MetricsServiceConfig.Unmarshal(m, b)
}
func (m *MetricsServiceConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MetricsServiceConfig.Marshal(b, m, deterministic)
}
func (m *MetricsServiceConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MetricsServiceConfig.Merge(m, src)
}
func (m *MetricsServiceConfig) XXX_Size() int {
	return xxx_messageInfo_MetricsServiceConfig.Size(m)
}
func (m *MetricsServiceConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_MetricsServiceConfig.DiscardUnknown(m)
}

var xxx_messageInfo_MetricsServiceConfig proto.InternalMessageInfo

func (m *MetricsServiceConfig) GetGrpcService() *v3.GrpcService {
	if m != nil {
		return m.GrpcService
	}
	return nil
}

func init() {
	proto.RegisterType((*MetricsServiceConfig)(nil), "envoy.config.metrics.v3.MetricsServiceConfig")
}

func init() {
	proto.RegisterFile("envoy/config/metrics/v3/metrics_service.proto", fileDescriptor_10f80b3d56cf3c1b)
}

var fileDescriptor_10f80b3d56cf3c1b = []byte{
	// 266 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4d, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0xcf, 0x4d, 0x2d, 0x29, 0xca, 0x4c, 0x2e,
	0xd6, 0x2f, 0x33, 0x86, 0x31, 0xe3, 0x8b, 0x53, 0x8b, 0xca, 0x32, 0x93, 0x53, 0xf5, 0x0a, 0x8a,
	0xf2, 0x4b, 0xf2, 0x85, 0xc4, 0xc1, 0xca, 0xf5, 0x20, 0xca, 0xf5, 0xa0, 0x6a, 0xf4, 0xca, 0x8c,
	0xa5, 0xd4, 0x51, 0xcc, 0x49, 0xce, 0x2f, 0x4a, 0x05, 0x19, 0x92, 0x5e, 0x54, 0x90, 0x8c, 0x6a,
	0x82, 0x94, 0x6c, 0x69, 0x4a, 0x41, 0xa2, 0x7e, 0x62, 0x5e, 0x5e, 0x7e, 0x49, 0x62, 0x49, 0x66,
	0x7e, 0x5e, 0xb1, 0x7e, 0x71, 0x49, 0x62, 0x49, 0x69, 0x31, 0x54, 0x5a, 0x11, 0x43, 0xba, 0x2c,
	0xb5, 0xa8, 0x38, 0x33, 0x3f, 0x2f, 0x33, 0x2f, 0x1d, 0xaa, 0x44, 0xbc, 0x2c, 0x31, 0x27, 0x33,
	0x25, 0xb1, 0x24, 0x55, 0x1f, 0xc6, 0x80, 0x48, 0x28, 0xcd, 0x66, 0xe4, 0x12, 0xf1, 0x85, 0x38,
	0x29, 0x18, 0x62, 0xa7, 0x33, 0xd8, 0x39, 0x42, 0x7e, 0x5c, 0x3c, 0xc8, 0x2e, 0x91, 0x60, 0x54,
	0x60, 0xd4, 0xe0, 0x36, 0x52, 0xd4, 0x43, 0xf1, 0x0c, 0xc8, 0xcd, 0x7a, 0x65, 0xc6, 0x7a, 0xee,
	0x45, 0x05, 0xc9, 0x50, 0xed, 0x4e, 0x1c, 0xbf, 0x9c, 0x58, 0xbb, 0x18, 0x99, 0x04, 0x18, 0x83,
	0xb8, 0xd3, 0x11, 0xc2, 0x56, 0xc6, 0xb3, 0x8e, 0x76, 0xc8, 0xe9, 0x71, 0xe9, 0x60, 0x0f, 0x0c,
	0x23, 0x3d, 0x6c, 0x8e, 0x70, 0x72, 0xdb, 0xd5, 0x70, 0xe2, 0x22, 0x1b, 0x93, 0x00, 0x13, 0x97,
	0x6a, 0x66, 0x3e, 0xc4, 0xea, 0x82, 0xa2, 0xfc, 0x8a, 0x4a, 0x3d, 0x1c, 0x41, 0xea, 0x24, 0x8c,
	0x6a, 0x4c, 0x00, 0xc8, 0x8f, 0x01, 0x8c, 0x49, 0x6c, 0x60, 0xcf, 0x1a, 0x03, 0x02, 0x00, 0x00,
	0xff, 0xff, 0x4b, 0xa8, 0xd4, 0xd2, 0xba, 0x01, 0x00, 0x00,
}
