// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: api/wallet/v1/wallet.proto

package v1

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type Transfer2WalletAddressRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 用户id
	UserId uint64 `protobuf:"varint,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	// 金额
	Amount float32 `protobuf:"fixed32,2,opt,name=amount,proto3" json:"amount,omitempty"`
	// 目标钱包地址
	ReceiverWalletAddress string `protobuf:"bytes,3,opt,name=receiver_wallet_address,json=receiverWalletAddress,proto3" json:"receiver_wallet_address,omitempty"`
}

func (x *Transfer2WalletAddressRequest) Reset() {
	*x = Transfer2WalletAddressRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Transfer2WalletAddressRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Transfer2WalletAddressRequest) ProtoMessage() {}

func (x *Transfer2WalletAddressRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Transfer2WalletAddressRequest.ProtoReflect.Descriptor instead.
func (*Transfer2WalletAddressRequest) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{0}
}

func (x *Transfer2WalletAddressRequest) GetUserId() uint64 {
	if x != nil {
		return x.UserId
	}
	return 0
}

func (x *Transfer2WalletAddressRequest) GetAmount() float32 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *Transfer2WalletAddressRequest) GetReceiverWalletAddress() string {
	if x != nil {
		return x.ReceiverWalletAddress
	}
	return ""
}

type Transfer2WalletAddressResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 交易签名
	TransactionSignature string `protobuf:"bytes,1,opt,name=transaction_signature,json=transactionSignature,proto3" json:"transaction_signature,omitempty"`
}

func (x *Transfer2WalletAddressResponse) Reset() {
	*x = Transfer2WalletAddressResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Transfer2WalletAddressResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Transfer2WalletAddressResponse) ProtoMessage() {}

func (x *Transfer2WalletAddressResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Transfer2WalletAddressResponse.ProtoReflect.Descriptor instead.
func (*Transfer2WalletAddressResponse) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{1}
}

func (x *Transfer2WalletAddressResponse) GetTransactionSignature() string {
	if x != nil {
		return x.TransactionSignature
	}
	return ""
}

type GetWalletAddressByUserIdRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 用户id
	UserId uint64 `protobuf:"varint,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
}

func (x *GetWalletAddressByUserIdRequest) Reset() {
	*x = GetWalletAddressByUserIdRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetWalletAddressByUserIdRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetWalletAddressByUserIdRequest) ProtoMessage() {}

func (x *GetWalletAddressByUserIdRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetWalletAddressByUserIdRequest.ProtoReflect.Descriptor instead.
func (*GetWalletAddressByUserIdRequest) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{2}
}

func (x *GetWalletAddressByUserIdRequest) GetUserId() uint64 {
	if x != nil {
		return x.UserId
	}
	return 0
}

type GetWalletAddressByUserIdResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 钱包地址
	WalletAddress string `protobuf:"bytes,1,opt,name=wallet_address,json=walletAddress,proto3" json:"wallet_address,omitempty"`
}

func (x *GetWalletAddressByUserIdResponse) Reset() {
	*x = GetWalletAddressByUserIdResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetWalletAddressByUserIdResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetWalletAddressByUserIdResponse) ProtoMessage() {}

func (x *GetWalletAddressByUserIdResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetWalletAddressByUserIdResponse.ProtoReflect.Descriptor instead.
func (*GetWalletAddressByUserIdResponse) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{3}
}

func (x *GetWalletAddressByUserIdResponse) GetWalletAddress() string {
	if x != nil {
		return x.WalletAddress
	}
	return ""
}

type CreateWalletByMnemonicRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 助词
	Mnemonic []string `protobuf:"bytes,1,rep,name=mnemonic,proto3" json:"mnemonic,omitempty"`
}

func (x *CreateWalletByMnemonicRequest) Reset() {
	*x = CreateWalletByMnemonicRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateWalletByMnemonicRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateWalletByMnemonicRequest) ProtoMessage() {}

func (x *CreateWalletByMnemonicRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateWalletByMnemonicRequest.ProtoReflect.Descriptor instead.
func (*CreateWalletByMnemonicRequest) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{4}
}

func (x *CreateWalletByMnemonicRequest) GetMnemonic() []string {
	if x != nil {
		return x.Mnemonic
	}
	return nil
}

type CreateWalletByMnemonicResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 私钥
	PrivateKey string `protobuf:"bytes,1,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// 公钥
	PublicKey string `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *CreateWalletByMnemonicResponse) Reset() {
	*x = CreateWalletByMnemonicResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_wallet_v1_wallet_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateWalletByMnemonicResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateWalletByMnemonicResponse) ProtoMessage() {}

func (x *CreateWalletByMnemonicResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_wallet_v1_wallet_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateWalletByMnemonicResponse.ProtoReflect.Descriptor instead.
func (*CreateWalletByMnemonicResponse) Descriptor() ([]byte, []int) {
	return file_api_wallet_v1_wallet_proto_rawDescGZIP(), []int{5}
}

func (x *CreateWalletByMnemonicResponse) GetPrivateKey() string {
	if x != nil {
		return x.PrivateKey
	}
	return ""
}

func (x *CreateWalletByMnemonicResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

var File_api_wallet_v1_wallet_proto protoreflect.FileDescriptor

var file_api_wallet_v1_wallet_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x61, 0x70, 0x69, 0x2f, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x2f,
	0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x77, 0x61,
	0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaa,
	0x01, 0x0a, 0x1d, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x32, 0x57, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x22, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x42, 0x09, 0xfa, 0x42, 0x06, 0x32, 0x04, 0x20, 0x00, 0x40, 0x00, 0x52, 0x06, 0x75, 0x73,
	0x65, 0x72, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x02, 0x42, 0x0c, 0xfa, 0x42, 0x09, 0x0a, 0x07, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x3f, 0x0a, 0x17, 0x72, 0x65,
	0x63, 0x65, 0x69, 0x76, 0x65, 0x72, 0x5f, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x5f, 0x61, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04,
	0x72, 0x02, 0x10, 0x01, 0x52, 0x15, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72, 0x57, 0x61,
	0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x22, 0x55, 0x0a, 0x1e, 0x54,
	0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x32, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x33, 0x0a,
	0x15, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x14, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x22, 0x45, 0x0a, 0x1f, 0x47, 0x65, 0x74, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x79, 0x55, 0x73, 0x65, 0x72, 0x49, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x42, 0x09, 0xfa, 0x42, 0x06, 0x32, 0x04, 0x20, 0x00, 0x40,
	0x00, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x22, 0x49, 0x0a, 0x20, 0x47, 0x65, 0x74,
	0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x79, 0x55,
	0x73, 0x65, 0x72, 0x49, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x25, 0x0a,
	0x0e, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x22, 0x3b, 0x0a, 0x1d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x57, 0x61,
	0x6c, 0x6c, 0x65, 0x74, 0x42, 0x79, 0x4d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69,
	0x63, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69,
	0x63, 0x22, 0x60, 0x0a, 0x1e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x57, 0x61, 0x6c, 0x6c, 0x65,
	0x74, 0x42, 0x79, 0x4d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x32, 0xc2, 0x03, 0x0a, 0x06, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x12, 0x8b,
	0x01, 0x0a, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x42,
	0x79, 0x4d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x12, 0x28, 0x2e, 0x77, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x57, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x42, 0x79, 0x4d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x42, 0x79, 0x4d, 0x6e,
	0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1c,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x16, 0x3a, 0x01, 0x2a, 0x22, 0x11, 0x2f, 0x77, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x2f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x12, 0x99, 0x01, 0x0a,
	0x18, 0x47, 0x65, 0x74, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x42, 0x79, 0x55, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x2a, 0x2e, 0x77, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x79, 0x55, 0x73, 0x65, 0x72, 0x49, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x65, 0x74, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x42, 0x79, 0x55, 0x73, 0x65, 0x72, 0x49, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x24, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1e, 0x12, 0x1c, 0x2f, 0x77, 0x61, 0x6c,
	0x6c, 0x65, 0x74, 0x2f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x7b,
	0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x7d, 0x12, 0x8d, 0x01, 0x0a, 0x16, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x66, 0x65, 0x72, 0x32, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x12, 0x28, 0x2e, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x32, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e,
	0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66,
	0x65, 0x72, 0x32, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x18,
	0x3a, 0x01, 0x2a, 0x22, 0x13, 0x2f, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2f, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x66, 0x65, 0x72, 0x2f, 0x76, 0x31, 0x42, 0x3e, 0x0a, 0x09, 0x77, 0x61, 0x6c, 0x6c,
	0x65, 0x74, 0x2e, 0x76, 0x31, 0x50, 0x01, 0x5a, 0x21, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x5f,
	0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x77, 0x61,
	0x6c, 0x6c, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0xa2, 0x02, 0x0b, 0x41, 0x50, 0x49,
	0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_wallet_v1_wallet_proto_rawDescOnce sync.Once
	file_api_wallet_v1_wallet_proto_rawDescData = file_api_wallet_v1_wallet_proto_rawDesc
)

func file_api_wallet_v1_wallet_proto_rawDescGZIP() []byte {
	file_api_wallet_v1_wallet_proto_rawDescOnce.Do(func() {
		file_api_wallet_v1_wallet_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_wallet_v1_wallet_proto_rawDescData)
	})
	return file_api_wallet_v1_wallet_proto_rawDescData
}

var file_api_wallet_v1_wallet_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_api_wallet_v1_wallet_proto_goTypes = []any{
	(*Transfer2WalletAddressRequest)(nil),    // 0: wallet.v1.Transfer2WalletAddressRequest
	(*Transfer2WalletAddressResponse)(nil),   // 1: wallet.v1.Transfer2WalletAddressResponse
	(*GetWalletAddressByUserIdRequest)(nil),  // 2: wallet.v1.GetWalletAddressByUserIdRequest
	(*GetWalletAddressByUserIdResponse)(nil), // 3: wallet.v1.GetWalletAddressByUserIdResponse
	(*CreateWalletByMnemonicRequest)(nil),    // 4: wallet.v1.CreateWalletByMnemonicRequest
	(*CreateWalletByMnemonicResponse)(nil),   // 5: wallet.v1.CreateWalletByMnemonicResponse
}
var file_api_wallet_v1_wallet_proto_depIdxs = []int32{
	4, // 0: wallet.v1.Wallet.CreateWalletByMnemonic:input_type -> wallet.v1.CreateWalletByMnemonicRequest
	2, // 1: wallet.v1.Wallet.GetWalletAddressByUserId:input_type -> wallet.v1.GetWalletAddressByUserIdRequest
	0, // 2: wallet.v1.Wallet.Transfer2WalletAddress:input_type -> wallet.v1.Transfer2WalletAddressRequest
	5, // 3: wallet.v1.Wallet.CreateWalletByMnemonic:output_type -> wallet.v1.CreateWalletByMnemonicResponse
	3, // 4: wallet.v1.Wallet.GetWalletAddressByUserId:output_type -> wallet.v1.GetWalletAddressByUserIdResponse
	1, // 5: wallet.v1.Wallet.Transfer2WalletAddress:output_type -> wallet.v1.Transfer2WalletAddressResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_api_wallet_v1_wallet_proto_init() }
func file_api_wallet_v1_wallet_proto_init() {
	if File_api_wallet_v1_wallet_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_wallet_v1_wallet_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Transfer2WalletAddressRequest); i {
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
		file_api_wallet_v1_wallet_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*Transfer2WalletAddressResponse); i {
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
		file_api_wallet_v1_wallet_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*GetWalletAddressByUserIdRequest); i {
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
		file_api_wallet_v1_wallet_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*GetWalletAddressByUserIdResponse); i {
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
		file_api_wallet_v1_wallet_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*CreateWalletByMnemonicRequest); i {
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
		file_api_wallet_v1_wallet_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*CreateWalletByMnemonicResponse); i {
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
			RawDescriptor: file_api_wallet_v1_wallet_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_wallet_v1_wallet_proto_goTypes,
		DependencyIndexes: file_api_wallet_v1_wallet_proto_depIdxs,
		MessageInfos:      file_api_wallet_v1_wallet_proto_msgTypes,
	}.Build()
	File_api_wallet_v1_wallet_proto = out.File
	file_api_wallet_v1_wallet_proto_rawDesc = nil
	file_api_wallet_v1_wallet_proto_goTypes = nil
	file_api_wallet_v1_wallet_proto_depIdxs = nil
}
