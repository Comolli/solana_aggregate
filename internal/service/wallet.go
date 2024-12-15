package service

import (
	"context"
	pb "solana_aggregate/api/wallet/v1"
	"solana_aggregate/internal/biz"
)

type WalletService struct {
	pb.UnimplementedWalletServer
	uc *biz.WalletUsecase
}

func NewWalletService(uc *biz.WalletUsecase) *WalletService {
	return &WalletService{
		uc: uc,
	}
}

func (s *WalletService) CreateAddress(ctx context.Context, req *pb.CreateAddressRequest) (*pb.CreateAddressResponse, error) {
	return s.uc.GetWalletAddressByUserId(ctx, req)
}

func (s *WalletService) Transfer(ctx context.Context, req *pb.TransferRequest) (*pb.TransferResponse, error) {
	return s.uc.Transfer2WalletAddress(ctx, req)
}

// func (s *WalletService) CreateWalletByMnemonic(ctx context.Context, req *pb.CreateWalletByMnemonicRequest) (*pb.CreateWalletByMnemonicResponse, error) {
// 	return s.uc.CreateWalletByMnemonic(ctx, req)
// }

// func (s *WalletService) GetWalletAddressByUserId(ctx context.Context, req *pb.GetWalletAddressByUserIdRequest) (*pb.GetWalletAddressByUserIdResponse, error) {
// 	return s.uc.GetWalletAddressByUserId(ctx, req)
// }

// func (s *WalletService) Transfer2WalletAddress(ctx context.Context, req *pb.Transfer2WalletAddressRequest) (*pb.Transfer2WalletAddressResponse, error) {
// 	return s.uc.Transfer2WalletAddress(ctx, req)
// }
