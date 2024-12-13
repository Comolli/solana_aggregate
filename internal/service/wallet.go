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

func NewWalletService() *WalletService {
	return &WalletService{}
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

// func (u *PrepareLessonUsecase) GetPrepareIdTimeOutPass(ctx context.Context, schoolId string) ([]*Interact, error) {
// 	res := []*Interact{}
// 	timeOutAgo := time.Now().Add(-(1 * AndriodEndTimeOut))
// 	t := utils.GetTableName(schoolId, Interact{}.TableName())
// 	if _, err := models.ListV2[Interact](ctx, u.repo.GetDB(), func(d *gorm.DB) *gorm.DB {
// 		return d.Debug().Where("created_at < ? and deleted_at is null", timeOutAgo)
// 	}, &res, t); err != nil {
// 		return nil, err
// 	}
// 	return res, nil
// }

// func (s *WalletService) GetWalletAddressByUserId(ctx context.Context, req *pb.GetWalletAddressByUserIdRequest) (*pb.GetWalletAddressByUserIdResponse, error) {
// 	return s.uc.GetWalletAddressByUserId(ctx, req)
// }

// func (s *WalletService) Transfer2WalletAddress(ctx context.Context, req *pb.Transfer2WalletAddressRequest) (*pb.Transfer2WalletAddressResponse, error) {
// 	return s.uc.Transfer2WalletAddress(ctx, req)
// }
