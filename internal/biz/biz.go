package biz

import (
	"github.com/google/wire"
	"gorm.io/gorm"
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewGreeterUsecase, NewWalletUsecase)

type UserInfo struct {
	gorm.Model
	UserID   string `gorm:"type:varchar(1024);default:'';comment:'用户id'" json:"user_id"`
	IsDelete bool   `gorm:"type:tinyint(1);default:0;comment:'是否删除'" json:"is_delete"`
}

type UserWallet struct {
	gorm.Model
	UserID        uint64 `gorm:"type:int;default:0;comment:'用户id'" json:"user_id"`
	WalletType    int    `gorm:"type:int;default:0;comment:'钱包类型: 0=>solana 1=>usdc'" json:"wallet_type"`
	WalletAddress string `gorm:"type:varchar(1024);default:'';comment:'钱包地址'" json:"wallet_address"`
	Mnemonic      string `gorm:"type:varchar(1024);default:'';comment:'助记词'" json:"mnemonic"`
	PrivateKey    string `gorm:"type:varchar(1024);default:'';comment:'私钥'" json:"private_key"`
}

type UserWalletTransaction struct {
	gorm.Model
	Token string `gorm:"type:varchar(1024);default:'';comment:'token名字'" json:"token"`
	// FromWalletPrivateKey string `gorm:"type:varchar(1024);default:'';comment:'发送者钱包私钥'" json:"from_wallet_private_key"`
	ToWallet  string `gorm:"type:varchar(1024);default:'';comment:'接收者钱包地址'" json:"to_wallet"`
	Amount    int64  `gorm:"type:int;default:0;comment:'金额'" json:"amount"`
	Status    int    `gorm:"type:int;default:0;comment:'状态: 0=>初始化default 1=>成功 2=>失败'" json:"status"`
	RequestID string `gorm:"type:varchar(1024);default:'';comment:'请求id'" json:"request_id"`
	Hash      string `gorm:"type:varchar(1024);default:'';comment:'交易hash'" json:"hash"`
}

type TokenMintAdress struct {
	gorm.Model
	Token   string `gorm:"type:varchar(1024);default:'';comment:'token名字'" json:"token_name"`
	Address string `gorm:"type:varchar(1024);default:'';comment:'token地址'" json:"address"`
}
