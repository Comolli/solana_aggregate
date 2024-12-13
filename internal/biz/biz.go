package biz

import (
	"time"

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
	SenderID   uint64    `gorm:"type:int;default:0;comment:'发送者id'" json:"sender_id"`
	ReceiverID uint64    `gorm:"type:int;default:0;comment:'接收者id'" json:"receiver_id"`
	Amount     int64     `gorm:"type:int;default:0;comment:'金额'" json:"amount"`
	Status     int       `gorm:"type:int;default:0;comment:'状态: 0=>初始化default 1=>成功 2=>失败'" json:"status"`
	TxHash     string    `gorm:"type:varchar(1024);default:'';comment:'交易hash'" json:"tx_hash"`
	TxTime     time.Time `gorm:"type:datetime;comment:'交易时间'" json:"tx_time"`
}
