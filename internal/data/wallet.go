package data

import (
	"solana_aggregate/internal/biz"

	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-kratos/kratos/v2/log"
	"gorm.io/gorm"
)

type WalletRepo struct {
	db         *gorm.DB
	log        *log.Helper
	solRpcCli  *rpc.Client
	privateKey string
}

func NewWalletRepo(data *Data, logger log.Logger) biz.WalletRepo {
	return &WalletRepo{
		db:        data.MysqlDb,
		log:       log.NewHelper(logger),
		solRpcCli: data.solRpcCli,
	}
}

func (r *WalletRepo) GetMysqlDb() *gorm.DB {
	return r.db
}

func (r *WalletRepo) GetRpcSolCli() *rpc.Client {
	return r.solRpcCli
}

func (r *WalletRepo) GetPrivateKey() string {
	return r.privateKey
}
