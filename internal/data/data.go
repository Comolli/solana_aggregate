package data

import (
	"fmt"

	"solana_aggregate/internal/biz"
	"solana_aggregate/internal/conf"
	"time"

	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewMysql, NewGreeterRepo, NewWalletRepo, NewSolRpcCli, NewPrivateKey)

// Data .
type Data struct {
	MysqlDb    *gorm.DB
	solRpcCli  *rpc.Client
	privateKey string
}

// NewData .
func NewData(
	logger log.Logger,
	mysqlDb *gorm.DB,
	solRpcCli *rpc.Client,
	privateKey string,
) (*Data, func(), error) {
	cleanup := func() {
		log.NewHelper(logger).Info("closing the data resources")
	}
	return &Data{
		MysqlDb:    mysqlDb,
		solRpcCli:  solRpcCli,
		privateKey: privateKey,
	}, cleanup, nil
}

func NewSolRpcCli(c *conf.Server, logger log.Logger) *rpc.Client {
	return rpc.New(c.SolEndpoint.Endpoint)
}

func NewPrivateKey(c *conf.Server, logger log.Logger) string {
	return c.SolanaPrivateKey.PrivateKey
}

func NewMysql(conf *conf.Data, logger log.Logger) *gorm.DB {
	log := log.NewHelper(log.With(logger, "module", "knowledge/data/gorm"))
	mysqlsource := genMysqlSource(conf)
	db, err := gorm.Open(mysql.Open(mysqlsource), &gorm.Config{})
	db.Logger.LogMode(1)
	if err != nil {
		log.Fatalf("failed opening connection to mysql: %v", err)
	}
	// if !db.Migrator().HasTable(&model.PrepareLessonEventRecord{}) {
	// 	if err := db.AutoMigrate(
	// 		&model.PrepareLessonEventRecord{},
	// 	); err != nil {
	// 		log.Fatal(err)
	// 	}
	// }
	_d, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	_d.SetMaxOpenConns(50)
	_d.SetMaxIdleConns(10)
	_d.SetConnMaxIdleTime(1 * time.Minute)
	if err := db.AutoMigrate(
		&biz.UserInfo{},
		&biz.UserWallet{},
		&biz.UserWalletTransaction{},
		&biz.TokenMintAdress{},
	); err != nil {
		log.Fatal(err)
	}
	return db
}

func genMysqlSource(conf *conf.Data) string {
	return fmt.Sprintf("%s:%s@%s(%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", conf.Database.User, conf.Database.Pwd, conf.Database.Protocol, conf.Database.Uri, conf.Database.Database)
}
