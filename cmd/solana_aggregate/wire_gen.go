// Code generated by Wire. DO NOT EDIT.

//go:generate go run -mod=mod github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"solana_aggregate/internal/biz"
	"solana_aggregate/internal/conf"
	"solana_aggregate/internal/data"
	"solana_aggregate/internal/server"
	"solana_aggregate/internal/service"
)

import (
	_ "go.uber.org/automaxprocs"
)

// Injectors from wire.go:

// wireApp init kratos application.
func wireApp(confServer *conf.Server, confData *conf.Data, logger log.Logger) (*kratos.App, func(), error) {
	db := data.NewMysql(confData, logger)
	client := data.NewSolRpcCli(confServer, logger)
	dataData, cleanup, err := data.NewData(logger, db, client)
	if err != nil {
		return nil, nil, err
	}
	walletRepo := data.NewWalletRepo(dataData, logger)
	walletUsecase := biz.NewWalletUsecase(walletRepo, logger)
	walletService := service.NewWalletService(walletUsecase)
	grpcServer := server.NewGRPCServer(confServer, walletService, logger)
	httpServer := server.NewHTTPServer(confServer, walletService, logger)
	app := newApp(logger, grpcServer, httpServer)
	return app, func() {
		cleanup()
	}, nil
}
