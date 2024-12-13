package biz

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	pb "solana_aggregate/api/wallet/v1"
	"solana_aggregate/internal/base/models"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tyler-smith/go-bip39"
	"gorm.io/gorm"
)

type walletType int32

const (
	WalletTypeSol walletType = 0
)

type WalletUsecase struct {
	log  *log.Helper
	Repo WalletRepo
}

type WalletRepo interface {
	GetMysqlDb() *gorm.DB
	GetRpcSolCli() *rpc.Client
}

func NewWalletUsecase(repo WalletRepo, logger log.Logger) *WalletUsecase {
	return &WalletUsecase{
		log:  log.NewHelper(logger),
		Repo: repo,
	}
}

func (u *WalletUsecase) Transfer2WalletAddress(ctx context.Context, req *pb.Transfer2WalletAddressRequest) (*pb.Transfer2WalletAddressResponse, error) {
	userId := req.GetUserId()
	wallet, err := u.GetUserWalletInfo(ctx, userId, WalletTypeSol)
	if err != nil {
		return nil, err
	}
	privateKey := wallet.PrivateKey
	sig, err := u.SendTransaction(ctx, TransactionRequest{
		FromPrivateKey: privateKey,
		ToAddress:      req.GetReceiverWalletAddress(),
		Amount:         uint64(req.GetAmount()),
		Commitment:     rpc.CommitmentFinalized,
		SkipPreflight:  false,
	})
	if err != nil {
		return nil, err
	}
	return &pb.Transfer2WalletAddressResponse{
		TransactionSignature: sig,
	}, nil
}

func (u *WalletUsecase) CreateWalletByMnemonic(ctx context.Context, req *pb.CreateWalletByMnemonicRequest) (*pb.CreateWalletByMnemonicResponse, error) {
	return &pb.CreateWalletByMnemonicResponse{}, nil
}

func (u *WalletUsecase) GetUserWalletInfo(ctx context.Context, userId uint64, walletType walletType) (*UserWallet, error) {
	mysqlDb := u.Repo.GetMysqlDb()
	res := []*UserWallet{}
	cnt, err := models.List(ctx, mysqlDb, func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("user_id = ? and wallet_type = ?", userId, int(walletType))
	}, &res)
	if err != nil {
		return nil, err
	}
	if cnt == 0 {
		return nil, errors.New("cant find user wallet")
	}
	return res[0], nil
}

func (u *WalletUsecase) GetWalletAddressByUserId(ctx context.Context, req *pb.GetWalletAddressByUserIdRequest) (*pb.GetWalletAddressByUserIdResponse, error) {
	userId := req.GetUserId()
	mysqlDb := u.Repo.GetMysqlDb()
	res := []*UserWallet{}
	cnt, err := models.List(ctx, mysqlDb, func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("user_id = ? and wallet_type = 0", userId)
	}, &res)
	if err != nil {
		return nil, err
	}
	if cnt > 0 {
		return &pb.GetWalletAddressByUserIdResponse{
			WalletAddress: res[0].WalletAddress,
		}, nil
	}

	pubKey, err := u.CreateWalletWithMnemonic(ctx, userId)
	if err != nil {
		return nil, err
	}
	return &pb.GetWalletAddressByUserIdResponse{
		WalletAddress: pubKey,
	}, nil
}

func (u *WalletUsecase) CreateWalletWithMnemonic(ctx context.Context, userId uint64) (string, error) {
	// Generate a new mnemonic
	entropy, err := bip39.NewEntropy(256) // 256 bits of entropy
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	// Derive the seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Create a new keypair from the seed
	privateKey := ed25519.NewKeyFromSeed(seed[:32])
	keypair := solana.PrivateKey(privateKey)
	pubKey := keypair.PublicKey()
	if pubKey.IsZero() {
		return "", errors.New("pubKey is zero")
	}
	return pubKey.String(), models.CreateV2[UserWallet](ctx, u.Repo.GetMysqlDb(), &UserWallet{
		UserID:        userId,
		WalletAddress: pubKey.String(),
		Mnemonic:      mnemonic,
		PrivateKey:    keypair.String(),
		WalletType:    0,
	})
}

type TransactionRequest struct {
	FromPrivateKey string
	ToAddress      string
	Amount         uint64
	Commitment     rpc.CommitmentType
	SkipPreflight  bool
}

// SendTransaction sends SOL from one account to another
func (s *WalletUsecase) SendTransaction(ctx context.Context, req TransactionRequest) (string, error) {
	// Create sender wallet from private key
	fromPrivateKey := solana.MustPrivateKeyFromBase58(req.FromPrivateKey)
	fromPubKey := fromPrivateKey.PublicKey()

	// Parse recipient address
	toPubKey := solana.MustPublicKeyFromBase58(req.ToAddress)

	// Check sender's balance
	rpcCli := s.Repo.GetRpcSolCli()
	balance, err := rpcCli.GetBalance(
		ctx,
		fromPubKey,
		req.Commitment,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get balance: %w", err)
	}

	// Verify sufficient balance
	if balance.Value < req.Amount {
		return "", fmt.Errorf("insufficient balance: %d lamports required, got %d",
			req.Amount, balance.Value)
	}

	// Get recent blockhash
	recent, err := rpcCli.GetRecentBlockhash(ctx, req.Commitment)
	if err != nil {
		return "", fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	// Create transfer instruction
	instruction := system.NewTransferInstruction(
		req.Amount,
		fromPubKey,
		toPubKey,
	).Build()

	// Build transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(fromPubKey),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create transaction: %w", err)
	}

	// Sign transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(fromPubKey) {
			return &fromPrivateKey
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	sig, err := rpcCli.SendTransaction(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	return sig.String(), nil
}

func (s *WalletUsecase) ConfirmTransaction(ctx context.Context, signature string, commitment rpc.CommitmentType) error {
	sig := solana.MustSignatureFromBase58(signature)
	rpcCli := s.Repo.GetRpcSolCli()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := rpcCli.GetSignatureStatuses(ctx, false, sig)
			if err != nil {
				return fmt.Errorf("failed to get signature status: %w", err)
			}

			if len(status.Value) == 0 || status.Value[0] == nil {
				return fmt.Errorf("no status returned for signature")
			}

			if status.Value[0].Err != nil {
				return fmt.Errorf("transaction failed: %v", status.Value[0].Err)
			}

			if status.Value[0].Confirmations != nil && *status.Value[0].Confirmations > 0 {
				return nil // Transaction confirmed
			}
		}
	}
}
