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
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"gorm.io/gorm"
)

type walletType int32

const (
	WalletTypeSol walletType = 0
)

var (
	RootWalletUserName = "root"
)

type WalletUsecase struct {
	log  *log.Helper
	Repo WalletRepo
}

type WalletRepo interface {
	GetMysqlDb() *gorm.DB
	GetRpcSolCli() *rpc.Client
	GetPrivateKey() string
}

func NewWalletUsecase(repo WalletRepo, logger log.Logger) *WalletUsecase {
	return &WalletUsecase{
		log:  log.NewHelper(logger),
		Repo: repo,
	}
}

func (u *WalletUsecase) Transfer2WalletAddress(ctx context.Context, req *pb.TransferRequest) (*pb.TransferResponse, error) {
	privateKey := u.Repo.GetPrivateKey()
	repeat, err := u.CheckRequestIsRepeat(ctx, req.GetRequestId())
	if err != nil {
		return nil, err
	}
	if repeat {
		return nil, errors.New("request is repeat")
	}
	if req.GetToken() != "solana" {
		tokenMintAdress, err := u.GetTokenMintAdress(ctx, req.GetToken())
		if err != nil {
			return nil, err
		}
		txReq := TransactionRequest{
			FromPrivateKey:  privateKey,
			ToAddress:       req.GetDstAddress(),
			Amount:          uint64(req.GetAmount()),
			TokenMintAdress: tokenMintAdress,
			Commitment:      rpc.CommitmentFinalized,
			SkipPreflight:   false,
			RequestId:       req.GetRequestId(),
			Token:           req.GetToken(),
		}
		sig, err := u.SendTokenTransaction(ctx, txReq)
		if err != nil {
			return nil, err
		}
		txReq.Hash = sig
		if err = u.CreateUserWalletTransaction(ctx, txReq); err != nil {
			return nil, err
		}
		return &pb.TransferResponse{
			Hash: sig,
		}, nil
	}
	txReq := TransactionRequest{
		FromPrivateKey: privateKey,
		ToAddress:      req.GetDstAddress(),
		Amount:         uint64(req.GetAmount()),
		Commitment:     rpc.CommitmentFinalized,
		SkipPreflight:  false,
		RequestId:      req.GetRequestId(),
	}
	sig, err := u.SendSolanaTransaction(ctx, txReq)
	if err != nil {
		return nil, err
	}
	txReq.Hash = sig
	if err = u.CreateUserWalletTransaction(ctx, txReq); err != nil {
		return nil, err
	}
	return &pb.TransferResponse{
		Hash: sig,
	}, nil
}

func DecodeSolanaPublicKey(privateKey string) string {
	keypair := solana.MustPrivateKeyFromBase58(privateKey)
	pubKey := keypair.PublicKey()
	return pubKey.String()
}

func (u *WalletUsecase) CreateUserWalletTransaction(ctx context.Context, req TransactionRequest) error {
	mysqlDb := u.Repo.GetMysqlDb()
	return models.CreateV2[UserWalletTransaction](ctx, mysqlDb, &UserWalletTransaction{
		Amount:     int64(req.Amount),
		FromWallet: DecodeSolanaPublicKey(req.FromPrivateKey),
		ToWallet:   req.ToAddress,
		// Status:     1,
		RequestID: req.RequestId,
		Hash:      req.Hash,
		Token:     req.Token,
	})
}

func (u *WalletUsecase) CheckRequestIsRepeat(ctx context.Context, requestId string) (bool, error) {
	mysqlDb := u.Repo.GetMysqlDb()
	res := []*UserWalletTransaction{}
	cnt, err := models.List(ctx, mysqlDb, func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("request_id = ?", requestId)
	}, &res)
	if err != nil {
		return false, err
	}
	if cnt > 0 {
		return true, nil
	}
	return false, nil
}

func (u *WalletUsecase) GetTokenMintAdress(ctx context.Context, token string) (string, error) {
	mysqlDb := u.Repo.GetMysqlDb()
	res := []*TokenMintAdress{}
	cnt, err := models.List(ctx, mysqlDb, func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("token = ?", token)
	}, &res)
	if err != nil {
		return "", err
	}
	if cnt == 0 {
		return "", errors.New("cant find token mint adress")
	}
	return res[0].Address, nil
}

func CheckTokenAddressIsSolanaAddress(address string) (bool, error) {
	// Attempt to parse the address as a Solana public key
	_, err := solana.PublicKeyFromBase58(address)
	if err != nil {
		return false, err // Return false if the address is invalid
	}
	return true, nil // Return true if the address is valid
}

// func (u *WalletUsecase) CreateWalletByMnemonic(ctx context.Context, req *pb.CreateWalletByMnemonicRequest) (*pb.CreateWalletByMnemonicResponse, error) {
// 	return &pb.CreateWalletByMnemonicResponse{}, nil
// }

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

func (u *WalletUsecase) GetWalletAddressByUserId(ctx context.Context, req *pb.CreateAddressRequest) (*pb.CreateAddressResponse, error) {
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
		return &pb.CreateAddressResponse{
			Address: res[0].WalletAddress,
		}, nil
	}

	pubKey, err := u.CreateWalletWithMnemonic(ctx, userId)
	if err != nil {
		return nil, err
	}
	return &pb.CreateAddressResponse{
		Address: pubKey,
	}, nil
}

func (u *WalletUsecase) GetRootUserWalletInfo(ctx context.Context) (*UserWallet, error) {
	mysqlDb := u.Repo.GetMysqlDb()
	res := []*UserWallet{}
	cnt, err := models.List(ctx, mysqlDb, func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("user_name = ?", RootWalletUserName)
	}, &res)
	if err != nil {
		return nil, err
	}
	if cnt == 0 {
		return nil, errors.New("cant find root user wallet")
	}
	return res[0], nil
}

func (u *WalletUsecase) CreateHierarchicalDeterministicWallet(ctx context.Context, userId uint64) (string, error) {
	res := []*UserWallet{}
	cnt, err := models.List(ctx, u.Repo.GetMysqlDb(), func(d *gorm.DB) *gorm.DB {
		return d.Debug().Where("user_id = ?", userId)
	}, &res)
	if err != nil {
		return "", err
	}
	if cnt > 0 {
		return res[0].PublicKey, nil
	}

	accountIndex := uint32(userId)
	rootUserWallet, err := u.GetRootUserWalletInfo(ctx)
	if err != nil {
		return "", err
	}
	mnemonic := rootUserWallet.Mnemonic
	privateKey, err := deriveWallet(mnemonic, accountIndex)
	if err != nil {
		return "", err
	}
	keypair := solana.PrivateKey(privateKey)
	pubKey := keypair.PublicKey()

	return pubKey.String(), models.CreateV2[UserWallet](ctx, u.Repo.GetMysqlDb(), &UserWallet{
		UserID:        userId,
		WalletAddress: pubKey.String(),
		Mnemonic:      mnemonic,
		PrivateKey:    keypair.String(),
		PublicKey:     pubKey.String(),
		WalletType:    0,
		UserName:      fmt.Sprintf("hd_wallet_user_%d", userId),
	})
}

func deriveWallet(mnemonic string, accountIndex uint32) (solana.PrivateKey, error) {
	// 1. 从助记词生成种子
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}

	// 2. 生成主密钥
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// 3. 按 BIP44 路径派生
	path := []uint32{
		44 + bip32.FirstHardenedChild,           // purpose
		501 + bip32.FirstHardenedChild,          // coin type (SOL)
		accountIndex + bip32.FirstHardenedChild, // account
		0 + bip32.FirstHardenedChild,            // change
		0 + bip32.FirstHardenedChild,            // address index
	}

	// 4. 派生子密钥
	key := masterKey
	for _, n := range path {
		key, err = key.NewChildKey(n)
		if err != nil {
			return nil, err
		}
	}

	privateKey := ed25519.NewKeyFromSeed(key.Key)

	if _, err := solana.ValidatePrivateKey(privateKey); err != nil {
		return nil, err
	}

	return solana.PrivateKey(privateKey), nil
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
	FromPrivateKey  string
	ToAddress       string
	Amount          uint64
	Commitment      rpc.CommitmentType
	TokenMintAdress string
	SkipPreflight   bool
	RequestId       string
	Token           string
	Hash            string
}

func (s *WalletUsecase) SendTokenTransaction(ctx context.Context, req TransactionRequest) (string, error) {
	rpcCli := s.Repo.GetRpcSolCli()
	// Create the sender's keypair from the private key
	senderKeypair, err := solana.PrivateKeyFromBase58(req.FromPrivateKey)
	if err != nil {
		return "", err
		// log.Fatalf("failed to create sender keypair: %v", err)
	}
	// Create the recipient public key
	recipientPubKey, err := solana.PublicKeyFromBase58(req.ToAddress)
	if err != nil {
		log.Fatalf("failed to create recipient public key: %v", err)
		return "", err
	}
	// Create the  token mint address
	tokenMintAdress := solana.MustPublicKeyFromBase58(req.TokenMintAdress)
	// Create the token transfer instruction
	transferInstruction := token.NewTransferInstruction(
		req.Amount,
		senderKeypair.PublicKey(),
		recipientPubKey,
		tokenMintAdress,
		[]solana.PublicKey{},
	).Build()

	recent, err := rpcCli.GetRecentBlockhash(ctx, req.Commitment)
	if err != nil {
		return "", fmt.Errorf("failed to get recent blockhash: %w", err)
	}
	// Create a transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{transferInstruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(senderKeypair.PublicKey()),
	)
	if err != nil {
		log.Fatalf("failed to create transaction: %v", err)
	}

	// Sign the transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(senderKeypair.PublicKey()) {
			return &senderKeypair
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}
	// Send the transaction
	signature, err := rpcCli.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("failed to send transaction: %v", err)
	}
	return signature.String(), nil
}

// SendTransaction sends SOL from one account to another
func (s *WalletUsecase) SendSolanaTransaction(ctx context.Context, req TransactionRequest) (string, error) {
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
