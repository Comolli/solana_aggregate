package biz

import (
	"context"
	"errors"
	"fmt"
	"time"

	pb "solana_aggregate/api/wallet/v1"
	"solana_aggregate/internal/base/models"
	"solana_aggregate/pkg/hdwallet"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/mr-tron/base58"
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
		return "", errors.New("cant find token mint address")
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

	pubKey, err := u.CreateHierarchicalDeterministicWallet(ctx, userId)
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
	generator, err := hdwallet.NewKeypairGenerator(mnemonic)
	if err != nil {
		return "", err
	}

	pub, priv, err := generator.Keypair(accountIndex)
	if err != nil {
		return "", err
	}

	return base58.Encode(pub), models.CreateV2[UserWallet](ctx, u.Repo.GetMysqlDb(), &UserWallet{
		UserID:        userId,
		WalletAddress: base58.Encode(pub),
		Mnemonic:      mnemonic,
		PrivateKey:    base58.Encode(priv),
		PublicKey:     base58.Encode(pub),
		WalletType:    0,
		UserName:      fmt.Sprintf("hd_wallet_user_%d", userId),
	})
}

func (u *WalletUsecase) CreateWalletWithMnemonic(ctx context.Context, userId uint64) (string, error) {
	accountIndex := uint32(userId)
	// Generate a new mnemonic
	entropy, err := bip39.NewEntropy(256) // 256 bits of entropy
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	generator, err := hdwallet.NewKeypairGenerator(mnemonic)
	if err != nil {
		return "", err
	}

	pub, priv, err := generator.Keypair(accountIndex)
	if err != nil {
		return "", err
	}

	return base58.Encode(pub), models.CreateV2[UserWallet](ctx, u.Repo.GetMysqlDb(), &UserWallet{
		UserID:        userId,
		WalletAddress: base58.Encode(pub),
		Mnemonic:      mnemonic,
		PrivateKey:    base58.Encode(priv),
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
	client := s.Repo.GetRpcSolCli()
	// Set up keys and addresses
	senderPrivateKey := solana.MustPrivateKeyFromBase58(req.FromPrivateKey)
	senderPublicKey := senderPrivateKey.PublicKey()
	mintAddress := solana.MustPublicKeyFromBase58(req.TokenMintAdress)
	recipientAddress := solana.MustPublicKeyFromBase58(req.ToAddress)

	// Validate mint account
	mintInfo, err := client.GetAccountInfo(ctx, mintAddress)
	if err != nil || mintInfo == nil {
		return "", fmt.Errorf("invalid mint address or mint account not found: %v", err)
	}

	// Find and validate sender ATA
	senderATA, _, err := solana.FindAssociatedTokenAddress(
		senderPublicKey,
		mintAddress,
	)
	if err != nil {
		return "", fmt.Errorf("error finding sender ata: %v", err)
	}
	// Get and validate sender token account
	senderAccInfo, err := client.GetAccountInfo(ctx, senderATA)
	if err != nil || senderAccInfo == nil {
		return "", fmt.Errorf("sender token account not found or invalid: %v", err)
	}

	// Find and validate recipient ATA
	recipientATA, _, err := solana.FindAssociatedTokenAddress(
		recipientAddress,
		mintAddress,
	)
	if err != nil {
		return "", fmt.Errorf("error finding recipient ata: %v", err)
	}

	// Get and validate recipient token account
	recipientAccInfo, err := client.GetAccountInfo(ctx, recipientATA)
	if err != nil || recipientAccInfo == nil {
		return "", fmt.Errorf("recipient token account not found. It needs to be created first")
	}

	// Get token mint info for decimals
	mintAccInfo, err := client.GetTokenSupply(ctx, mintAddress, rpc.CommitmentFinalized)
	if err != nil {
		return "", fmt.Errorf("error getting token mint info: %v", err)
	}
	decimals := mintAccInfo.Value.Decimals
	// Create transfer instruction
	transferAmount := req.Amount

	transferIx := token.NewTransferCheckedInstruction(
		transferAmount,
		decimals,
		senderATA,
		mintAddress,
		recipientATA,
		senderPublicKey,
		[]solana.PublicKey{},
	).Build()

	// Print instruction accounts for debugging
	fmt.Printf("Transfer instruction accounts:\n")
	for i, acc := range transferIx.Accounts() {
		fmt.Printf("Account %d: %s (is_signer: %v, is_writable: %v)\n",
			i, acc.PublicKey, acc.IsSigner, acc.IsWritable)
	}

	recent, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("Error getting recent blockhash: %v", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{transferIx},
		recent.Value.Blockhash,
		solana.TransactionPayer(senderPublicKey),
	)
	if err != nil {
		log.Fatalf("Error creating transaction: %v", err)
	}

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(senderPublicKey) {
			return &senderPrivateKey
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	// Simulate transaction first
	sim, err := client.SimulateTransaction(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("simulation error: %v", err)
	}
	if sim.Value.Err != nil {
		return "", fmt.Errorf("simulation showed error: %v", sim.Value.Err)
	}

	// Send transaction
	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("error sending transaction: %v", err)
	}

	return sig.String(), nil
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
	recent, err := rpcCli.GetLatestBlockhash(ctx, req.Commitment)
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
