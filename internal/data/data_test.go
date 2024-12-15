package data

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"solana_aggregate/internal/biz"
	"solana_aggregate/pkg/hdwallet"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"
	"github.com/mr-tron/base58"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func TestCreateNewWallet(t *testing.T) {
	// Generate a new random wallet/account
	account := solana.NewWallet()

	// Get the public key (wallet address)
	publicKey := account.PublicKey()

	// Get the private key
	privateKey := account.PrivateKey

	fmt.Println("Wallet Address (Public Key):", publicKey.String())
	fmt.Println("Private Key:", privateKey)
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

func TestDeriveWallet(t *testing.T) {
	// Test data
	mnemonic := "begin electric midnight latin eager echo find veteran uniform milk flee brave faint tissue fire faith extra regret water mistake win bullet plate tail"
	accountIndex := uint32(2)

	// // Expected private key (replace with the expected value for your test)
	// expectedPrivateKey := "tZ7AwugCZSQM6bVYe4nLjwCfRu9WNcfqFxzxnFgkrPJaEGTK5BDEWwpiVJZgzqHPEP8GrxpWiggEsNCRLVdyURu"
	// // expectedPublicKey := DecodeSolanaPublicKey(expectedPrivateKey)
	// expectedPublicKey := "D6cpS6HaKutqRpE5yHR6NJnjKy3Rv2KfkSyxN4p1znbZ"
	// Call the deriveWallet function
	privateKey, err := deriveWallet(mnemonic, accountIndex)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	t.Log("privateKey", privateKey.String())

	// // Validate the derived private key

	// if privateKey.String() != expectedPrivateKey {
	// 	t.Errorf("Expected private key %s, got %s", expectedPrivateKey, privateKey.String())
	// }
	// // Validate the derived public key
	// publicKey := privateKey.PublicKey()
	// if publicKey.String() != expectedPublicKey {
	// 	t.Errorf("Expected public key %s, got %s", expectedPublicKey, publicKey.String())
	// }
	// t.Log(publicKey.String())

}

func DecodeSolanaPublicKey(privateKey string) string {
	keypair := solana.MustPrivateKeyFromBase58(privateKey)
	pubKey := keypair.PublicKey()
	return pubKey.String()
}
func TestGetAccountSlot(t *testing.T) {
	// Connect to the Solana devnet
	client := rpc.New(rpc.DevNet_RPC)

	// Replace with a valid public key for testing
	publicKey := solana.MustPublicKeyFromBase58("2JfLGJJuH37KdH17FrBJ8zCtJkUysRZRbW3FKojXLdwU")

	// Get account info
	accountInfo, err := client.GetAccountInfo(context.Background(), publicKey)
	if err != nil {
		t.Fatalf("Failed to get account info: %v", err)
	}

	// Check if the account exists
	if accountInfo == nil {
		t.Fatalf("Account not found: %s", publicKey)
	}
	t.Log(accountInfo.Context.Slot)
}

func GetAccountSlot() uint64 {
	client := rpc.New(rpc.DevNet_RPC)

	// Replace with a valid public key for testing
	publicKey := solana.MustPublicKeyFromBase58("2JfLGJJuH37KdH17FrBJ8zCtJkUysRZRbW3FKojXLdwU")

	// Get account info
	accountInfo, _ := client.GetAccountInfo(context.Background(), publicKey)
	return accountInfo.Context.Slot
}

func TestGetBlockInfo(t *testing.T) {
	// Connect to the Solana devnet
	client := rpc.New(rpc.DevNet_RPC)

	// Specify a valid slot number for testing
	// slot := uint64(12345678) // Replace with a valid slot number
	slot := GetAccountSlot()

	// Get block information
	block, err := client.GetBlock(context.Background(), slot)
	if err != nil {
		t.Fatalf("Failed to get block info: %v", err)
	}

	// Check if the block is not nil
	if block == nil {
		t.Fatalf("Block not found for slot: %d", slot)
	}

	// Check that the slot matches
	// if block.Slot != slot {
	// 	t.Errorf("Expected slot %d, got %d", slot, block.Slot)
	// }

	// Optionally, check the number of transactions in the block
	if len(block.Transactions) == 0 {
		t.Logf("Block %d has no transactions", slot)
	} else {
		t.Logf("Block %d has %d transactions", slot, len(block.Transactions))
	}
	for _, tx := range block.Transactions {
		fmt.Printf("Transaction Signature: %s\n", tx.MustGetTransaction().Signatures[0])
	}
}

func TestGetTransaction(t *testing.T) {
	endpoint := rpc.DevNet_RPC
	client := rpc.New(endpoint)

	pubKey := solana.MustPublicKeyFromBase58("2JfLGJJuH37KdH17FrBJ8zCtJkUysRZRbW3FKojXLdwU") // serum token
	// Let's get a valid transaction to use in the example:
	example, err := client.GetConfirmedSignaturesForAddress2(
		context.TODO(),
		pubKey,
		nil,
	)
	if err != nil {
		panic(err)
	}

	out, err := client.GetConfirmedTransaction(
		context.TODO(),
		example[0].Signature,
	)
	if err != nil {
		panic(err)
	}
	spew.Dump(out)
}

func TestCreateWalletWithMnemonic(t *testing.T) {
	// Generate a new mnemonic
	entropy, err := bip39.NewEntropy(256) // 256 bits of entropy
	if err != nil {
		t.Fatalf("Failed to generate entropy: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatalf("Failed to generate mnemonic: %v", err)
	}

	// Log the generated mnemonic
	t.Logf("Generated Mnemonic: %s", mnemonic)

	// Derive the seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Create a new keypair from the seed
	privateKey := ed25519.NewKeyFromSeed(seed[:32])
	keypair := solana.PrivateKey(privateKey)

	// Check that the public key is not zero
	pubKey := keypair.PublicKey()
	if pubKey.IsZero() {
		t.Errorf("Expected a non-zero public key, got %s", pubKey.String())
	}

	// Check that the private key is not empty
	if len(keypair) == 0 {
		t.Errorf("Expected a non-empty private key, got %v", keypair)
	}

	// Check the length of the private key
	if len(keypair) != 64 {
		t.Errorf("Expected private key length of 64 bytes, got %d", len(keypair))
	}
}

// TransactionService handles Solana transaction operations
type TransactionService struct {
	rpcClient *rpc.Client
	endpoint  string
}

// TransactionRequest represents a transaction request
type TransactionRequest struct {
	FromPrivateKey string
	ToAddress      string
	Amount         uint64
	Commitment     rpc.CommitmentType
	SkipPreflight  bool
}

func TestTransferSOL(t *testing.T) {

}

func TestTransferSOLWs(t *testing.T) {

	// Connect to RPC and WebSocket clients
	rpcClient := rpc.New(rpc.DevNet_RPC) // or rpc.MainNetBeta_RPC for mainnet
	wsClient, err := ws.Connect(context.Background(), rpc.DevNet_WS)
	if err != nil {
		panic(err)
	}
	defer wsClient.Close()

	// Create sender wallet (replace with your private key)
	privateKey := solana.MustPrivateKeyFromBase58("your-private-key")
	sender := privateKey.PublicKey()

	// Recipient address
	recipient := solana.MustPublicKeyFromBase58("recipient-address")

	// Amount to send (in lamports)
	amount := uint64(100000000) // 0.1 SOL = 100000000 lamports

	// Get recent blockhash
	recent, err := rpcClient.GetRecentBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		panic(err)
	}

	// Create transfer instruction
	transferInstruction := system.NewTransferInstruction(
		amount,
		sender,
		recipient,
	).Build()

	// Create transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{transferInstruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(sender),
	)
	if err != nil {
		panic(err)
	}

	// Sign transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(sender) {
			return &privateKey
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	// Send transaction and wait for confirmation
	sig, err := confirm.SendAndConfirmTransaction(
		context.Background(),
		rpcClient,
		wsClient,
		tx,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Transaction signature:", sig)
}

func TestCreateUserWallet(t *testing.T) {
	mnemonic := "begin electric midnight latin eager echo find veteran uniform milk flee brave faint tissue fire faith extra regret water mistake win bullet plate tail"
	// create sol wallet
	generator, err := hdwallet.NewKeypairGenerator(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := generator.Keypair(0)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := base58.Encode(pub)
	privateKey := base58.Encode(priv)

	mysqlDns := "sol_wallet:12334567800@tcp()/sol_wallet_db?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(mysqlDns), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.AutoMigrate(&biz.UserWallet{})
	userWallet := biz.UserWallet{
		UserID:        0,
		WalletType:    0,
		PublicKey:     pubKey,
		PrivateKey:    privateKey,
		WalletAddress: pubKey,
		Mnemonic:      mnemonic,
		UserName:      "root",
	}
	err = db.Create(&userWallet).Error
	if err != nil {
		t.Fatal(err)
	}
}
