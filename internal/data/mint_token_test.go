package data

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"

	"github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	SOLANA_PRIVATE_KEY     = "42uscNweihsXURQyD3Gs5dvzjy7aRxn5eZspQgnwmr2AXn1jirqUwvcLhBXmwM6jFBvbvQSTADqBEQNB2KYAkAE7"
	SOLANA_PUBLIC_KEY      = "7Q4yj4Dsir5gXu4YsZrsYZ2ro5ytVmsyZFhg9gR88rfV"
	mintAccountPubKey      = "5UEokEzVxWBPLabxiiz6uKkx6mSPNGMPH1z7Afk2CPZW"
	mintAccountPRIVATE_KEY = "5dftrxjU9fEFT2kNSJdp5ThgksrNvZ9pqUGLx8T7Ah6xXkQJyHTdf88PTEqb5LQNn7JZPyNfGSMkTsNgXNEccrmz"
	tokenMetadataAddress   = "4U4fYv5TcLpFj9mJg2yywzRY1V7WXrdhdF3oXJCxWTLA"
	toWalletAddress        = "BGeF9BWTn4zWGdMyQRFvVuadxXAqvDmEJwPzQUQ9dmWg"
)

func TestSendMintTokenTransaction(t *testing.T) {
	// Initialize client
	client := rpc.New(rpc.DevNet_RPC)
	ctx := context.Background()

	// Set up keys and addresses
	senderPrivateKey := solana.MustPrivateKeyFromBase58(SOLANA_PRIVATE_KEY)
	senderPublicKey := senderPrivateKey.PublicKey()
	mintAddress := solana.MustPublicKeyFromBase58(mintAccountPubKey)
	recipientAddress := solana.MustPublicKeyFromBase58(toWalletAddress)

	// Debug logging
	log.Printf("Sender Public Key: %s", senderPublicKey)
	log.Printf("Mint Address: %s", mintAddress)
	log.Printf("Recipient Address: %s", recipientAddress)

	// Validate mint account
	mintInfo, err := client.GetAccountInfo(ctx, mintAddress)
	if err != nil || mintInfo == nil {
		log.Fatalf("Invalid mint address or mint account not found: %v", err)
	}
	log.Printf("Mint account exists and is valid")

	// Find and validate sender ATA
	senderATA, _, err := solana.FindAssociatedTokenAddress(
		senderPublicKey,
		mintAddress,
	)
	if err != nil {
		log.Fatalf("Error finding sender ATA: %v", err)
	}

	// Get and validate sender token account
	senderAccInfo, err := client.GetAccountInfo(ctx, senderATA)
	if err != nil || senderAccInfo == nil {
		log.Fatalf("Sender token account not found or invalid: %v", err)
	}
	log.Printf("Sender ATA: %s", senderATA)

	// Get sender token balance
	senderBalance, err := client.GetTokenAccountBalance(ctx, senderATA, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("Error getting sender balance: %v", err)
	}
	tokenAmount, err := strconv.ParseUint(senderBalance.Value.Amount, 10, 64)
	if err != nil {
		log.Fatalf("Error parsing token amount: %v", err)
	}
	log.Printf("Sender token balance: %d", tokenAmount)

	// Find and validate recipient ATA
	recipientATA, _, err := solana.FindAssociatedTokenAddress(
		recipientAddress,
		mintAddress,
	)
	if err != nil {
		log.Fatalf("Error finding recipient ATA: %v", err)
	}

	// Get and validate recipient token account
	recipientAccInfo, err := client.GetAccountInfo(ctx, recipientATA)
	if err != nil || recipientAccInfo == nil {
		log.Printf("Warning: Recipient token account not found. It needs to be created first")
		// You might want to create the ATA here
		return
	}
	log.Printf("Recipient ATA: %s", recipientATA)

	// Get token mint info for decimals
	mintAccInfo, err := client.GetTokenSupply(ctx, mintAddress, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("Error getting token mint info: %v", err)
	}
	decimals := mintAccInfo.Value.Decimals
	log.Printf("Token decimals: %d", decimals)

	// Create transfer instruction
	transferAmount := uint64(1000000) // Adjust based on your token decimals
	log.Printf("Transfer amount: %d", transferAmount)

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
		log.Printf("Simulation error: %v", err)
		return
	}
	if sim.Value.Err != nil {
		log.Printf("Simulation showed error: %v", sim.Value.Err)
		return
	}

	// Send transaction
	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}

	log.Printf("Transaction sent! Signature: %s", sig)

}
func TestMintToken(t *testing.T) {
	// 1. 初始化钱包
	wallet := solana.MustPrivateKeyFromBase58(SOLANA_PRIVATE_KEY)

	// 2. 连接到 Solana 网络
	client := rpc.New(rpc.DevNet_RPC) // 使用开�������������网络,可改为 MainnetBeta

	// 3. 创建新的代币铸造账户
	mintAccount := solana.NewWallet()
	mintAccountPubKey := mintAccount.PublicKey()
	mintAccountPrivateKey := mintAccount.PrivateKey
	log.Printf("新创建的代币地址: %s", mintAccountPubKey)
	log.Printf("新创建的代币私钥: %s", mintAccountPrivateKey)

	// 4. 计算所需空间的租金
	rentExemptionAmount, err := client.GetMinimumBalanceForRentExemption(
		context.Background(),
		82, // Size of a mint account is 82 bytes
		rpc.CommitmentConfirmed,
	)
	if err != nil {
		log.Fatalf("计算租金失败: %v", err)
	}

	// 5. 创建系统程序创建账户的指令
	createAccountIx := system.NewCreateAccountInstruction(
		rentExemptionAmount,
		82, // Size of a mint account is 82 bytes
		token.ProgramID,
		wallet.PublicKey(),
		mintAccount.PublicKey(),
	).Build()
	// 6. 修改后的代币初始化指令
	// walletPubKey := wallet.PublicKey()

	// 4. Create Associated Token Account (ATA)
	ata, _, err := solana.FindAssociatedTokenAddress(
		wallet.PublicKey(),
		mintAccountPubKey,
	)
	if err != nil {
		log.Fatalf("failed to find associated token address: %v", err)
	}
	mintPubKey := mintAccount.PublicKey()
	initializeMintIx := token.NewInitializeMint2Instruction(
		9, // decimals
		wallet.PublicKey(),
		wallet.PublicKey(),
		mintPubKey, // mint account
	).Build()
	// 5. Create ATA instruction
	createAtaIx := associatedtokenaccount.NewCreateInstruction(
		wallet.PublicKey(), // payer
		wallet.PublicKey(), // owner
		mintAccountPubKey,  // mint
	).Build()

	// 6. Mint tokens instruction
	mintToIx := token.NewMintToInstruction(
		100000000000, // amount (1 token with 9 decimals)
		mintAccountPubKey,
		ata,
		wallet.PublicKey(),
		[]solana.PublicKey{},
	).Build()

	tokenMetadataAddress, _, err := solana.FindTokenMetadataAddress(mintAccountPubKey)
	if err != nil {
		log.Fatalf("failed to find token metadata address: %v", err)
	}
	log.Printf("token metadata address: %s", tokenMetadataAddress)
	// 7. ���取最新区块哈希
	recent, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("获取区块哈希失败: %v", err)
	}
	log.Printf("最新区块哈希: %s", recent.Value.Blockhash)

	// 8. 构建交易
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			createAccountIx,
			initializeMintIx,
			createAtaIx,
			mintToIx,
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(wallet.PublicKey()),
	)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}

	// 9. 签名交易
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(wallet.PublicKey()) {
			return &wallet
		}
		if key.Equals(mintAccount.PublicKey()) {
			return &mintAccount.PrivateKey
		}
		return nil
	})
	if err != nil {
		log.Fatalf("签名交易失败: %v", err)
	}

	// 10. 发送交易
	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("发送交易失败: %v", err)
	}

	// 11. 输出重要信息
	log.Printf("\n=== 代币创建成功 ===")
	log.Printf("交易签名: %s", sig)
	log.Printf("代币地址: %s", mintAccount.PublicKey())
	log.Printf("代币精度: 9")
	log.Printf("铸币权限: %s", wallet.PublicKey())
	log.Printf("冻结权限: %s", wallet.PublicKey())

	// 12. 保存代币私钥 (重要!)
	log.Printf("\n=== 重要! 请安全保存以下信息 ===")
	log.Printf("代币私钥: %s", base64.StdEncoding.EncodeToString(mintAccount.PrivateKey[:]))
}

func TestTransferSol(t *testing.T) {
	client := rpc.New(rpc.DevNet_RPC)
	toWalletAccount := solana.NewWallet()
	pubKey := toWalletAccount.PublicKey()
	privateKey := toWalletAccount.PrivateKey
	t.Logf("pubKey: %s", pubKey)
	t.Logf("privateKey: %s", privateKey)
	fromWalletAccount := solana.MustPrivateKeyFromBase58(SOLANA_PRIVATE_KEY)
	fromWalletAccountPubKey := fromWalletAccount.PublicKey()
	recent, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		t.Fatalf("failed to get recent blockhash: %v", err)
	}
	// Create transfer instruction
	instruction := system.NewTransferInstruction(
		solana.LAMPORTS_PER_SOL,
		fromWalletAccountPubKey,
		pubKey,
	).Build()

	// Build transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(fromWalletAccountPubKey),
	)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(fromWalletAccountPubKey) {
			return &fromWalletAccount
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("failed to send transaction: %v", err)
	}
	fmt.Printf("Transaction signature: %s\n", sig)

}

func TestWalletHoldToken(t *testing.T) {
	client := rpc.New(rpc.DevNet_RPC)
	wallet := solana.MustPrivateKeyFromBase58(SOLANA_PRIVATE_KEY)
	t.Logf("wallet: %s", wallet.PublicKey())
	CreateToken2(client, wallet)
}

func CreateToken2(client *rpc.Client, payer solana.PrivateKey) {
	// 1. 检查账户余额
	balance, err := client.GetBalance(
		context.Background(),
		payer.PublicKey(),
		rpc.CommitmentFinalized,
	)
	if err != nil {
		log.Fatalf("failed to get balance: %v", err)
	}
	fmt.Printf("Current balance: %d lamports\n", balance)

	// 如果余太低，请求空投
	if balance.Value < solana.LAMPORTS_PER_SOL {
		sig, err := client.RequestAirdrop(
			context.Background(),
			payer.PublicKey(),
			solana.LAMPORTS_PER_SOL,
			rpc.CommitmentFinalized,
		)
		if err != nil {
			log.Fatalf("failed to request airdrop: %v", err)
		}
		fmt.Printf("Airdrop requested: %s\n", sig)
	}

	// 2. 创���新的 mint account（每次都是新的）
	mintAccount := solana.MustPrivateKeyFromBase58(mintAccountPRIVATE_KEY)
	mintAccountPubKey := mintAccount.PublicKey()
	fmt.Printf("New Mint Account: %s\n", mintAccountPubKey)

	// 3. 创建 mint account 系统指令
	createMintAccountIx := system.NewCreateAccountInstruction(
		uint64(solana.LAMPORTS_PER_SOL/10), // lamports
		uint64(82),                         // space
		token.ProgramID,                    // owner
		mintAccountPubKey,                  // new mint account (already a PublicKey)
		payer.PublicKey(),                  // from
	).Build()

	// 3. Initialize mint instruction
	initializeMintIx := token.NewInitializeMintInstruction(
		9,                 // decimals
		mintAccountPubKey, // mint account (already a PublicKey)
		payer.PublicKey(), // mint authority
		payer.PublicKey(), // freeze authority
		token.ProgramID,
	).Build()

	// 4. Create Associated Token Account (ATA)
	ata, _, err := solana.FindAssociatedTokenAddress(
		payer.PublicKey(),
		mintAccountPubKey,
	)
	if err != nil {
		log.Fatalf("failed to find associated token address: %v", err)
	}

	// 5. Create ATA instruction
	createAtaIx := associatedtokenaccount.NewCreateInstruction(
		payer.PublicKey(), // payer
		payer.PublicKey(), // owner
		mintAccountPubKey, // mint
	).Build()

	// 6. Mint tokens instruction
	mintToIx := token.NewMintToInstruction(
		1000000000, // amount (1 token with 9 decimals)
		mintAccountPubKey,
		ata,
		payer.PublicKey(),
		[]solana.PublicKey{},
	).Build()

	// 7. Get recent blockhash
	recent, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("failed to get recent blockhash: %v", err)
	}

	// 8. Create transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			createMintAccountIx,
			initializeMintIx,
			createAtaIx,
			mintToIx,
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		log.Fatalf("failed to create transaction: %v", err)
	}

	// 9. Sign transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		switch key {
		case payer.PublicKey():
			return &payer
		case mintAccountPubKey:
			return &payer
		default:
			return nil
		}
	})
	if err != nil {
		log.Fatalf("failed to sign transaction: %v", err)
	}

	// 10. Send transaction
	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction signature: %s\n", sig)
	fmt.Printf("Token created and minted successfully!\n")
	fmt.Printf("Associated Token Account: %s\n", ata)

}

func createToken(client *rpc.Client, wallet solana.PrivateKey) {
	// Generate a new mint account
	mintAccount := solana.NewWallet()

	// Create token mint instruction
	createMintIx := token.NewInitializeMintInstruction(
		9,                  // decimals
		wallet.PublicKey(), // mint authority
		solana.PublicKey{}, // Replace nil with empty public key
		mintAccount.PublicKey(),
		token.ProgramID, // Use token.ProgramID instead of TOKEN_PROGRAM_ID
	)

	// Create associated token account
	ata, _, err := solana.FindAssociatedTokenAddress(
		wallet.PublicKey(),
		mintAccount.PublicKey(),
	)
	if err != nil {
		log.Fatalf("Error finding associated token address: %v", err)
	}

	// Create token account instruction
	createAccountIx := associatedtokenaccount.NewCreateInstruction(
		ata,                     // ata
		wallet.PublicKey(),      // owner
		mintAccount.PublicKey(), // mint
	).Build()

	// 6. Mint tokens instruction
	mintToIx := token.NewMintToInstruction(
		1000000000, // amount (1 token with 9 decimals)
		mintAccount.PublicKey(),
		ata,
		wallet.PublicKey(),
		[]solana.PublicKey{},
	).Build()

	// Get recent blockhash
	recent, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentConfirmed)
	if err != nil {
		log.Fatalf("Error getting recent blockhash: %v", err)
	}

	// Build transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			createMintIx.Build(), // Build() returns Instruction
			createAccountIx,
			mintToIx,
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(wallet.PublicKey()),
	)
	if err != nil {
		log.Fatalf("Error creating transaction: %v", err)
	}

	// Sign and send transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if wallet.PublicKey().Equals(key) {
			return &wallet
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}

	fmt.Printf("Token created! Transaction signature: %s\n", sig)
}

func TestSolanaMintToken(t *testing.T) {
	// Connect to the Solana cluster
	client := rpc.New(rpc.DevNet_RPC) // Change to MainNet or DevNet as needed

	// Load the private key from an environment variable or a file
	privateKey := os.Getenv("SOLANA_PRIVATE_KEY") // Example: "your_private_key_here"
	if privateKey == "" {
		log.Fatal("Please set the SOLANA_PRIVATE_KEY environment variable")
	}

	// Decode the private key
	var keyPair solana.PrivateKey
	err := json.Unmarshal([]byte(privateKey), &keyPair)
	if err != nil {
		log.Fatalf("failed to unmarshal private key: %v", err)
	}

	// Create a new token mint
	mintAccount := solana.NewWallet()

	// Get recent blockhash
	recent, err := client.GetLatestBlockhash(
		context.Background(),
		rpc.CommitmentFinalized,
	)
	if err != nil {
		t.Fatalf("failed to get recent blockhash: %v", err)
	}

	// Find the associated token address
	ata, _, err := solana.FindAssociatedTokenAddress(
		keyPair.PublicKey(),
		mintAccount.PublicKey(),
	)
	if err != nil {
		t.Fatalf("failed to find associated token address: %v", err)
	}

	// Define amount before using it
	amount := uint64(1000) // Amount to mint

	// Create mint instruction with correct argument order
	mintInstruction := token.NewMintToInstruction(
		amount,                  // amount (uint64)
		mintAccount.PublicKey(), // mint account
		ata,                     // destination
		keyPair.PublicKey(),     // authority
		[]solana.PublicKey{},    // signers
	).Build()

	// Build transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{mintInstruction},
		recent.Value.Blockhash,
		solana.TransactionPayer(keyPair.PublicKey()),
	)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}

	// Sign and send transaction
	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction sent: %s\n", sig)
}

func TestFindAssociatedTokenAddress(t *testing.T) {
	payerPrivateKey := "42uscNweihsXURQyD3Gs5dvzjy7aRxn5eZspQgnwmr2AXn1jirqUwvcLhBXmwM6jFBvbvQSTADqBEQNB2KYAkAE7"
	var payer solana.PrivateKey
	err := json.Unmarshal([]byte(payerPrivateKey), &payer)
	if err != nil {
		log.Fatalf("failed to unmarshal private key: %v", err)
	}

	// Replace with your actual wallet address and mint address
	walletAddress := payer.PublicKey()
	mintAddress := solana.MustPublicKeyFromBase58("YourMintAddressHere")

	// Call the FindAssociatedTokenAddress function
	associatedTokenAddress, _, err := solana.FindAssociatedTokenAddress(
		walletAddress,
		mintAddress,
	)
	if err != nil {
		t.Fatalf("failed to find associated token address: %v", err)
	}

	fmt.Printf("Associated Token Address: %s\n", associatedTokenAddress)
}

func TestSolanaAssociatedTokenAccount(t *testing.T) {
	// Connect to Solana devnet
	client := rpc.New(rpc.DevNet_RPC)

	// Create a new wallet keypair for payer
	payer := solana.NewWallet()

	// Create a new keypair for mint account
	mintAccount := solana.NewWallet()
	fmt.Printf("Mint Account Public Key: %s\n", mintAccount.PublicKey())
	// Request airdrop for payer wallet
	// sig, err := client.RequestAirdrop(
	// 	context.TODO(),
	// 	payer.PublicKey(),
	// 	solana.LAMPORTS_PER_SOL,
	// 	rpc.CommitmentFinalized,
	// )
	// if err != nil {
	// 	log.Fatalf("failed to request airdrop: %v", err)
	// }

	// Create mint account instruction
	createMintAccountIx := system.NewCreateAccountInstruction(
		uint64(solana.LAMPORTS_PER_SOL/10), // lamports
		uint64(82),                         // space
		token.ProgramID,                    // owner
		mintAccount.PublicKey(),            // to
		payer.PublicKey(),                  // from
	).Build()

	// Initialize mint instruction
	initializeMintIx := token.NewInitializeMintInstruction(
		9,                       // decimals (uint8)
		mintAccount.PublicKey(), // mint account
		payer.PublicKey(),       // mint authority
		payer.PublicKey(),       // freeze authority
		solana.PublicKey{},      // empty public key
	).Build()

	// // Get recent blockhash
	// recent, err := client.GetRecentBlockhash(context.TODO(), rpc.CommitmentConfirmed)
	// if err != nil {
	// 	log.Fatalf("failed to get recent blockhash: %v", err)
	// }
	recent, err := client.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("failed to get recent blockhash: %v", err)
	}

	// Create transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			// airdropIx,              // Add airdrop instruction
			createMintAccountIx,
			initializeMintIx,
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		log.Fatalf("failed to create transaction: %v", err)
	}

	// Sign transaction with both payer and mint account
	_, err = tx.Sign(
		func(key solana.PublicKey) *solana.PrivateKey {
			switch key {
			case payer.PublicKey():
				return &payer.PrivateKey
			case mintAccount.PublicKey():
				return &mintAccount.PrivateKey
			default:
				return nil
			}
		},
	)
	if err != nil {
		log.Fatalf("failed to sign transaction: %v", err)
	}

	// Send transaction
	sig, err := client.SendTransaction(context.TODO(), tx)
	if err != nil {
		log.Fatalf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction signature: %s\n", sig)
	fmt.Printf("Mint Account created: %s\n", mintAccount.PublicKey())
}

func TestCreateAndMintToken(t *testing.T) {
	// Connect to Solana devnet
	client := rpc.New(rpc.DevNet_RPC)

	// Create a new wallet for the payer/authority
	payer := solana.NewWallet()
	mintAccount := solana.NewWallet()

	fmt.Printf("Payer Address: %s\n", payer.PublicKey())
	fmt.Printf("Mint Address: %s\n", mintAccount.PublicKey())

	// Request airdrop for payer wallet (commented out for test)
	sig, err := client.RequestAirdrop(
		context.TODO(),
		payer.PublicKey(),
		solana.LAMPORTS_PER_SOL,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		t.Fatalf("failed to request airdrop: %v", err)
	}
	fmt.Printf("Airdrop signature: %s\n", sig)

	// 1. Create mint account
	createMintAccountIx := system.NewCreateAccountInstruction(
		uint64(solana.LAMPORTS_PER_SOL/10), // lamports
		uint64(82),                         // space for mint
		token.ProgramID,                    // owner
		mintAccount.PublicKey(),            // new mint account
		payer.PublicKey(),                  // from
	).Build()

	// 2. Initialize mint
	initializeMintIx := token.NewInitializeMintInstruction(
		9,                       // decimals
		mintAccount.PublicKey(), // mint account
		payer.PublicKey(),       // mint authority
		payer.PublicKey(),       // freeze authority (optional)
		token.ProgramID,         // program id
	).Build()

	// 3. Create Associated Token Account (ATA) for the payer
	ata, _, err := solana.FindAssociatedTokenAddress(
		payer.PublicKey(),
		mintAccount.PublicKey(),
	)
	if err != nil {
		t.Fatalf("failed to find associated token address: %v", err)
	}

	// Create Associated Token Account instruction
	createAtaIx := associatedtokenaccount.NewCreateInstruction(
		payer.PublicKey(),       // funding address (payer)
		payer.PublicKey(),       // owner
		mintAccount.PublicKey(), // mint
	).Build()

	// 4. Mint tokens to ATA
	mintToIx := token.NewMintToInstruction(
		1000000000, // amount (1 token with 9 decimals)
		mintAccount.PublicKey(),
		ata,
		payer.PublicKey(),
		[]solana.PublicKey{},
	).Build()

	// Get recent blockhash
	recent, err := client.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		t.Fatalf("failed to get recent blockhash: %v", err)
	}

	// Create and sign transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			createMintAccountIx,
			initializeMintIx,
			createAtaIx,
			mintToIx,
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}

	// Sign transaction
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		switch key {
		case payer.PublicKey():
			return &payer.PrivateKey
		case mintAccount.PublicKey():
			return &mintAccount.PrivateKey
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}

	// Send transaction
	txSig, err := client.SendTransaction(context.TODO(), tx)
	if err != nil {
		t.Fatalf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction signature: %s\n", txSig)
	fmt.Printf("Token created and minted successfully!\n")
	fmt.Printf("Mint Account: %s\n", mintAccount.PublicKey())
	fmt.Printf("Associated Token Account: %s\n", ata)
}

func TestAirDrop(t *testing.T) {

	client := rpc.New(rpc.DevNet_RPC)
	walletAccount := solana.NewWallet()
	pubKey := walletAccount.PublicKey()
	privateKey := walletAccount.PrivateKey
	t.Logf("pubKey: %s", pubKey)
	t.Logf("privateKey: %s", privateKey)

	t.Log(pubKey.String())
	sig, err := client.RequestAirdrop(
		context.TODO(),
		pubKey,
		solana.LAMPORTS_PER_SOL,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		t.Fatalf("failed to request airdrop: %v", err)
	}
	fmt.Printf("Airdrop signature: %s\n", sig)

}
