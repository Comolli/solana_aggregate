package hdwallet

import (
	"testing"

	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
)

func TestKeypairGenerator(t *testing.T) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		t.Fatal(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}

	generator, err := NewKeypairGenerator(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, err := generator.Keypair(0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("mnemonic: %v", mnemonic)
	t.Logf("pub: %v", base58.Encode(pub))
	t.Logf("priv: %v", base58.Encode(priv))
}
