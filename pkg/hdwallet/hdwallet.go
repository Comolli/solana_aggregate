package hdwallet

import (
	"crypto/ed25519"

	"github.com/tyler-smith/go-bip39"
)

const (
	Purpose      uint32 = 44
	CoinType     uint32 = 501 // Solana 的币种类型是 501
	Change       uint32 = 0   // 通常为0
	AddressIndex uint32 = 0   // 地址索引，可以递增
)

type KeypairGenerator struct {
	seed   []byte
	master Node
}

func NewKeypairGenerator(mnemonic string) (*KeypairGenerator, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}

	master, err := NewMasterNode(seed)
	if err != nil {
		return nil, err
	}

	return &KeypairGenerator{
		seed:   seed,
		master: master,
	}, nil
}

func (g *KeypairGenerator) Keypair(accountIndex uint32) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	path := []uint32{
		Purpose,
		CoinType,
		accountIndex,
		Change,
	}

	node := g.master
	for _, i := range path {
		node, err = node.Derive(i | FirstHardenedIndex)
		if err != nil {
			return nil, nil, err
		}
	}

	pub, priv = node.Keypair()

	return pub, priv, nil
}
