package main

import (
	"encoding/binary"
	"flag"
	"log"

	"github.com/pkg/errors"
	"github.com/wavesplatform/gowaves/pkg/crypto"
	"github.com/wavesplatform/gowaves/pkg/proto"
)

func main() {
	log.SetFlags(0)
	var (
		number int
		scheme string
		derive bool
	)
	flag.IntVar(&number, "number", 1, "Number of seeds/key pairs/addresses to generate")
	flag.StringVar(&scheme, "scheme", "W", "Waves blockchain scheme to generate addresses")
	flag.BoolVar(&derive, "derive", false, "Derive accounts from single seed phrase")

	flag.Parse()

	if len(scheme) != 1 {
		log.Fatalf("Invalid blockchain scheme '%s', expected one letter", scheme)
	}
	var seed string
	var n int
	var err error
	for i := 0; i < number; i++ {
		if derive {
			if i == 0 {
				seed, err = mnemonic()
				if err != nil {
					log.Fatalf("Failed to generate seeds: %v", err)
				}
			}
			n = i
		} else {
			seed, err = mnemonic()
			if err != nil {
				log.Fatalf("Failed to generate seeds: %v", err)
			}
			n = 0
		}
		as, pk, sk, ad, err := generate(seed, n, scheme[0])
		if err != nil {
			log.Fatalf("Failed to generate account: %v", err)
		}
		log.Printf("Account #%d:", i+1)
		log.Printf("Seed Phrase: '%s'", seed)
		log.Printf("Account Number: %d", n)
		log.Printf("Account Seed: %s", as.String())
		log.Printf("Public Key: %s", pk.String())
		log.Printf("Secret Key: %s", sk.String())
		log.Printf("Address: %s", ad.String())
		log.Println()
	}
}

func generate(seed string, n int, scheme byte) (crypto.Digest, crypto.PublicKey, crypto.SecretKey, proto.Address, error) {
	iv := make([]byte, 4)
	binary.BigEndian.PutUint32(iv, uint32(n))
	s := append(iv, seed...)
	as, err := crypto.SecureHash(s)
	if err != nil {
		return crypto.Digest{}, crypto.PublicKey{}, crypto.SecretKey{}, proto.Address{}, errors.Wrap(err, "failed to generate account seed")
	}
	sk, pk, err := crypto.GenerateKeyPair(as.Bytes())
	if err != nil {
		return crypto.Digest{}, crypto.PublicKey{}, crypto.SecretKey{}, proto.Address{}, errors.Wrap(err, "failed to generate key pair")
	}
	a, err := proto.NewAddressFromPublicKey(scheme, pk)
	if err != nil {
		return crypto.Digest{}, crypto.PublicKey{}, crypto.SecretKey{}, proto.Address{}, errors.Wrap(err, "failed to generate address")
	}
	return as, pk, sk, a, nil
}
