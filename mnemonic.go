package main

import (
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

const (
	defaultBitSize = 160
)

func mnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(defaultBitSize)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate random entropy")
	}
	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate mnemonic phrase")
	}
	return m, nil
}
