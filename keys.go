package arch

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// NewPrivateKey generates a fresh secp256k1 private key suitable for use as
// an Arch account key.
func NewPrivateKey() (*btcec.PrivateKey, error) {
	return btcec.NewPrivateKey()
}

// XOnlyPubkey returns the 32-byte x-only public key of a private key. This is
// the Arch account pubkey (the BIP-340 serialization of the public key).
func XOnlyPubkey(priv *btcec.PrivateKey) Pubkey {
	var pk Pubkey
	copy(pk[:], schnorr.SerializePubKey(priv.PubKey()))
	return pk
}

// P2TRAddress returns the taproot (P2TR) Bitcoin address for an Arch account
// pubkey on the given network — the same address the node reports via
// get_account_address. The pubkey is used as the taproot internal key with no
// script tree (BIP-86 style tweak), matching the node's derivation.
func P2TRAddress(pubkey Pubkey, params *chaincfg.Params) (string, error) {
	internalKey, err := schnorr.ParsePubKey(pubkey[:])
	if err != nil {
		return "", fmt.Errorf("invalid x-only pubkey: %w", err)
	}
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}
