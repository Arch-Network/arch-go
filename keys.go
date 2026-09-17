package arch

import (
	"encoding/hex"
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

// P2TRAddress returns the plain taproot (P2TR) Bitcoin address of an x-only
// pubkey (the key as taproot internal key with no script tree, BIP-86 style).
// This is the address BIP-322 signatures commit to. It is NOT an Arch
// account's on-chain address — accounts live in taproot outputs controlled by
// the network's distributed signing key; use AccountAddress (or
// Client.GetAccountAddress) for that.
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

// NetworkPubkeyFromHex parses the value returned by Client.GetNetworkPubkey,
// which may be a 33-byte compressed pubkey or a 32-byte x-only key, into the
// x-only form used by AccountAddress.
func NetworkPubkeyFromHex(s string) (Pubkey, error) {
	var pk Pubkey
	b, err := hex.DecodeString(s)
	if err != nil {
		return pk, fmt.Errorf("invalid network pubkey hex: %w", err)
	}
	switch len(b) {
	case 32:
		copy(pk[:], b)
	case 33:
		copy(pk[:], b[1:])
	default:
		return pk, fmt.Errorf("network pubkey must be 32 or 33 bytes, got %d", len(b))
	}
	return pk, nil
}

// AccountAddress derives the Bitcoin address of an Arch account offline — the
// same address the node reports via get_account_address, mirroring
// arch-network's build_account_address (as of v0.10.0). The account's UTXO is
// a taproot output whose internal key is the network's distributed signing
// (FROST) pubkey and whose script tree is the single leaf
// <network_key> OP_CHECKSIG OP_FALSE OP_IF <account_pubkey> OP_ENDIF
// (the OP_FALSE makes the account-pubkey block a dead data envelope).
// networkPubkey is the x-only network key (see NetworkPubkeyFromHex).
func AccountAddress(networkPubkey, accountPubkey Pubkey, params *chaincfg.Params) (string, error) {
	internalKey, err := schnorr.ParsePubKey(networkPubkey[:])
	if err != nil {
		return "", fmt.Errorf("invalid network pubkey: %w", err)
	}

	script, err := txscript.NewScriptBuilder().
		AddData(networkPubkey[:]).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_FALSE).
		AddOp(txscript.OP_IF).
		AddData(accountPubkey[:]).
		AddOp(txscript.OP_ENDIF).
		Script()
	if err != nil {
		return "", err
	}

	root := txscript.NewBaseTapLeaf(script).TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, root[:])
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}
