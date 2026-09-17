package arch

import (
	"encoding/hex"
	"fmt"
)

// Pubkey is a 32-byte secp256k1 x-only public key, mirroring
// arch_program::pubkey::Pubkey. It serializes to JSON as an array of 32
// numbers, which is the wire format the Arch node expects.
type Pubkey [32]byte

// PubkeyFromHex parses a 64-character hex string into a Pubkey.
func PubkeyFromHex(s string) (Pubkey, error) {
	var pk Pubkey
	b, err := hex.DecodeString(s)
	if err != nil {
		return pk, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(b) != 32 {
		return pk, fmt.Errorf("pubkey must be 32 bytes, got %d", len(b))
	}
	copy(pk[:], b)
	return pk, nil
}

// String returns the lowercase hex encoding of the pubkey.
func (p Pubkey) String() string {
	return hex.EncodeToString(p[:])
}

// Hash is a 32-byte hash (block hash, txid, recent blockhash), mirroring
// arch_program::hash::Hash. Like Pubkey it serializes to JSON as an array of
// 32 numbers; its human-readable form is lowercase hex.
type Hash [32]byte

// HashFromHex parses a 64-character hex string into a Hash.
func HashFromHex(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(b) != 32 {
		return h, fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

// String returns the lowercase hex encoding of the hash.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}
