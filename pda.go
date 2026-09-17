package arch

// Program-derived addresses, mirroring arch_program::pubkey. Note that Arch's
// derivation differs from Solana's: the hash is a single
// sha256(seed_1 || ... || seed_n || bump || program_id) with no domain
// separator string.

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// MaxSeeds is the maximum number of seeds in a PDA derivation (the bump
// counts as one).
const MaxSeeds = 16

// MaxSeedLen is the maximum length in bytes of each PDA seed.
const MaxSeedLen = 32

// isOnCurve mirrors arch_program::pubkey::Pubkey::is_on_curve, which parses
// the candidate bytes as a full secp256k1 public key (33/65-byte encodings).
func isOnCurve(candidate []byte) bool {
	_, err := btcec.ParsePubKey(candidate)
	return err == nil
}

// CreateProgramAddress derives a program address from seeds and a program id,
// mirroring arch_program::pubkey::Pubkey::create_program_address.
func CreateProgramAddress(seeds [][]byte, programID Pubkey) (Pubkey, error) {
	if len(seeds) > MaxSeeds {
		return Pubkey{}, fmt.Errorf("too many seeds: %d > %d", len(seeds), MaxSeeds)
	}
	for i, seed := range seeds {
		if len(seed) > MaxSeedLen {
			return Pubkey{}, fmt.Errorf("seed %d too long: %d > %d", i, len(seed), MaxSeedLen)
		}
	}

	h := sha256.New()
	for _, seed := range seeds {
		h.Write(seed)
	}
	h.Write(programID[:])
	digest := h.Sum(nil)

	if isOnCurve(digest) {
		return Pubkey{}, fmt.Errorf("invalid seeds: address is on curve")
	}
	var pda Pubkey
	copy(pda[:], digest)
	return pda, nil
}

// FindProgramAddress finds a valid program address and bump seed, mirroring
// arch_program::pubkey::Pubkey::find_program_address: bumps are tried from
// 255 downward, each appended as an extra one-byte seed.
func FindProgramAddress(seeds [][]byte, programID Pubkey) (Pubkey, uint8, error) {
	for bump := 255; bump >= 1; bump-- {
		seedsWithBump := make([][]byte, 0, len(seeds)+1)
		seedsWithBump = append(seedsWithBump, seeds...)
		seedsWithBump = append(seedsWithBump, []byte{uint8(bump)})
		pda, err := CreateProgramAddress(seedsWithBump, programID)
		if err == nil {
			return pda, uint8(bump), nil
		}
	}
	return Pubkey{}, 0, fmt.Errorf("unable to find a viable program address bump seed")
}

// AssociatedTokenAddress derives the associated token account address for a
// wallet and mint, mirroring
// apl_associated_token_account::get_associated_token_address_and_bump_seed.
func AssociatedTokenAddress(wallet, mint Pubkey) (Pubkey, uint8, error) {
	return FindProgramAddress(
		[][]byte{wallet[:], TokenProgramID[:], mint[:]},
		AssociatedTokenProgramID,
	)
}
