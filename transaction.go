package arch

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// BuildAndSignTransaction hashes the message and produces one BIP-322
// signature per required signer, mirroring arch-network's
// build_and_sign_transaction. signers must contain a private key whose x-only
// pubkey matches each of the first header.num_required_signatures account
// keys.
func BuildAndSignTransaction(message SanitizedMessage, signers ...*btcec.PrivateKey) (RuntimeTransaction, error) {
	digest := message.Hash()

	numRequired := int(message.Header.NumRequiredSignatures)
	if numRequired > len(message.AccountKeys) {
		return RuntimeTransaction{}, fmt.Errorf(
			"message requires %d signatures but has only %d account keys",
			numRequired, len(message.AccountKeys),
		)
	}

	byPubkey := make(map[Pubkey]*btcec.PrivateKey, len(signers))
	for _, signer := range signers {
		byPubkey[XOnlyPubkey(signer)] = signer
	}

	signatures := make([]Signature, 0, numRequired)
	for _, key := range message.AccountKeys[:numRequired] {
		signer, ok := byPubkey[key]
		if !ok {
			return RuntimeTransaction{}, fmt.Errorf("required signer %s not found", key)
		}
		sig, err := SignMessageBIP322(signer, digest)
		if err != nil {
			return RuntimeTransaction{}, err
		}
		signatures = append(signatures, sig)
	}

	return RuntimeTransaction{
		Version:    RuntimeTxVersion,
		Signatures: signatures,
		Message:    message,
	}, nil
}

// AdjustSignature normalizes a BIP-322 signature from an external wallet to
// the 64-byte format Arch transactions carry, mirroring the TypeScript SDK's
// adjustSignature: 66-byte inputs drop the 2-byte size prefix, 67-byte inputs
// additionally drop the trailing sighash byte, 64-byte inputs pass through.
func AdjustSignature(sig []byte) (Signature, error) {
	var out Signature
	switch len(sig) {
	case 64:
		copy(out[:], sig)
	case 66:
		copy(out[:], sig[2:])
	case 67:
		copy(out[:], sig[2:66])
	default:
		return out, fmt.Errorf("invalid signature length %d", len(sig))
	}
	return out, nil
}
