package arch

// BIP-322 generic signed message support, restricted to taproot key-spend —
// the only address type Arch account keys use. This is a port of
// arch-network's sdk/src/helper/bip322.rs.
//
// The scheme (https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
// builds two virtual Bitcoin transactions:
//
//   - "to_spend": an unspendable transaction whose input commits to
//     tagged_hash("BIP0322-signed-message", msg) and whose output pays to the
//     signer's address.
//   - "to_sign": a transaction spending that output to OP_RETURN.
//
// The signature is the taproot key-spend witness of to_sign, using
// SIGHASH_ALL. Arch transports only the first 64 bytes (the Schnorr
// signature, without the sighash byte).

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var bip322Tag = []byte("BIP0322-signed-message")

// p2trScript returns the P2TR output script (OP_1 <32-byte tweaked key>) for
// an x-only internal key with no script tree. The script is identical on
// every Bitcoin network, which is why signing needs no network parameter.
func p2trScript(pubkey Pubkey) ([]byte, error) {
	internalKey, err := schnorr.ParsePubKey(pubkey[:])
	if err != nil {
		return nil, fmt.Errorf("invalid x-only pubkey: %w", err)
	}
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	return txscript.PayToTaprootScript(taprootKey)
}

// buildToSpend constructs the BIP-322 "to_spend" transaction for a message
// and an output script.
func buildToSpend(script []byte, msg []byte) (*wire.MsgTx, error) {
	msgHash := chainhash.TaggedHash(bip322Tag, msg)
	scriptSig, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(msgHash[:]).
		Script()
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(0)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: wire.MaxPrevOutIndex},
		SignatureScript:  scriptSig,
		Sequence:         0,
	})
	tx.AddTxOut(wire.NewTxOut(0, script))
	return tx, nil
}

// buildToSign constructs the BIP-322 "to_sign" transaction spending
// to_spend's output to OP_RETURN.
func buildToSign(toSpend *wire.MsgTx) *wire.MsgTx {
	tx := wire.NewMsgTx(0)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: toSpend.TxHash(), Index: 0},
		Sequence:         0,
	})
	tx.AddTxOut(wire.NewTxOut(0, []byte{txscript.OP_RETURN}))
	return tx
}

// SignMessageBIP322 signs msg with the private key following BIP-322
// (taproot key-spend, SIGHASH_ALL) and returns the 64-byte Schnorr
// signature, mirroring arch-network's sign_message_bip322. For an Arch
// transaction, msg must be SanitizedMessage.Hash().
func SignMessageBIP322(priv *btcec.PrivateKey, msg []byte) (Signature, error) {
	var sig Signature

	script, err := p2trScript(XOnlyPubkey(priv))
	if err != nil {
		return sig, err
	}
	toSpend, err := buildToSpend(script, msg)
	if err != nil {
		return sig, err
	}
	toSign := buildToSign(toSpend)

	fetcher := txscript.NewCannedPrevOutputFetcher(script, 0)
	sigHashes := txscript.NewTxSigHashes(toSign, fetcher)
	// Empty tapscript root hash = BIP-86 style key tweak with no script tree,
	// matching the Rust side's tap_tweak(None).
	rawSig, err := txscript.RawTxInTaprootSignature(
		toSign, sigHashes, 0, 0, script, []byte{}, txscript.SigHashAll, priv,
	)
	if err != nil {
		return sig, fmt.Errorf("taproot signing failed: %w", err)
	}
	// SigHashAll appends the sighash byte; the Arch wire format carries only
	// the 64-byte Schnorr signature.
	if len(rawSig) < 64 {
		return sig, fmt.Errorf("unexpected signature length %d", len(rawSig))
	}
	copy(sig[:], rawSig[:64])
	return sig, nil
}

// VerifyMessageBIP322 verifies a 64-byte BIP-322 signature over msg for an
// x-only pubkey, mirroring arch-network's verify_message_bip322. Set
// usesSighashAll to true for signatures produced by SignMessageBIP322 and by
// the Arch SDKs (they always sign with SIGHASH_ALL).
func VerifyMessageBIP322(msg []byte, pubkey Pubkey, sig Signature, usesSighashAll bool) error {
	script, err := p2trScript(pubkey)
	if err != nil {
		return err
	}
	toSpend, err := buildToSpend(script, msg)
	if err != nil {
		return err
	}
	toSign := buildToSign(toSpend)

	witnessSig := sig[:]
	if usesSighashAll {
		witnessSig = append(witnessSig, byte(txscript.SigHashAll))
	}
	toSign.TxIn[0].Witness = wire.TxWitness{witnessSig}

	fetcher := txscript.NewCannedPrevOutputFetcher(script, 0)
	sigHashes := txscript.NewTxSigHashes(toSign, fetcher)
	vm, err := txscript.NewEngine(
		script, toSign, 0, txscript.StandardVerifyFlags, nil, sigHashes, 0, fetcher,
	)
	if err != nil {
		return err
	}
	if err := vm.Execute(); err != nil {
		return fmt.Errorf("BIP-322 verification failed: %w", err)
	}
	return nil
}
