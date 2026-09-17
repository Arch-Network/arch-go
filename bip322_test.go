package arch

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// The taproot test vector from the rust bip322 crate (the exact BIP-322
// implementation the Arch node depends on; see its
// simple_verify_and_falsify_taproot test): private key
// L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k, address
// bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3,
// message "Hello World".
const (
	bip322VectorWIF     = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
	bip322VectorAddress = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3"
	bip322VectorMessage = "Hello World"
	// Full witness serialization: [item count 0x01][length 0x41][65-byte sig].
	bip322VectorSigB64 = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ=="
)

func TestP2TRAddressMatchesBIP322Vector(t *testing.T) {
	wif, err := btcutil.DecodeWIF(bip322VectorWIF)
	if err != nil {
		t.Fatal(err)
	}
	pubkey := XOnlyPubkey(wif.PrivKey)
	addr, err := P2TRAddress(pubkey, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr != bip322VectorAddress {
		t.Errorf("address = %s, want %s", addr, bip322VectorAddress)
	}
}

func TestVerifyMessageBIP322KnownVector(t *testing.T) {
	wif, err := btcutil.DecodeWIF(bip322VectorWIF)
	if err != nil {
		t.Fatal(err)
	}
	pubkey := XOnlyPubkey(wif.PrivKey)

	raw, err := base64.StdEncoding.DecodeString(bip322VectorSigB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 67 || raw[0] != 0x01 || raw[1] != 0x41 {
		t.Fatalf("unexpected witness encoding: %x", raw)
	}
	if raw[66] != 0x01 {
		t.Fatalf("expected SIGHASH_ALL byte, got %#x", raw[66])
	}
	var sig Signature
	copy(sig[:], raw[2:66])

	if err := VerifyMessageBIP322([]byte(bip322VectorMessage), pubkey, sig, true); err != nil {
		t.Errorf("known-good BIP-322 signature failed to verify: %v", err)
	}

	// Same signature over a different message must fail.
	if err := VerifyMessageBIP322([]byte("Hello World - this should fail"), pubkey, sig, true); err == nil {
		t.Error("signature verified against the wrong message")
	}
}

func TestSignMessageBIP322RoundTrip(t *testing.T) {
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey := XOnlyPubkey(priv)
	msg := []byte("arch-go bip322 round trip")

	sig, err := SignMessageBIP322(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessageBIP322(msg, pubkey, sig, true); err != nil {
		t.Errorf("own signature failed to verify: %v", err)
	}

	// Tampered signature must fail.
	bad := sig
	bad[0] ^= 0xFF
	if err := VerifyMessageBIP322(msg, pubkey, bad, true); err == nil {
		t.Error("tampered signature verified")
	}

	// Wrong key must fail.
	other, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessageBIP322(msg, XOnlyPubkey(other), sig, true); err == nil {
		t.Error("signature verified under the wrong pubkey")
	}
}

func TestBuildAndSignTransaction(t *testing.T) {
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := XOnlyPubkey(priv)
	to := pk(3)

	msg, err := NewSanitizedMessage([]Instruction{Transfer(payer, to, 1000)}, &payer, Hash{0xCC})
	if err != nil {
		t.Fatal(err)
	}

	tx, err := BuildAndSignTransaction(msg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Version != 0 {
		t.Errorf("version = %d, want 0", tx.Version)
	}
	if len(tx.Signatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(tx.Signatures))
	}
	// The signature must be a valid BIP-322 signature over the message hash.
	if err := VerifyMessageBIP322(msg.Hash(), payer, tx.Signatures[0], true); err != nil {
		t.Errorf("transaction signature failed BIP-322 verification: %v", err)
	}
}

func TestBuildAndSignTransactionMissingSigner(t *testing.T) {
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := pk(77) // not the pubkey of priv
	msg, err := NewSanitizedMessage([]Instruction{Transfer(payer, pk(3), 1)}, &payer, Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAndSignTransaction(msg, priv); err == nil {
		t.Error("expected missing-signer error, got nil")
	}
}

func TestAdjustSignature(t *testing.T) {
	base := make([]byte, 64)
	for i := range base {
		base[i] = byte(i)
	}

	// 64 bytes: passthrough.
	got, err := AdjustSignature(base)
	if err != nil || got[:][0] != 0 || got[63] != 63 {
		t.Errorf("64-byte adjust failed: %v %v", got, err)
	}

	// 66 bytes: strip 2-byte size prefix.
	in66 := append([]byte{0xDE, 0xAD}, base...)
	got, err = AdjustSignature(in66)
	if err != nil || got[0] != 0 || got[63] != 63 {
		t.Errorf("66-byte adjust failed: %v %v", got, err)
	}

	// 67 bytes: strip prefix and trailing sighash byte.
	in67 := append(append([]byte{0xDE, 0xAD}, base...), 0x01)
	got, err = AdjustSignature(in67)
	if err != nil || got[0] != 0 || got[63] != 63 {
		t.Errorf("67-byte adjust failed: %v %v", got, err)
	}

	// Anything else: error.
	if _, err := AdjustSignature(make([]byte, 65)); err == nil {
		t.Error("expected error for 65-byte signature")
	}
}
