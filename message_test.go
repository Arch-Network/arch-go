package arch

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// fixtureMessage is the message whose serialization and hash are pinned
// below. The expected values were generated with the reference TypeScript SDK
// (@arch-network/arch-sdk SanitizedMessageUtil.serialize / .hash), so this
// test proves cross-SDK byte-for-byte compatibility.
func fixtureMessage() SanitizedMessage {
	var key1 Pubkey
	for i := range key1 {
		key1[i] = byte(i + 1)
	}
	var blockhash Hash
	for i := range blockhash {
		blockhash[i] = 0xAA
	}
	data2 := make(Bytes, 10)
	for i := range data2 {
		data2[i] = byte(250 + i%6)
	}
	return SanitizedMessage{
		Header: MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys:     []Pubkey{key1, SystemProgramID},
		RecentBlockhash: blockhash,
		Instructions: []SanitizedInstruction{
			{ProgramIDIndex: 1, Accounts: Bytes{0}, Data: Bytes{1, 2, 3}},
			{ProgramIDIndex: 1, Accounts: Bytes{0, 1}, Data: data2},
		},
	}
}

const fixtureSerializedHex = "010001020000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000000000000000000000000000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200000001010000000003000000010203010200000000010a000000fafbfcfdfefffafbfcfd"

const fixtureHashUTF8 = "920c8cf815dda297d7fcd85d79a7b0856c96b488ed2eb11171f17d4ccee7b795"

func TestSerializeMessageMatchesTypeScriptSDK(t *testing.T) {
	got := hex.EncodeToString(fixtureMessage().Serialize())
	if got != fixtureSerializedHex {
		t.Errorf("serialized message mismatch:\n got  %s\n want %s", got, fixtureSerializedHex)
	}
}

func TestMessageHashMatchesTypeScriptSDK(t *testing.T) {
	got := fixtureMessage().Hash()
	if string(got) != fixtureHashUTF8 {
		t.Errorf("message hash mismatch:\n got  %s\n want %s", got, fixtureHashUTF8)
	}
	if len(got) != 64 {
		t.Errorf("hash must be the 64 ASCII bytes of a hex string, got %d bytes", len(got))
	}
}

func TestSerializeInstruction(t *testing.T) {
	ix := SanitizedInstruction{ProgramIDIndex: 1, Accounts: Bytes{0}, Data: Bytes{1, 2, 3}}
	want, _ := hex.DecodeString("010100000000" + "03000000" + "010203")
	if got := ix.Serialize(); !bytes.Equal(got, want) {
		t.Errorf("instruction serialization mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestSerializeInstructionEmpty(t *testing.T) {
	ix := SanitizedInstruction{ProgramIDIndex: 0, Accounts: Bytes{}, Data: Bytes{}}
	want, _ := hex.DecodeString("00" + "00000000" + "00000000")
	if got := ix.Serialize(); !bytes.Equal(got, want) {
		t.Errorf("empty instruction serialization mismatch:\n got  %x\n want %x", got, want)
	}
}
