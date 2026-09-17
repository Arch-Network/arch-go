package arch

import (
	"bytes"
	"testing"
)

func TestLoaderWrite(t *testing.T) {
	ix := LoaderWrite(pk(1), pk(2), 16, []byte{9, 8, 7})
	if ix.ProgramID != BpfLoaderProgramID {
		t.Error("wrong program id")
	}
	// Pinned by the TS SDK's loader-instructions test: discriminant 0,
	// offset u32 LE, u64 LE length, payload.
	want := []byte{
		0, 0, 0, 0,
		16, 0, 0, 0,
		3, 0, 0, 0, 0, 0, 0, 0,
		9, 8, 7,
	}
	if !bytes.Equal(ix.Data, want) {
		t.Errorf("data = %v, want %v", ix.Data, want)
	}
	assertMetas(t, ix.Accounts, []AccountMeta{
		{Pubkey: pk(1), IsSigner: false, IsWritable: true},
		{Pubkey: pk(2), IsSigner: true, IsWritable: false},
	})
}

func TestLoaderSimpleInstructions(t *testing.T) {
	cases := []struct {
		name string
		ix   Instruction
		data []byte
	}{
		{"truncate", LoaderTruncate(pk(1), pk(2), 4096), []byte{1, 0, 0, 0, 0, 16, 0, 0}},
		{"deploy", LoaderDeploy(pk(1), pk(2)), []byte{2, 0, 0, 0}},
		{"retract", LoaderRetract(pk(1), pk(2)), []byte{3, 0, 0, 0}},
		{"transfer_authority", LoaderTransferAuthority(pk(1), pk(2), pk(3)), []byte{4, 0, 0, 0}},
		{"finalize", LoaderFinalize(pk(1), pk(2), pk(3)), []byte{5, 0, 0, 0}},
	}
	for _, tc := range cases {
		if tc.ix.ProgramID != BpfLoaderProgramID {
			t.Errorf("%s: wrong program id", tc.name)
		}
		if !bytes.Equal(tc.ix.Data, tc.data) {
			t.Errorf("%s: data = %v, want %v", tc.name, tc.ix.Data, tc.data)
		}
	}

	// Account flag spot-checks against loader_instruction.rs.
	truncate := LoaderTruncate(pk(1), pk(2), 1)
	assertMetas(t, truncate.Accounts, []AccountMeta{
		{Pubkey: pk(1), IsSigner: true, IsWritable: true},
		{Pubkey: pk(2), IsSigner: true, IsWritable: false},
	})
	deploy := LoaderDeploy(pk(1), pk(2))
	assertMetas(t, deploy.Accounts, []AccountMeta{
		{Pubkey: pk(1), IsSigner: false, IsWritable: true},
		{Pubkey: pk(2), IsSigner: true, IsWritable: false},
	})
	finalize := LoaderFinalize(pk(1), pk(2), pk(3))
	assertMetas(t, finalize.Accounts, []AccountMeta{
		{Pubkey: pk(1), IsSigner: true, IsWritable: true},
		{Pubkey: pk(2), IsSigner: true, IsWritable: false},
		{Pubkey: pk(3), IsSigner: false, IsWritable: false},
	})
}

func TestExtendBytesMaxLenFillsTxSizeLimit(t *testing.T) {
	maxLen, err := ExtendBytesMaxLen()
	if err != nil {
		t.Fatal(err)
	}
	if maxLen <= 0 || maxLen >= RuntimeTxSizeLimit {
		t.Fatalf("maxLen = %d, want within (0, %d)", maxLen, RuntimeTxSizeLimit)
	}

	// A Write carrying exactly maxLen bytes must serialize to exactly the
	// transaction size limit (mirrors the TS SDK test).
	var program, authority Pubkey
	for i := range program {
		program[i] = 1
		authority[i] = 2
	}
	message, err := NewSanitizedMessage(
		[]Instruction{LoaderWrite(program, authority, 0, make([]byte, maxLen))},
		nil,
		Hash{},
	)
	if err != nil {
		t.Fatal(err)
	}
	tx := RuntimeTransaction{
		Version:    RuntimeTxVersion,
		Signatures: []Signature{{}},
		Message:    message,
	}
	if got := len(tx.Serialize()); got != RuntimeTxSizeLimit {
		t.Errorf("serialized size = %d, want %d", got, RuntimeTxSizeLimit)
	}
}
