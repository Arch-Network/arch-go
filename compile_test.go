package arch

import (
	"testing"
)

func pk(b byte) Pubkey {
	var p Pubkey
	p[0] = b
	return p
}

func TestNewSanitizedMessageTransfer(t *testing.T) {
	payer := pk(9)
	to := pk(3)
	blockhash := Hash{0xBB}

	ix := Transfer(payer, to, 500)
	msg, err := NewSanitizedMessage([]Instruction{ix}, &payer, blockhash)
	if err != nil {
		t.Fatal(err)
	}

	// payer (writable signer) first, then `to` (writable non-signer), then
	// the system program (readonly non-signer).
	wantKeys := []Pubkey{payer, to, SystemProgramID}
	if len(msg.AccountKeys) != len(wantKeys) {
		t.Fatalf("got %d account keys, want %d", len(msg.AccountKeys), len(wantKeys))
	}
	for i, want := range wantKeys {
		if msg.AccountKeys[i] != want {
			t.Errorf("account_keys[%d] = %s, want %s", i, msg.AccountKeys[i], want)
		}
	}

	wantHeader := MessageHeader{NumRequiredSignatures: 1, NumReadonlySignedAccounts: 0, NumReadonlyUnsignedAccounts: 1}
	if msg.Header != wantHeader {
		t.Errorf("header = %+v, want %+v", msg.Header, wantHeader)
	}

	if msg.RecentBlockhash != blockhash {
		t.Errorf("recent_blockhash not preserved")
	}

	compiled := msg.Instructions[0]
	if compiled.ProgramIDIndex != 2 {
		t.Errorf("program_id_index = %d, want 2", compiled.ProgramIDIndex)
	}
	if len(compiled.Accounts) != 2 || compiled.Accounts[0] != 0 || compiled.Accounts[1] != 1 {
		t.Errorf("accounts = %v, want [0 1]", compiled.Accounts)
	}
}

// Keys within each group must be sorted byte-wise, matching the Rust
// implementation's BTreeMap (arch_program::compiled_keys).
func TestNewSanitizedMessageSortsKeysWithinGroups(t *testing.T) {
	payer := pk(200) // sorts last, but must still be first as payer
	program := pk(150)
	ix := Instruction{
		ProgramID: program,
		Accounts: []AccountMeta{
			{Pubkey: pk(5), IsSigner: true, IsWritable: true},
			{Pubkey: pk(2), IsSigner: true, IsWritable: true},
			{Pubkey: pk(80), IsSigner: false, IsWritable: true},
			{Pubkey: pk(70), IsSigner: false, IsWritable: true},
			{Pubkey: pk(40), IsSigner: true, IsWritable: false},
		},
		Data: Bytes{1},
	}

	msg, err := NewSanitizedMessage([]Instruction{ix}, &payer, Hash{})
	if err != nil {
		t.Fatal(err)
	}

	wantKeys := []Pubkey{
		payer,   // payer always first
		pk(2),   // writable signers, sorted
		pk(5),   //
		pk(40),  // readonly signers
		pk(70),  // writable non-signers, sorted
		pk(80),  //
		program, // readonly non-signers (invoked program)
	}
	if len(msg.AccountKeys) != len(wantKeys) {
		t.Fatalf("got %d keys, want %d", len(msg.AccountKeys), len(wantKeys))
	}
	for i, want := range wantKeys {
		if msg.AccountKeys[i] != want {
			t.Errorf("account_keys[%d] = %s, want %s", i, msg.AccountKeys[i], want)
		}
	}

	wantHeader := MessageHeader{NumRequiredSignatures: 4, NumReadonlySignedAccounts: 1, NumReadonlyUnsignedAccounts: 1}
	if msg.Header != wantHeader {
		t.Errorf("header = %+v, want %+v", msg.Header, wantHeader)
	}
}

// Duplicate account metas must merge with OR-ed flags, as in the Rust
// test_compile_with_dups.
func TestNewSanitizedMessageMergesDuplicates(t *testing.T) {
	program := pk(100)
	id0 := pk(1)
	ix := Instruction{
		ProgramID: program,
		Accounts: []AccountMeta{
			{Pubkey: id0, IsSigner: false, IsWritable: false},
			{Pubkey: id0, IsSigner: true, IsWritable: false},
			{Pubkey: id0, IsSigner: false, IsWritable: true},
		},
		Data: Bytes{},
	}

	msg, err := NewSanitizedMessage([]Instruction{ix}, nil, Hash{})
	if err != nil {
		t.Fatal(err)
	}
	// id0 ends up signer+writable; program readonly non-signer.
	wantKeys := []Pubkey{id0, program}
	for i, want := range wantKeys {
		if msg.AccountKeys[i] != want {
			t.Errorf("account_keys[%d] = %s, want %s", i, msg.AccountKeys[i], want)
		}
	}
	wantHeader := MessageHeader{NumRequiredSignatures: 1, NumReadonlySignedAccounts: 0, NumReadonlyUnsignedAccounts: 1}
	if msg.Header != wantHeader {
		t.Errorf("header = %+v, want %+v", msg.Header, wantHeader)
	}
	// All three metas reference index 0.
	acc := msg.Instructions[0].Accounts
	if len(acc) != 3 || acc[0] != 0 || acc[1] != 0 || acc[2] != 0 {
		t.Errorf("accounts = %v, want [0 0 0]", acc)
	}
}

func TestNewSanitizedMessageOverflow(t *testing.T) {
	// 257 distinct writable non-signer accounts + program + payer > 256 keys.
	accounts := make([]AccountMeta, 257)
	for i := range accounts {
		var key Pubkey
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		key[31] = 1 // avoid colliding with payer/program
		accounts[i] = AccountMeta{Pubkey: key, IsSigner: false, IsWritable: true}
	}
	payer := pk(255)
	ix := Instruction{ProgramID: pk(254), Accounts: accounts, Data: Bytes{}}
	if _, err := NewSanitizedMessage([]Instruction{ix}, &payer, Hash{}); err == nil {
		t.Error("expected account index overflow error, got nil")
	}
}
