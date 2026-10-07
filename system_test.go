package arch

import (
	"encoding/hex"
	"testing"
)

// Expected data layouts computed from arch-network's
// program/src/system_instruction.rs: u32 LE discriminant, u64 LE integers,
// raw 32-byte pubkeys, u64-length-prefixed strings.

func checkInstruction(t *testing.T, got Instruction, wantDataHex string, wantAccounts []AccountMeta) {
	t.Helper()
	if got.ProgramID != SystemProgramID {
		t.Errorf("program_id = %s, want system program", got.ProgramID)
	}
	if gotData := hex.EncodeToString(got.Data); gotData != wantDataHex {
		t.Errorf("data mismatch:\n got  %s\n want %s", gotData, wantDataHex)
	}
	if len(got.Accounts) != len(wantAccounts) {
		t.Fatalf("got %d accounts, want %d", len(got.Accounts), len(wantAccounts))
	}
	for i, want := range wantAccounts {
		if got.Accounts[i] != want {
			t.Errorf("accounts[%d] = %+v, want %+v", i, got.Accounts[i], want)
		}
	}
}

func TestCreateAccount(t *testing.T) {
	from, to := pk(1), pk(2)
	ix := CreateAccount(from, to, 1000, 128, TokenProgramID)
	wantData := "00000000" + // discriminant 0
		"e803000000000000" + // lamports 1000
		"8000000000000000" + // space 128
		hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: from, IsSigner: true, IsWritable: true},
		{Pubkey: to, IsSigner: true, IsWritable: true},
	})
}

func TestAssign(t *testing.T) {
	acct := pk(4)
	ix := Assign(acct, TokenProgramID)
	wantData := "01000000" + hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: acct, IsSigner: true, IsWritable: true},
	})
}

func TestSignInput(t *testing.T) {
	signer := pk(4)
	ix := SignInput(3, signer)
	checkInstruction(t, ix, "02000000"+"03000000", []AccountMeta{
		{Pubkey: signer, IsSigner: true, IsWritable: true},
	})
}

func TestTransfer(t *testing.T) {
	from, to := pk(1), pk(2)
	ix := Transfer(from, to, 500)
	checkInstruction(t, ix, "03000000"+"f401000000000000", []AccountMeta{
		{Pubkey: from, IsSigner: true, IsWritable: true},
		{Pubkey: to, IsSigner: false, IsWritable: true},
	})
}

func TestAllocate(t *testing.T) {
	acct := pk(4)
	ix := Allocate(acct, 256)
	checkInstruction(t, ix, "04000000"+"0001000000000000", []AccountMeta{
		{Pubkey: acct, IsSigner: true, IsWritable: true},
	})
}

func TestCreateAccountWithSeed(t *testing.T) {
	from, to, base := pk(1), pk(2), pk(3)
	ix := CreateAccountWithSeed(from, to, base, "seed", 10, 20, TokenProgramID)
	wantData := "05000000" +
		hex.EncodeToString(base[:]) +
		"0400000000000000" + hex.EncodeToString([]byte("seed")) +
		"0a00000000000000" +
		"1400000000000000" +
		hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: from, IsSigner: true, IsWritable: true},
		{Pubkey: to, IsSigner: false, IsWritable: true},
		{Pubkey: base, IsSigner: true, IsWritable: false},
	})

	// When base == from, the third account meta is omitted.
	ix = CreateAccountWithSeed(from, to, from, "seed", 10, 20, TokenProgramID)
	if len(ix.Accounts) != 2 {
		t.Errorf("got %d accounts, want 2 when base == from", len(ix.Accounts))
	}
}

func TestAllocateWithSeed(t *testing.T) {
	addr, base := pk(1), pk(2)
	ix := AllocateWithSeed(addr, base, "s", 32, TokenProgramID)
	wantData := "06000000" +
		hex.EncodeToString(base[:]) +
		"0100000000000000" + hex.EncodeToString([]byte("s")) +
		"2000000000000000" +
		hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: addr, IsSigner: false, IsWritable: true},
		{Pubkey: base, IsSigner: true, IsWritable: false},
	})
}

func TestAssignWithSeed(t *testing.T) {
	addr, base := pk(1), pk(2)
	ix := AssignWithSeed(addr, base, "s", TokenProgramID)
	wantData := "07000000" +
		hex.EncodeToString(base[:]) +
		"0100000000000000" + hex.EncodeToString([]byte("s")) +
		hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: addr, IsSigner: false, IsWritable: true},
		{Pubkey: base, IsSigner: true, IsWritable: false},
	})
}

func TestTransferWithSeed(t *testing.T) {
	from, fromBase, to := pk(1), pk(2), pk(3)
	ix := TransferWithSeed(from, fromBase, "s", TokenProgramID, to, 500)
	wantData := "08000000" +
		"f401000000000000" +
		"0100000000000000" + hex.EncodeToString([]byte("s")) +
		hex.EncodeToString(TokenProgramID[:])
	checkInstruction(t, ix, wantData, []AccountMeta{
		{Pubkey: from, IsSigner: false, IsWritable: true},
		{Pubkey: fromBase, IsSigner: true, IsWritable: false},
		{Pubkey: to, IsSigner: false, IsWritable: true},
	})
}

func TestCreateNonceAccount(t *testing.T) {
	from, nonce, authority := pk(1), pk(2), pk(3)
	ixs := CreateNonceAccount(from, nonce, authority, 1000)
	if len(ixs) != 2 {
		t.Fatalf("got %d instructions, want 2", len(ixs))
	}
	checkInstruction(t, ixs[0], "00000000"+
		"e803000000000000"+
		"4400000000000000"+ // space 68
		hex.EncodeToString(SystemProgramID[:]), []AccountMeta{
		{Pubkey: from, IsSigner: true, IsWritable: true},
		{Pubkey: nonce, IsSigner: true, IsWritable: true},
	})
	checkInstruction(t, ixs[1], "0b000000"+hex.EncodeToString(authority[:]), []AccountMeta{
		{Pubkey: nonce, IsWritable: true},
	})
}

func TestAdvanceNonceAccount(t *testing.T) {
	nonce, authority := pk(1), pk(2)
	// arch-network's nonce.rs pins the advance tag at 9u32 LE.
	checkInstruction(t, AdvanceNonceAccount(nonce, authority), "09000000", []AccountMeta{
		{Pubkey: nonce, IsWritable: true},
		{Pubkey: authority, IsSigner: true},
	})
}

func TestWithdrawNonceAccount(t *testing.T) {
	nonce, authority, to := pk(1), pk(2), pk(3)
	ix := WithdrawNonceAccount(nonce, authority, to, 500)
	checkInstruction(t, ix, "0a000000"+"f401000000000000", []AccountMeta{
		{Pubkey: nonce, IsWritable: true},
		{Pubkey: to, IsWritable: true},
		{Pubkey: authority, IsSigner: true},
	})
}

func TestAuthorizeNonceAccount(t *testing.T) {
	nonce, authority, newAuthority := pk(1), pk(2), pk(3)
	ix := AuthorizeNonceAccount(nonce, authority, newAuthority)
	checkInstruction(t, ix, "0c000000"+hex.EncodeToString(newAuthority[:]), []AccountMeta{
		{Pubkey: nonce, IsWritable: true},
		{Pubkey: authority, IsSigner: true},
	})
}
