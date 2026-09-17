package arch

import (
	"encoding/hex"
	"testing"
)

// Expected data layouts computed from apl-token's instruction.rs (an SPL
// Token fork): 1-byte discriminant, u64 LE amounts, raw 32-byte pubkeys,
// Option<Pubkey> as a 0/1 tag byte.

func assertMetas(t *testing.T, got, want []AccountMeta) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d accounts, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("accounts[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func checkTokenInstruction(t *testing.T, got Instruction, wantDataHex string, wantAccounts []AccountMeta) {
	t.Helper()
	if got.ProgramID != TokenProgramID {
		t.Errorf("program_id = %s, want token program", got.ProgramID)
	}
	if gotData := hex.EncodeToString(got.Data); gotData != wantDataHex {
		t.Errorf("data mismatch:\n got  %s\n want %s", gotData, wantDataHex)
	}
	assertMetas(t, got.Accounts, wantAccounts)
}

func TestTokenInitializeMint(t *testing.T) {
	mint, authority, freeze := pk(1), pk(2), pk(3)

	withFreeze := TokenInitializeMint(mint, authority, &freeze, 9)
	checkTokenInstruction(t, withFreeze,
		"0009"+authority.String()+"01"+freeze.String(),
		[]AccountMeta{{Pubkey: mint, IsWritable: true}},
	)

	noFreeze := TokenInitializeMint(mint, authority, nil, 6)
	checkTokenInstruction(t, noFreeze,
		"0006"+authority.String()+"00",
		[]AccountMeta{{Pubkey: mint, IsWritable: true}},
	)

	mint2 := TokenInitializeMint2(mint, authority, nil, 6)
	if mint2.Data[0] != 19 {
		t.Errorf("initialize_mint2 discriminant = %d, want 19", mint2.Data[0])
	}
}

func TestTokenInitializeAccountVariants(t *testing.T) {
	account, mint, owner := pk(1), pk(2), pk(3)

	checkTokenInstruction(t, TokenInitializeAccount(account, mint, owner),
		"01",
		[]AccountMeta{
			{Pubkey: account, IsWritable: true},
			{Pubkey: mint},
			{Pubkey: owner},
		},
	)

	checkTokenInstruction(t, TokenInitializeAccount2(account, mint, owner),
		"10"+owner.String(),
		[]AccountMeta{
			{Pubkey: account, IsWritable: true},
			{Pubkey: mint},
		},
	)

	checkTokenInstruction(t, TokenInitializeAccount3(account, mint, owner),
		"12"+owner.String(),
		[]AccountMeta{
			{Pubkey: account, IsWritable: true},
			{Pubkey: mint},
		},
	)
}

func TestTokenInitializeMultisig(t *testing.T) {
	checkTokenInstruction(t, TokenInitializeMultisig(pk(1), []Pubkey{pk(2), pk(3)}, 2),
		"0202",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3)},
		},
	)
}

func TestTokenTransfer(t *testing.T) {
	// Single owner: authority signs.
	checkTokenInstruction(t, TokenTransfer(pk(1), pk(2), pk(3), nil, 5000),
		"03"+"8813000000000000",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	// Multisig owner: authority is readonly non-signer, listed keys sign.
	checkTokenInstruction(t, TokenTransfer(pk(1), pk(2), pk(3), []Pubkey{pk(4), pk(5)}, 1),
		"03"+"0100000000000000",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3)},
			{Pubkey: pk(4), IsSigner: true},
			{Pubkey: pk(5), IsSigner: true},
		},
	)
}

func TestTokenTransferChecked(t *testing.T) {
	checkTokenInstruction(t, TokenTransferChecked(pk(1), pk(2), pk(3), pk(4), nil, 5000, 9),
		"0c"+"8813000000000000"+"09",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3), IsWritable: true},
			{Pubkey: pk(4), IsSigner: true},
		},
	)
}

func TestTokenApproveAndRevoke(t *testing.T) {
	checkTokenInstruction(t, TokenApprove(pk(1), pk(2), pk(3), nil, 77),
		"04"+"4d00000000000000",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenApproveChecked(pk(1), pk(2), pk(3), pk(4), nil, 77, 6),
		"0d"+"4d00000000000000"+"06",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3)},
			{Pubkey: pk(4), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenRevoke(pk(1), pk(2), nil),
		"05",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsSigner: true},
		},
	)
}

func TestTokenSetAuthority(t *testing.T) {
	newAuth := pk(9)
	checkTokenInstruction(t, TokenSetAuthority(pk(1), &newAuth, AuthorityAccountOwner, pk(2), nil),
		"0602"+"01"+newAuth.String(),
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsSigner: true},
		},
	)

	// Removing the authority: Option::None tag.
	checkTokenInstruction(t, TokenSetAuthority(pk(1), nil, AuthorityMintTokens, pk(2), nil),
		"0600"+"00",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsSigner: true},
		},
	)
}

func TestTokenMintToAndBurn(t *testing.T) {
	checkTokenInstruction(t, TokenMintTo(pk(1), pk(2), pk(3), nil, 1_000_000),
		"07"+"40420f0000000000",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenMintToChecked(pk(1), pk(2), pk(3), nil, 1_000_000, 6),
		"0e"+"40420f0000000000"+"06",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenBurn(pk(1), pk(2), pk(3), nil, 42),
		"08"+"2a00000000000000",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenBurnChecked(pk(1), pk(2), pk(3), nil, 42, 9),
		"0f"+"2a00000000000000"+"09",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)
}

func TestTokenAccountLifecycle(t *testing.T) {
	checkTokenInstruction(t, TokenCloseAccount(pk(1), pk(2), pk(3), nil),
		"09",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2), IsWritable: true},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenFreezeAccount(pk(1), pk(2), pk(3), nil),
		"0a",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenThawAccount(pk(1), pk(2), pk(3), nil),
		"0b",
		[]AccountMeta{
			{Pubkey: pk(1), IsWritable: true},
			{Pubkey: pk(2)},
			{Pubkey: pk(3), IsSigner: true},
		},
	)

	checkTokenInstruction(t, TokenSyncNative(pk(1)),
		"11",
		[]AccountMeta{{Pubkey: pk(1), IsWritable: true}},
	)
}

func TestCreateAssociatedTokenAccount(t *testing.T) {
	funder, wallet, mint := pk(1), pk(7), pk(9)
	ata, _, err := AssociatedTokenAddress(wallet, mint)
	if err != nil {
		t.Fatal(err)
	}

	ix := CreateAssociatedTokenAccount(funder, ata, wallet, mint)
	if ix.ProgramID != AssociatedTokenProgramID {
		t.Error("wrong program id")
	}
	if len(ix.Data) != 0 {
		t.Errorf("data = %v, want empty", ix.Data)
	}
	assertMetas(t, ix.Accounts, []AccountMeta{
		{Pubkey: funder, IsSigner: true, IsWritable: true},
		{Pubkey: ata, IsWritable: true},
		{Pubkey: wallet},
		{Pubkey: mint},
		{Pubkey: SystemProgramID},
		{Pubkey: TokenProgramID},
	})
}

func TestCreateAssociatedTokenAccountWithAnchor(t *testing.T) {
	txid := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	ix, err := CreateAssociatedTokenAccountWithAnchor(pk(1), pk(2), pk(7), pk(9), txid, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantData := txid + "03000000"
	if got := hex.EncodeToString(ix.Data); got != wantData {
		t.Errorf("data = %s, want %s", got, wantData)
	}

	if _, err := CreateAssociatedTokenAccountWithAnchor(pk(1), pk(2), pk(7), pk(9), "beef", 0); err == nil {
		t.Error("expected error for short txid")
	}
}
