package arch

// APL token program instruction builders, mirroring apl-token's
// instruction.rs (an SPL Token fork). Data layouts: 1-byte discriminant,
// u64 LE amounts, raw 32-byte pubkeys, and Option<Pubkey> as a 0/1 tag byte
// optionally followed by 32 key bytes.
//
// For instructions with an owner/authority, pass nil multisigSigners when the
// authority is a single key (it will be marked as the signer); pass the
// signer set when the authority is a multisig account (the authority is then
// readonly non-signer and each listed key signs).

import "encoding/binary"

// Token instruction discriminants, in apl-token enum order.
const (
	tokInitializeMint     byte = 0
	tokInitializeAccount  byte = 1
	tokInitializeMultisig byte = 2
	tokTransfer           byte = 3
	tokApprove            byte = 4
	tokRevoke             byte = 5
	tokSetAuthority       byte = 6
	tokMintTo             byte = 7
	tokBurn               byte = 8
	tokCloseAccount       byte = 9
	tokFreezeAccount      byte = 10
	tokThawAccount        byte = 11
	tokTransferChecked    byte = 12
	tokApproveChecked     byte = 13
	tokMintToChecked      byte = 14
	tokBurnChecked        byte = 15
	tokInitializeAccount2 byte = 16
	tokSyncNative         byte = 17
	tokInitializeAccount3 byte = 18
	tokInitializeMint2    byte = 19
)

// AuthorityType selects which authority TokenSetAuthority changes.
type AuthorityType uint8

// AuthorityType values, in apl-token enum order.
const (
	AuthorityMintTokens    AuthorityType = 0
	AuthorityFreezeAccount AuthorityType = 1
	AuthorityAccountOwner  AuthorityType = 2
	AuthorityCloseAccount  AuthorityType = 3
)

func appendOptionalPubkey(data []byte, key *Pubkey) []byte {
	if key == nil {
		return append(data, 0)
	}
	data = append(data, 1)
	return append(data, key[:]...)
}

// authorityAccounts appends the owner/authority meta followed by any multisig
// signer metas, mirroring the apl-token builder convention.
func authorityAccounts(accounts []AccountMeta, authority Pubkey, multisigSigners []Pubkey) []AccountMeta {
	accounts = append(accounts, AccountMeta{
		Pubkey:   authority,
		IsSigner: len(multisigSigners) == 0,
	})
	for _, signer := range multisigSigners {
		accounts = append(accounts, AccountMeta{Pubkey: signer, IsSigner: true})
	}
	return accounts
}

// TokenInitializeMint initializes a new mint. freezeAuthority may be nil.
func TokenInitializeMint(mint, mintAuthority Pubkey, freezeAuthority *Pubkey, decimals uint8) Instruction {
	data := []byte{tokInitializeMint, decimals}
	data = append(data, mintAuthority[:]...)
	data = appendOptionalPubkey(data, freezeAuthority)
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  []AccountMeta{{Pubkey: mint, IsWritable: true}},
		Data:      data,
	}
}

// TokenInitializeMint2 is InitializeMint with a different discriminant,
// matching apl-token's initialize_mint2.
func TokenInitializeMint2(mint, mintAuthority Pubkey, freezeAuthority *Pubkey, decimals uint8) Instruction {
	ix := TokenInitializeMint(mint, mintAuthority, freezeAuthority, decimals)
	ix.Data[0] = tokInitializeMint2
	return ix
}

// TokenInitializeAccount initializes a token account for mint owned by owner.
func TokenInitializeAccount(account, mint, owner Pubkey) Instruction {
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts: []AccountMeta{
			{Pubkey: account, IsWritable: true},
			{Pubkey: mint},
			{Pubkey: owner},
		},
		Data: []byte{tokInitializeAccount},
	}
}

// TokenInitializeAccount2 initializes a token account with the owner passed
// in instruction data.
func TokenInitializeAccount2(account, mint, owner Pubkey) Instruction {
	data := []byte{tokInitializeAccount2}
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts: []AccountMeta{
			{Pubkey: account, IsWritable: true},
			{Pubkey: mint},
		},
		Data: data,
	}
}

// TokenInitializeAccount3 is InitializeAccount2 with a different
// discriminant, matching apl-token's initialize_account3.
func TokenInitializeAccount3(account, mint, owner Pubkey) Instruction {
	ix := TokenInitializeAccount2(account, mint, owner)
	ix.Data[0] = tokInitializeAccount3
	return ix
}

// TokenInitializeMultisig initializes a multisig account requiring m of the
// given signers.
func TokenInitializeMultisig(multisig Pubkey, signers []Pubkey, m uint8) Instruction {
	accounts := []AccountMeta{{Pubkey: multisig, IsWritable: true}}
	for _, signer := range signers {
		accounts = append(accounts, AccountMeta{Pubkey: signer})
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  accounts,
		Data:      []byte{tokInitializeMultisig, m},
	}
}

// TokenTransfer transfers amount tokens from source to destination.
func TokenTransfer(source, destination, authority Pubkey, multisigSigners []Pubkey, amount uint64) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokTransfer}, amount)
	accounts := []AccountMeta{
		{Pubkey: source, IsWritable: true},
		{Pubkey: destination, IsWritable: true},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, authority, multisigSigners),
		Data:      data,
	}
}

// TokenTransferChecked is TokenTransfer with a mint account and decimals
// check.
func TokenTransferChecked(source, mint, destination, authority Pubkey, multisigSigners []Pubkey, amount uint64, decimals uint8) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokTransferChecked}, amount)
	data = append(data, decimals)
	accounts := []AccountMeta{
		{Pubkey: source, IsWritable: true},
		{Pubkey: mint},
		{Pubkey: destination, IsWritable: true},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, authority, multisigSigners),
		Data:      data,
	}
}

// TokenApprove approves a delegate for amount tokens of source.
func TokenApprove(source, delegate, owner Pubkey, multisigSigners []Pubkey, amount uint64) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokApprove}, amount)
	accounts := []AccountMeta{
		{Pubkey: source, IsWritable: true},
		{Pubkey: delegate},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, owner, multisigSigners),
		Data:      data,
	}
}

// TokenApproveChecked is TokenApprove with a mint account and decimals check.
func TokenApproveChecked(source, mint, delegate, owner Pubkey, multisigSigners []Pubkey, amount uint64, decimals uint8) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokApproveChecked}, amount)
	data = append(data, decimals)
	accounts := []AccountMeta{
		{Pubkey: source, IsWritable: true},
		{Pubkey: mint},
		{Pubkey: delegate},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, owner, multisigSigners),
		Data:      data,
	}
}

// TokenRevoke revokes the delegate of source.
func TokenRevoke(source, owner Pubkey, multisigSigners []Pubkey) Instruction {
	accounts := []AccountMeta{{Pubkey: source, IsWritable: true}}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, owner, multisigSigners),
		Data:      []byte{tokRevoke},
	}
}

// TokenSetAuthority changes an authority of a mint or token account.
// newAuthority may be nil to remove the authority.
func TokenSetAuthority(owned Pubkey, newAuthority *Pubkey, authorityType AuthorityType, currentAuthority Pubkey, multisigSigners []Pubkey) Instruction {
	data := []byte{tokSetAuthority, byte(authorityType)}
	data = appendOptionalPubkey(data, newAuthority)
	accounts := []AccountMeta{{Pubkey: owned, IsWritable: true}}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, currentAuthority, multisigSigners),
		Data:      data,
	}
}

// TokenMintTo mints amount tokens to account.
func TokenMintTo(mint, account, mintAuthority Pubkey, multisigSigners []Pubkey, amount uint64) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokMintTo}, amount)
	accounts := []AccountMeta{
		{Pubkey: mint, IsWritable: true},
		{Pubkey: account, IsWritable: true},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, mintAuthority, multisigSigners),
		Data:      data,
	}
}

// TokenMintToChecked is TokenMintTo with a decimals check.
func TokenMintToChecked(mint, account, mintAuthority Pubkey, multisigSigners []Pubkey, amount uint64, decimals uint8) Instruction {
	ix := TokenMintTo(mint, account, mintAuthority, multisigSigners, amount)
	ix.Data[0] = tokMintToChecked
	ix.Data = append(ix.Data, decimals)
	return ix
}

// TokenBurn burns amount tokens from account.
func TokenBurn(account, mint, authority Pubkey, multisigSigners []Pubkey, amount uint64) Instruction {
	data := binary.LittleEndian.AppendUint64([]byte{tokBurn}, amount)
	accounts := []AccountMeta{
		{Pubkey: account, IsWritable: true},
		{Pubkey: mint, IsWritable: true},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, authority, multisigSigners),
		Data:      data,
	}
}

// TokenBurnChecked is TokenBurn with a decimals check.
func TokenBurnChecked(account, mint, authority Pubkey, multisigSigners []Pubkey, amount uint64, decimals uint8) Instruction {
	ix := TokenBurn(account, mint, authority, multisigSigners, amount)
	ix.Data[0] = tokBurnChecked
	ix.Data = append(ix.Data, decimals)
	return ix
}

// TokenCloseAccount closes account, sending its remaining lamports to
// destination.
func TokenCloseAccount(account, destination, owner Pubkey, multisigSigners []Pubkey) Instruction {
	accounts := []AccountMeta{
		{Pubkey: account, IsWritable: true},
		{Pubkey: destination, IsWritable: true},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, owner, multisigSigners),
		Data:      []byte{tokCloseAccount},
	}
}

// TokenFreezeAccount freezes account.
func TokenFreezeAccount(account, mint, freezeAuthority Pubkey, multisigSigners []Pubkey) Instruction {
	accounts := []AccountMeta{
		{Pubkey: account, IsWritable: true},
		{Pubkey: mint},
	}
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  authorityAccounts(accounts, freezeAuthority, multisigSigners),
		Data:      []byte{tokFreezeAccount},
	}
}

// TokenThawAccount thaws a frozen account.
func TokenThawAccount(account, mint, freezeAuthority Pubkey, multisigSigners []Pubkey) Instruction {
	ix := TokenFreezeAccount(account, mint, freezeAuthority, multisigSigners)
	ix.Data[0] = tokThawAccount
	return ix
}

// TokenSyncNative synchronizes a native token account's balance with its
// lamports.
func TokenSyncNative(account Pubkey) Instruction {
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts:  []AccountMeta{{Pubkey: account, IsWritable: true}},
		Data:      []byte{tokSyncNative},
	}
}

// CreateAssociatedTokenAccount creates the associated token account for
// wallet and mint, funded by funder. The account address must be derived with
// AssociatedTokenAddress.
func CreateAssociatedTokenAccount(funder, associatedTokenAccount, wallet, mint Pubkey) Instruction {
	return Instruction{
		ProgramID: AssociatedTokenProgramID,
		Accounts: []AccountMeta{
			{Pubkey: funder, IsSigner: true, IsWritable: true},
			{Pubkey: associatedTokenAccount, IsWritable: true},
			{Pubkey: wallet},
			{Pubkey: mint},
			{Pubkey: SystemProgramID},
			{Pubkey: TokenProgramID},
		},
		Data: Bytes{},
	}
}

// CreateAssociatedTokenAccountWithAnchor is CreateAssociatedTokenAccount with
// the new account anchored to a Bitcoin UTXO.
func CreateAssociatedTokenAccountWithAnchor(funder, associatedTokenAccount, wallet, mint Pubkey, txid string, vout uint32) (Instruction, error) {
	txidBytes, err := decodeTxid(txid)
	if err != nil {
		return Instruction{}, err
	}
	ix := CreateAssociatedTokenAccount(funder, associatedTokenAccount, wallet, mint)
	data := append([]byte{}, txidBytes...)
	ix.Data = binary.LittleEndian.AppendUint32(data, vout)
	return ix, nil
}
