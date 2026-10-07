package arch

// System program instruction builders. Discriminant values and data layouts
// match arch-network's program/src/system_instruction.rs (u32 LE
// discriminant, u64 LE integers, raw 32-byte pubkeys, u64-length-prefixed
// strings).

import "encoding/binary"

// System instruction discriminants, in Rust enum order (arch-network
// v0.12.0).
const (
	sysCreateAccount          uint32 = 0
	sysAssign                 uint32 = 1
	sysSignInput              uint32 = 2
	sysTransfer               uint32 = 3
	sysAllocate               uint32 = 4
	sysCreateAccountWithSeed  uint32 = 5
	sysAllocateWithSeed       uint32 = 6
	sysAssignWithSeed         uint32 = 7
	sysTransferWithSeed       uint32 = 8
	sysAdvanceNonceAccount    uint32 = 9
	sysWithdrawNonceAccount   uint32 = 10
	sysInitializeNonceAccount uint32 = 11
	sysAuthorizeNonceAccount  uint32 = 12
)

// NonceAccountLength is the data length of a nonce account: the encoding of
// an initialized nonce state (u32 tag, authority pubkey, durable nonce hash).
const NonceAccountLength = 68

func appendU32(buf []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(buf, v)
}

func appendU64(buf []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(buf, v)
}

func appendString(buf []byte, s string) []byte {
	buf = appendU64(buf, uint64(len(s)))
	return append(buf, s...)
}

// CreateAccount creates a new account owned by owner, funded with lamports
// and allocated space bytes.
func CreateAccount(from, to Pubkey, lamports, space uint64, owner Pubkey) Instruction {
	data := appendU32(nil, sysCreateAccount)
	data = appendU64(data, lamports)
	data = appendU64(data, space)
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: from, IsSigner: true, IsWritable: true},
			{Pubkey: to, IsSigner: true, IsWritable: true},
		},
		Data: data,
	}
}

// Assign sets the owner program of an account.
func Assign(pubkey, owner Pubkey) Instruction {
	data := appendU32(nil, sysAssign)
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts:  []AccountMeta{{Pubkey: pubkey, IsSigner: true, IsWritable: true}},
		Data:      data,
	}
}

// SignInput signs the Bitcoin transaction input at index.
func SignInput(index uint32, signer Pubkey) Instruction {
	data := appendU32(nil, sysSignInput)
	data = appendU32(data, index)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts:  []AccountMeta{{Pubkey: signer, IsSigner: true, IsWritable: true}},
		Data:      data,
	}
}

// Transfer moves lamports between accounts.
func Transfer(from, to Pubkey, lamports uint64) Instruction {
	data := appendU32(nil, sysTransfer)
	data = appendU64(data, lamports)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: from, IsSigner: true, IsWritable: true},
			{Pubkey: to, IsSigner: false, IsWritable: true},
		},
		Data: data,
	}
}

// Allocate allocates space bytes in an account.
func Allocate(pubkey Pubkey, space uint64) Instruction {
	data := appendU32(nil, sysAllocate)
	data = appendU64(data, space)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts:  []AccountMeta{{Pubkey: pubkey, IsSigner: true, IsWritable: true}},
		Data:      data,
	}
}

// CreateAccountWithSeed creates an account at an address derived from base
// and seed.
func CreateAccountWithSeed(from, to, base Pubkey, seed string, lamports, space uint64, owner Pubkey) Instruction {
	data := appendU32(nil, sysCreateAccountWithSeed)
	data = append(data, base[:]...)
	data = appendString(data, seed)
	data = appendU64(data, lamports)
	data = appendU64(data, space)
	data = append(data, owner[:]...)

	accounts := []AccountMeta{
		{Pubkey: from, IsSigner: true, IsWritable: true},
		{Pubkey: to, IsSigner: false, IsWritable: true},
	}
	if base != from {
		accounts = append(accounts, AccountMeta{Pubkey: base, IsSigner: true, IsWritable: false})
	}
	return Instruction{ProgramID: SystemProgramID, Accounts: accounts, Data: data}
}

// AllocateWithSeed allocates space in a seed-derived account.
func AllocateWithSeed(address, base Pubkey, seed string, space uint64, owner Pubkey) Instruction {
	data := appendU32(nil, sysAllocateWithSeed)
	data = append(data, base[:]...)
	data = appendString(data, seed)
	data = appendU64(data, space)
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: address, IsSigner: false, IsWritable: true},
			{Pubkey: base, IsSigner: true, IsWritable: false},
		},
		Data: data,
	}
}

// AssignWithSeed assigns a seed-derived account to owner.
func AssignWithSeed(address, base Pubkey, seed string, owner Pubkey) Instruction {
	data := appendU32(nil, sysAssignWithSeed)
	data = append(data, base[:]...)
	data = appendString(data, seed)
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: address, IsSigner: false, IsWritable: true},
			{Pubkey: base, IsSigner: true, IsWritable: false},
		},
		Data: data,
	}
}

// TransferWithSeed transfers lamports from a seed-derived account.
func TransferWithSeed(from, fromBase Pubkey, fromSeed string, fromOwner, to Pubkey, lamports uint64) Instruction {
	data := appendU32(nil, sysTransferWithSeed)
	data = appendU64(data, lamports)
	data = appendString(data, fromSeed)
	data = append(data, fromOwner[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: from, IsSigner: false, IsWritable: true},
			{Pubkey: fromBase, IsSigner: true, IsWritable: false},
			{Pubkey: to, IsSigner: false, IsWritable: true},
		},
		Data: data,
	}
}

// CreateNonceAccount creates a system-owned nonce account and initializes it
// with authority. nonce must sign; lamports must cover the rent-exempt
// minimum for NonceAccountLength bytes.
func CreateNonceAccount(from, nonce, authority Pubkey, lamports uint64) []Instruction {
	return []Instruction{
		CreateAccount(from, nonce, lamports, NonceAccountLength, SystemProgramID),
		InitializeNonceAccount(nonce, authority),
	}
}

// InitializeNonceAccount initializes an allocated nonce account, setting the
// authority allowed to advance, withdraw from, or re-authorize it.
func InitializeNonceAccount(nonce, authority Pubkey) Instruction {
	data := appendU32(nil, sysInitializeNonceAccount)
	data = append(data, authority[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts:  []AccountMeta{{Pubkey: nonce, IsWritable: true}},
		Data:      data,
	}
}

// AdvanceNonceAccount advances a nonce account. As the first instruction of a
// transaction whose recent blockhash is the stored nonce, it makes a
// durable-nonce transaction.
func AdvanceNonceAccount(nonce, authority Pubkey) Instruction {
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: nonce, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: appendU32(nil, sysAdvanceNonceAccount),
	}
}

// WithdrawNonceAccount withdraws lamports from a nonce account to to.
func WithdrawNonceAccount(nonce, authority, to Pubkey, lamports uint64) Instruction {
	data := appendU32(nil, sysWithdrawNonceAccount)
	data = appendU64(data, lamports)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: nonce, IsWritable: true},
			{Pubkey: to, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: data,
	}
}

// AuthorizeNonceAccount changes a nonce account's authority to newAuthority.
func AuthorizeNonceAccount(nonce, authority, newAuthority Pubkey) Instruction {
	data := appendU32(nil, sysAuthorizeNonceAccount)
	data = append(data, newAuthority[:]...)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: nonce, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: data,
	}
}
