package arch

// System program instruction builders. Discriminant values and data layouts
// match arch-network's program/src/system_instruction.rs (u32 LE
// discriminant, u64 LE integers, raw 32-byte pubkeys, u64-length-prefixed
// strings).

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// System instruction discriminants, in Rust enum order.
const (
	sysCreateAccount           uint32 = 0
	sysCreateAccountWithAnchor uint32 = 1
	sysAssign                  uint32 = 2
	sysAnchor                  uint32 = 3
	sysSignInput               uint32 = 4
	sysTransfer                uint32 = 5
	sysAllocate                uint32 = 6
	sysCreateAccountWithSeed   uint32 = 7
	sysAllocateWithSeed        uint32 = 8
	sysAssignWithSeed          uint32 = 9
	sysTransferWithSeed        uint32 = 10
)

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

func decodeTxid(txid string) ([]byte, error) {
	b, err := hex.DecodeString(txid)
	if err != nil {
		return nil, fmt.Errorf("invalid txid hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("txid must be 32 bytes, got %d", len(b))
	}
	return b, nil
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

// CreateAccountWithAnchor creates a new account anchored to a Bitcoin UTXO
// (txid is a 64-character hex string, vout its output index).
func CreateAccountWithAnchor(from, to Pubkey, lamports, space uint64, owner Pubkey, txid string, vout uint32) (Instruction, error) {
	txidBytes, err := decodeTxid(txid)
	if err != nil {
		return Instruction{}, err
	}
	data := appendU32(nil, sysCreateAccountWithAnchor)
	data = appendU64(data, lamports)
	data = appendU64(data, space)
	data = append(data, owner[:]...)
	data = append(data, txidBytes...)
	data = appendU32(data, vout)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{Pubkey: from, IsSigner: true, IsWritable: true},
			{Pubkey: to, IsSigner: true, IsWritable: true},
		},
		Data: data,
	}, nil
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

// Anchor anchors an existing account to a Bitcoin UTXO.
func Anchor(pubkey Pubkey, txid string, vout uint32) (Instruction, error) {
	txidBytes, err := decodeTxid(txid)
	if err != nil {
		return Instruction{}, err
	}
	data := appendU32(nil, sysAnchor)
	data = append(data, txidBytes...)
	data = appendU32(data, vout)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts:  []AccountMeta{{Pubkey: pubkey, IsSigner: true, IsWritable: true}},
		Data:      data,
	}, nil
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
