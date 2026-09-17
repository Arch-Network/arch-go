package arch

import (
	"bytes"
	"fmt"
	"sort"
)

// compiledKeyMeta mirrors arch_program::compiled_keys::CompiledKeyMeta.
type compiledKeyMeta struct {
	isSigner   bool
	isWritable bool
	isInvoked  bool
}

// NewSanitizedMessage compiles raw instructions into a SanitizedMessage,
// mirroring arch_program::sanitized::ArchMessage::new /
// compiled_keys::CompiledKeys. Keys are grouped as payer, then writable
// signers, readonly signers, writable non-signers, readonly non-signers;
// within each group keys are ordered by byte-wise comparison (the Rust
// implementation collects them in a BTreeMap). payer may be nil, in which
// case no key is forced to be a writable signer.
func NewSanitizedMessage(instructions []Instruction, payer *Pubkey, recentBlockhash Hash) (SanitizedMessage, error) {
	keyMetaMap := make(map[Pubkey]*compiledKeyMeta)
	getMeta := func(key Pubkey) *compiledKeyMeta {
		if m, ok := keyMetaMap[key]; ok {
			return m
		}
		m := &compiledKeyMeta{}
		keyMetaMap[key] = m
		return m
	}

	for _, ix := range instructions {
		getMeta(ix.ProgramID).isInvoked = true
		for _, accountMeta := range ix.Accounts {
			m := getMeta(accountMeta.Pubkey)
			m.isSigner = m.isSigner || accountMeta.IsSigner
			m.isWritable = m.isWritable || accountMeta.IsWritable
		}
	}
	if payer != nil {
		m := getMeta(*payer)
		m.isSigner = true
		m.isWritable = true
	}

	// Drain in sorted key order, payer excluded (it is prepended below).
	sortedKeys := make([]Pubkey, 0, len(keyMetaMap))
	for key := range keyMetaMap {
		if payer != nil && key == *payer {
			continue
		}
		sortedKeys = append(sortedKeys, key)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return bytes.Compare(sortedKeys[i][:], sortedKeys[j][:]) < 0
	})

	var writableSigners, readonlySigners, writableNonSigners, readonlyNonSigners []Pubkey
	if payer != nil {
		writableSigners = append(writableSigners, *payer)
	}
	for _, key := range sortedKeys {
		m := keyMetaMap[key]
		switch {
		case m.isSigner && m.isWritable:
			writableSigners = append(writableSigners, key)
		case m.isSigner && !m.isWritable:
			readonlySigners = append(readonlySigners, key)
		case !m.isSigner && m.isWritable:
			writableNonSigners = append(writableNonSigners, key)
		default:
			readonlyNonSigners = append(readonlyNonSigners, key)
		}
	}

	signersLen := len(writableSigners) + len(readonlySigners)
	totalKeys := signersLen + len(writableNonSigners) + len(readonlyNonSigners)
	if signersLen > 255 || len(readonlySigners) > 255 || len(readonlyNonSigners) > 255 || totalKeys > 256 {
		return SanitizedMessage{}, fmt.Errorf("account index overflowed during compilation")
	}

	accountKeys := make([]Pubkey, 0, totalKeys)
	accountKeys = append(accountKeys, writableSigners...)
	accountKeys = append(accountKeys, readonlySigners...)
	accountKeys = append(accountKeys, writableNonSigners...)
	accountKeys = append(accountKeys, readonlyNonSigners...)

	keyIndex := make(map[Pubkey]uint8, len(accountKeys))
	for i, key := range accountKeys {
		keyIndex[key] = uint8(i)
	}

	compiled := make([]SanitizedInstruction, 0, len(instructions))
	for _, ix := range instructions {
		programIdx, ok := keyIndex[ix.ProgramID]
		if !ok {
			return SanitizedMessage{}, fmt.Errorf("encountered unknown account key %s during instruction compilation", ix.ProgramID)
		}
		accounts := make(Bytes, 0, len(ix.Accounts))
		for _, accountMeta := range ix.Accounts {
			idx, ok := keyIndex[accountMeta.Pubkey]
			if !ok {
				return SanitizedMessage{}, fmt.Errorf("encountered unknown account key %s during instruction compilation", accountMeta.Pubkey)
			}
			accounts = append(accounts, idx)
		}
		compiled = append(compiled, SanitizedInstruction{
			ProgramIDIndex: programIdx,
			Accounts:       accounts,
			Data:           ix.Data,
		})
	}

	return SanitizedMessage{
		Header: MessageHeader{
			NumRequiredSignatures:       uint8(signersLen),
			NumReadonlySignedAccounts:   uint8(len(readonlySigners)),
			NumReadonlyUnsignedAccounts: uint8(len(readonlyNonSigners)),
		},
		AccountKeys:     accountKeys,
		RecentBlockhash: recentBlockhash,
		Instructions:    compiled,
	}, nil
}
