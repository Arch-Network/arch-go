package arch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// AccountMeta describes how an account is used by an instruction.
type AccountMeta struct {
	Pubkey     Pubkey `json:"pubkey"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

// Instruction is an uncompiled instruction: a program id, the accounts it
// touches, and opaque instruction data.
type Instruction struct {
	ProgramID Pubkey        `json:"program_id"`
	Accounts  []AccountMeta `json:"accounts"`
	Data      Bytes         `json:"data"`
}

// MessageHeader mirrors arch_program::sanitized::MessageHeader.
type MessageHeader struct {
	NumRequiredSignatures       uint8 `json:"num_required_signatures"`
	NumReadonlySignedAccounts   uint8 `json:"num_readonly_signed_accounts"`
	NumReadonlyUnsignedAccounts uint8 `json:"num_readonly_unsigned_accounts"`
}

// SanitizedInstruction is a compiled instruction whose program id and
// accounts are indices into the message's account_keys.
type SanitizedInstruction struct {
	ProgramIDIndex uint8 `json:"program_id_index"`
	Accounts       Bytes `json:"accounts"`
	Data           Bytes `json:"data"`
}

// Serialize encodes the instruction in the Arch binary message format:
// program_id_index (u8), accounts count (u32 LE), account indices (u8 each),
// data length (u32 LE), data bytes. This matches
// arch_program::sanitized::SanitizedInstruction::serialize; note the u32
// counts — Arch does NOT use Solana's compact-u16 encoding.
func (si SanitizedInstruction) Serialize() []byte {
	buf := make([]byte, 0, 1+4+len(si.Accounts)+4+len(si.Data))
	buf = append(buf, si.ProgramIDIndex)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(si.Accounts)))
	buf = append(buf, si.Accounts...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(si.Data)))
	buf = append(buf, si.Data...)
	return buf
}

// SanitizedMessage mirrors arch_program::sanitized::ArchMessage — the
// canonical message that is serialized, hashed, and signed.
type SanitizedMessage struct {
	Header          MessageHeader          `json:"header"`
	AccountKeys     []Pubkey               `json:"account_keys"`
	RecentBlockhash Hash                   `json:"recent_blockhash"`
	Instructions    []SanitizedInstruction `json:"instructions"`
}

// Serialize encodes the message in the Arch binary format: header (3 bytes),
// account key count (u32 LE), keys (32 bytes each), recent blockhash
// (32 bytes), instruction count (u32 LE), serialized instructions. This
// matches arch_program::sanitized::ArchMessage::serialize.
func (m SanitizedMessage) Serialize() []byte {
	var buf []byte
	buf = append(buf,
		m.Header.NumRequiredSignatures,
		m.Header.NumReadonlySignedAccounts,
		m.Header.NumReadonlyUnsignedAccounts,
	)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(m.AccountKeys)))
	for _, key := range m.AccountKeys {
		buf = append(buf, key[:]...)
	}
	buf = append(buf, m.RecentBlockhash[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(m.Instructions)))
	for _, ix := range m.Instructions {
		buf = append(buf, ix.Serialize()...)
	}
	return buf
}

// Hash returns the signing digest of the message: the 64 ASCII bytes of
// hex(sha256(hex(sha256(serialize(message))))). This unusual construction
// (hashing the lowercase hex string, not the raw digest) matches
// arch_program::sanitized::ArchMessage::hash, and its output is exactly what
// each signer must sign with BIP-322.
func (m SanitizedMessage) Hash() []byte {
	first := sha256.Sum256(m.Serialize())
	firstHex := []byte(hex.EncodeToString(first[:]))
	second := sha256.Sum256(firstHex)
	return []byte(hex.EncodeToString(second[:]))
}
