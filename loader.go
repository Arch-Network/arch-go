package arch

// BPF loader instruction builders for deploying programs, mirroring
// arch-network's program/src/loader_instruction.rs. The discriminant is
// bincode's u32 LE enum tag; Write's payload is a u32 LE offset followed by a
// u64-length-prefixed byte vector.

// Loader instruction discriminants, in Rust enum order.
const (
	loaderWrite             uint32 = 0
	loaderTruncate          uint32 = 1
	loaderDeploy            uint32 = 2
	loaderRetract           uint32 = 3
	loaderTransferAuthority uint32 = 4
	loaderFinalize          uint32 = 5
)

// LoaderWrite writes bytes into a program account at offset.
func LoaderWrite(programAccount, authority Pubkey, offset uint32, bytes []byte) Instruction {
	data := appendU32(nil, loaderWrite)
	data = appendU32(data, offset)
	data = appendU64(data, uint64(len(bytes)))
	data = append(data, bytes...)
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: data,
	}
}

// LoaderTruncate resizes a program account to newSize bytes.
func LoaderTruncate(programAccount, authority Pubkey, newSize uint32) Instruction {
	data := appendU32(nil, loaderTruncate)
	data = appendU32(data, newSize)
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsSigner: true, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: data,
	}
}

// LoaderDeploy marks a program account as executable.
func LoaderDeploy(programAccount, authority Pubkey) Instruction {
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: appendU32(nil, loaderDeploy),
	}
}

// LoaderRetract makes a deployed program writable again.
func LoaderRetract(programAccount, authority Pubkey) Instruction {
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
		},
		Data: appendU32(nil, loaderRetract),
	}
}

// LoaderTransferAuthority transfers a program account's upgrade authority.
func LoaderTransferAuthority(programAccount, currentAuthority, newAuthority Pubkey) Instruction {
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsSigner: true, IsWritable: true},
			{Pubkey: currentAuthority, IsSigner: true},
			{Pubkey: newAuthority, IsSigner: true},
		},
		Data: appendU32(nil, loaderTransferAuthority),
	}
}

// LoaderFinalize makes a program immutable, recording nextVersion as its
// successor.
func LoaderFinalize(programAccount, authority, nextVersion Pubkey) Instruction {
	return Instruction{
		ProgramID: BpfLoaderProgramID,
		Accounts: []AccountMeta{
			{Pubkey: programAccount, IsSigner: true, IsWritable: true},
			{Pubkey: authority, IsSigner: true},
			{Pubkey: nextVersion},
		},
		Data: appendU32(nil, loaderFinalize),
	}
}

// ExtendBytesMaxLen returns the largest LoaderWrite payload that still fits in
// RuntimeTxSizeLimit for a single-signer transaction, mirroring
// arch_sdk::extend_bytes_max_len.
func ExtendBytesMaxLen() (int, error) {
	program := Pubkey{}
	authority := Pubkey{}
	for i := range program {
		program[i] = 1
		authority[i] = 2
	}
	message, err := NewSanitizedMessage(
		[]Instruction{LoaderWrite(program, authority, 0, nil)},
		nil,
		Hash{},
	)
	if err != nil {
		return 0, err
	}
	tx := RuntimeTransaction{
		Version:    RuntimeTxVersion,
		Signatures: []Signature{{}},
		Message:    message,
	}
	return RuntimeTxSizeLimit - len(tx.Serialize()), nil
}
