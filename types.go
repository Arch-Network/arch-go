package arch

// Signature is a 64-byte BIP-322 Schnorr signature. It serializes to JSON as
// an array of 64 numbers.
type Signature [64]byte

// RuntimeTransaction is the transaction envelope sent to the node:
// version (always 0), one signature per required signer, and the message.
type RuntimeTransaction struct {
	Version    uint32           `json:"version"`
	Signatures []Signature      `json:"signatures"`
	Message    SanitizedMessage `json:"message"`
}

// AccountInfo is the response of read_account_info, mirroring
// arch_sdk::AccountInfo.
type AccountInfo struct {
	Lamports     uint64 `json:"lamports"`
	Owner        Pubkey `json:"owner"`
	Data         Bytes  `json:"data"`
	Utxo         string `json:"utxo"`
	IsExecutable bool   `json:"is_executable"`
}

// AccountInfoWithPubkey is an AccountInfo plus the account's key, returned by
// get_multiple_accounts.
type AccountInfoWithPubkey struct {
	Key          Pubkey `json:"key"`
	Lamports     uint64 `json:"lamports"`
	Owner        Pubkey `json:"owner"`
	Data         Bytes  `json:"data"`
	Utxo         string `json:"utxo"`
	IsExecutable bool   `json:"is_executable"`
}

// ProgramAccount pairs an account's pubkey with its info, returned by
// get_program_accounts.
type ProgramAccount struct {
	Pubkey  Pubkey      `json:"pubkey"`
	Account AccountInfo `json:"account"`
}

// DataContent is the payload of an AccountFilter matching account data bytes
// at an offset.
type DataContent struct {
	Offset uint64 `json:"offset"`
	Bytes  Bytes  `json:"bytes"`
}

// AccountFilter is a get_program_accounts filter. Exactly one of the fields
// is set; use DataSizeFilter or DataContentFilter to construct one. On the
// wire it is the externally-tagged serde enum {"DataSize": n} or
// {"DataContent": {"offset": n, "bytes": [...]}}.
type AccountFilter struct {
	DataSize    *uint64      `json:"DataSize,omitempty"`
	DataContent *DataContent `json:"DataContent,omitempty"`
}

// DataSizeFilter matches accounts whose data is exactly size bytes long.
func DataSizeFilter(size uint64) AccountFilter {
	return AccountFilter{DataSize: &size}
}

// DataContentFilter matches accounts whose data contains the given bytes at
// the given offset.
func DataContentFilter(offset uint64, b []byte) AccountFilter {
	return AccountFilter{DataContent: &DataContent{Offset: offset, Bytes: b}}
}

// Status type tags for ProcessedTransactionStatus.
const (
	StatusQueued    = "queued"
	StatusProcessed = "processed"
	StatusFailed    = "failed"
)

// ProcessedTransactionStatus is the processing status of a transaction.
// Type is one of StatusQueued, StatusProcessed, StatusFailed; Message is set
// only for failures.
type ProcessedTransactionStatus struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

// Rollback status type tags.
const (
	RollbackStatusNotRolledback = "notRolledback"
	RollbackStatusRolledback    = "rolledback"
)

// RollbackStatus reports whether a transaction was rolled back due to a
// Bitcoin reorg. Message is set only for the rolledback variant.
type RollbackStatus struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

// InnerInstruction is an instruction invoked via CPI during execution.
type InnerInstruction struct {
	Instruction SanitizedInstruction `json:"instruction"`
	StackHeight uint8                `json:"stack_height"`
}

// ProcessedTransaction is the response of get_processed_transaction.
type ProcessedTransaction struct {
	RuntimeTransaction    RuntimeTransaction         `json:"runtime_transaction"`
	Status                ProcessedTransactionStatus `json:"status"`
	BitcoinTxid           *Hash                      `json:"bitcoin_txid"`
	Logs                  []string                   `json:"logs"`
	RollbackStatus        RollbackStatus             `json:"rollback_status"`
	InnerInstructionsList [][]InnerInstruction       `json:"inner_instructions_list"`
}

// Block is the response of get_block / get_block_by_height. Transaction ids
// and hashes are 32-number JSON arrays on the wire (see Hash).
type Block struct {
	Transactions       []Hash `json:"transactions"`
	PreviousBlockHash  Hash   `json:"previous_block_hash"`
	Timestamp          uint64 `json:"timestamp"`
	BlockHeight        uint64 `json:"block_height"`
	BitcoinBlockHeight uint64 `json:"bitcoin_block_height"`
}

// FullBlock is a Block whose transactions are fully expanded.
type FullBlock struct {
	Transactions       []ProcessedTransaction `json:"transactions"`
	PreviousBlockHash  Hash                   `json:"previous_block_hash"`
	Timestamp          uint64                 `json:"timestamp"`
	BlockHeight        uint64                 `json:"block_height"`
	BitcoinBlockHeight uint64                 `json:"bitcoin_block_height"`
}

// BlockTransactionFilter selects how get_block returns transactions.
type BlockTransactionFilter string

// BlockTransactionFilter values.
const (
	BlockTransactionFilterFull       BlockTransactionFilter = "full"
	BlockTransactionFilterSignatures BlockTransactionFilter = "signatures"
)

// BlockTransactionsParams are the parameters of get_transactions_by_block.
type BlockTransactionsParams struct {
	BlockHash string  `json:"block_hash"`
	Limit     *uint64 `json:"limit,omitempty"`
	Offset    *uint64 `json:"offset,omitempty"`
	Account   *Pubkey `json:"account,omitempty"`
}

// TransactionListParams are the parameters of recent_transactions.
type TransactionListParams struct {
	Limit   *uint64 `json:"limit,omitempty"`
	Offset  *uint64 `json:"offset,omitempty"`
	Account *Pubkey `json:"account,omitempty"`
}

// CreatedAccount is the result of Client.CreateNewAccount: a fresh secp256k1
// keypair (hex-encoded) and its Bitcoin address as reported by the node.
type CreatedAccount struct {
	Privkey string `json:"privkey"`
	Pubkey  string `json:"pubkey"`
	Address string `json:"address"`
}
