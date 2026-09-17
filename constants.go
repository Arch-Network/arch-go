package arch

// JSON-RPC method names exposed by the Arch node. These strings are pinned by
// the node's wire-format tests (arch-network sdk/tests/rpc_wire_format.rs)
// and must not change.
const (
	MethodReadAccountInfo           = "read_account_info"
	MethodSendTransaction           = "send_transaction"
	MethodSendTransactions          = "send_transactions"
	MethodGetBlock                  = "get_block"
	MethodGetBlockCount             = "get_block_count"
	MethodGetBlockHash              = "get_block_hash"
	MethodGetBestBlockHash          = "get_best_block_hash"
	MethodGetBestFinalizedBlockHash = "get_best_finalized_block_hash"
	MethodGetProcessedTransaction   = "get_processed_transaction"
	MethodGetAccountAddress         = "get_account_address"
	MethodGetProgramAccounts        = "get_program_accounts"
	MethodRequestAirdrop            = "request_airdrop"
	MethodCreateAccountWithFaucet   = "create_account_with_faucet"
	MethodGetBlockByHeight          = "get_block_by_height"
	MethodGetFullBlockWithTxids     = "get_full_block_with_txids"
	MethodGetTransactionsByBlock    = "get_transactions_by_block"
	MethodGetTransactionsByIds      = "get_transactions_by_ids"
	MethodRecentTransactions        = "recent_transactions"
	MethodGetMultipleAccounts       = "get_multiple_accounts"
	MethodGetNetworkPubkey          = "get_network_pubkey"
	MethodCheckPreAnchorConflict    = "check_pre_anchor_conflict"
	MethodGetTransactionStatus      = "get_transaction_status"
)

// RuntimeTxSizeLimit is the serialized RuntimeTransaction size limit
// (Solana's PACKET_DATA_SIZE).
const RuntimeTxSizeLimit = 1232

// RuntimeTxVersion is the only RuntimeTransaction.version accepted by the
// network.
const RuntimeTxVersion = 0

// MaxTxBatchSize is the maximum number of transactions per send_transactions
// batch.
const MaxTxBatchSize = 100

// MaxSigners is the maximum number of signers per transaction.
const MaxSigners = 16

// MaxTransactionsPerBlock is the maximum number of transactions per block.
const MaxTransactionsPerBlock = 1024

// SystemProgramID is the native system program ("11111111111111111111111111111111",
// 32 zero bytes).
var SystemProgramID = Pubkey{}

// TokenProgramID is the APL token program
// (base58 "TokenT4em53UrV4gSvZ3nCS2mZeHaqTLapwt6iZt6Mk").
var TokenProgramID = Pubkey{
	6, 221, 246, 225, 185, 234, 132, 65, 44, 16, 184, 223, 2, 28, 16, 15,
	200, 135, 25, 7, 195, 9, 195, 53, 53, 222, 32, 156, 52, 23, 99, 191,
}

// AssociatedTokenProgramID is the associated token account program
// (base58 "ATok9pxLsNzM5zJJ3UQpXBrMriHpZiY5Yio3GKYU4we3").
var AssociatedTokenProgramID = Pubkey{
	140, 151, 35, 17, 132, 146, 123, 119, 181, 241, 128, 17, 143, 204, 104, 52,
	20, 183, 124, 82, 30, 90, 119, 8, 28, 247, 29, 95, 96, 106, 83, 132,
}

// BpfLoaderProgramID is the BPF loader program
// (base58 "BpfLoader1111111111111111111111111111111111").
var BpfLoaderProgramID = Pubkey{
	2, 197, 178, 216, 231, 45, 42, 178, 55, 139, 51, 119, 73, 71, 125, 120,
	122, 208, 19, 239, 94, 121, 232, 49, 230, 137, 68, 140, 0, 0, 0, 0,
}

// VoteProgramID is the vote program
// (base58 "VoteProgram11111111111111111111111111111111").
var VoteProgramID = Pubkey{
	7, 97, 72, 37, 227, 237, 86, 6, 249, 190, 178, 214, 177, 8, 63, 226,
	34, 198, 130, 48, 216, 183, 167, 155, 11, 12, 86, 34, 0, 0, 0, 0,
}

// StakeProgramID is the stake program
// (base58 "StakeProgram1111111111111111111111111111111").
var StakeProgramID = Pubkey{
	6, 161, 216, 23, 183, 136, 220, 118, 238, 58, 149, 122, 111, 233, 45, 126,
	42, 165, 35, 109, 10, 154, 58, 130, 3, 20, 197, 133, 0, 0, 0, 0,
}

// ComputeBudgetProgramID is the compute budget program
// (base58 "ComputeBudget111111111111111111111111111111").
var ComputeBudgetProgramID = Pubkey{
	3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231,
	188, 140, 229, 187, 197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
}

// NativeLoaderProgramID is the native loader program
// (base58 "NativeLoader1111111111111111111111111111111").
var NativeLoaderProgramID = Pubkey{
	5, 135, 132, 191, 20, 139, 164, 40, 47, 176, 18, 87, 72, 136, 169, 241,
	83, 160, 125, 173, 247, 101, 192, 69, 92, 154, 151, 3, 128, 0, 0, 0,
}
