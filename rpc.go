package arch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// rpcNotFoundCode is the error code the node returns for missing entities.
const rpcNotFoundCode = 404

// RPCError is a JSON-RPC error returned by the node.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// Client is a JSON-RPC client for an Arch node. The zero value is not usable;
// construct one with NewClient.
type Client struct {
	nodeURL    string
	httpClient *http.Client
}

// NewClient returns a Client for the node at nodeURL
// (e.g. "http://localhost:9002"). Pass nil to use http.DefaultClient.
func NewClient(nodeURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{nodeURL: nodeURL, httpClient: httpClient}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

// postData sends a JSON-RPC request and returns the raw result. hasParams
// distinguishes "params omitted" from "params: null".
func (c *Client) postData(method string, params any, hasParams bool) (json.RawMessage, error) {
	req := rpcRequest{JSONRPC: "2.0", ID: "curlycurl", Method: method}
	if hasParams {
		req.Params = params
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling rpc request: %w", err)
	}

	httpResp, err := c.httpClient.Post(c.nodeURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("posting to node: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading node response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node returned HTTP %d: %s", httpResp.StatusCode, respBody)
	}

	var resp rpcResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parsing node response: %w", err)
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

// call posts a request and unmarshals the result into T.
func call[T any](c *Client, method string, params any) (T, error) {
	var out T
	raw, err := c.postData(method, params, true)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("unmarshaling %s result: %w", method, err)
	}
	return out, nil
}

// callNoParams posts a parameterless request and unmarshals the result.
func callNoParams[T any](c *Client, method string) (T, error) {
	var out T
	raw, err := c.postData(method, nil, false)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("unmarshaling %s result: %w", method, err)
	}
	return out, nil
}

// callNilOnNotFound is call but maps the node's 404 error to (nil, nil), for
// lookups where "missing" is a normal outcome.
func callNilOnNotFound[T any](c *Client, method string, params any) (*T, error) {
	out, err := call[*T](c, method, params)
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) && rpcErr.Code == rpcNotFoundCode {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

// SendTransaction submits a signed transaction and returns its txid.
func (c *Client) SendTransaction(tx RuntimeTransaction) (string, error) {
	return call[string](c, MethodSendTransaction, tx)
}

// SendTransactions submits a batch of signed transactions (at most
// MaxTxBatchSize) and returns their txids.
func (c *Client) SendTransactions(txs []RuntimeTransaction) ([]string, error) {
	return call[[]string](c, MethodSendTransactions, txs)
}

// ReadAccountInfo fetches an account's lamports, owner, data, and anchoring
// UTXO.
func (c *Client) ReadAccountInfo(pubkey Pubkey) (AccountInfo, error) {
	return call[AccountInfo](c, MethodReadAccountInfo, pubkey)
}

// GetAccountAddress returns the Bitcoin address of an account pubkey.
func (c *Client) GetAccountAddress(pubkey Pubkey) (string, error) {
	return call[string](c, MethodGetAccountAddress, pubkey)
}

// GetBestBlockHash returns the hash of the latest block as a hex string.
func (c *Client) GetBestBlockHash() (string, error) {
	return callNoParams[string](c, MethodGetBestBlockHash)
}

// GetBestFinalizedBlockHash returns the hash of the latest finalized block.
func (c *Client) GetBestFinalizedBlockHash() (string, error) {
	return callNoParams[string](c, MethodGetBestFinalizedBlockHash)
}

// GetBlock fetches a block by hash (hex string). Returns nil if not found.
func (c *Client) GetBlock(blockHash string) (*Block, error) {
	return callNilOnNotFound[Block](c, MethodGetBlock, []any{blockHash})
}

// GetBlockByHeight fetches a block by height. Returns nil if not found.
func (c *Client) GetBlockByHeight(height uint64) (*Block, error) {
	return callNilOnNotFound[Block](c, MethodGetBlockByHeight, []any{height})
}

// GetFullBlockByHash fetches a block by hash with fully expanded
// transactions. Returns nil if not found.
func (c *Client) GetFullBlockByHash(blockHash string) (*FullBlock, error) {
	return callNilOnNotFound[FullBlock](c, MethodGetBlock, []any{blockHash, BlockTransactionFilterFull})
}

// GetFullBlockByHeight fetches a block by height with fully expanded
// transactions. Returns nil if not found.
func (c *Client) GetFullBlockByHeight(height uint64) (*FullBlock, error) {
	return callNilOnNotFound[FullBlock](c, MethodGetBlockByHeight, []any{height, BlockTransactionFilterFull})
}

// GetBlockCount returns the current block count.
func (c *Client) GetBlockCount() (uint64, error) {
	return callNoParams[uint64](c, MethodGetBlockCount)
}

// GetBlockHash returns the block hash at a height as a hex string.
func (c *Client) GetBlockHash(height uint64) (string, error) {
	return call[string](c, MethodGetBlockHash, height)
}

// GetProcessedTransaction fetches a transaction by txid (hex string).
// Returns nil if the node does not know the transaction.
func (c *Client) GetProcessedTransaction(txid string) (*ProcessedTransaction, error) {
	return callNilOnNotFound[ProcessedTransaction](c, MethodGetProcessedTransaction, txid)
}

// GetProgramAccounts lists the accounts owned by a program, optionally
// filtered. Pass nil filters to fetch all.
func (c *Client) GetProgramAccounts(programID Pubkey, filters []AccountFilter) ([]ProgramAccount, error) {
	return call[[]ProgramAccount](c, MethodGetProgramAccounts, []any{programID, filters})
}

// RequestAirdrop requests an airdrop to pubkey (regtest/testnet only).
func (c *Client) RequestAirdrop(pubkey Pubkey) error {
	_, err := c.postData(MethodRequestAirdrop, pubkey, true)
	return err
}

// CreateAccountWithFaucet asks the node to build a faucet-funded account
// creation transaction (regtest/testnet only). The returned transaction must
// still be submitted with SendTransaction.
func (c *Client) CreateAccountWithFaucet(pubkey Pubkey) (RuntimeTransaction, error) {
	return call[RuntimeTransaction](c, MethodCreateAccountWithFaucet, pubkey)
}

// GetTransactionsByBlock lists the processed transactions of a block.
func (c *Client) GetTransactionsByBlock(params BlockTransactionsParams) ([]ProcessedTransaction, error) {
	return call[[]ProcessedTransaction](c, MethodGetTransactionsByBlock, params)
}

// GetTransactionsByIds fetches up to MaxTxBatchSize transactions by txid;
// missing transactions are nil.
func (c *Client) GetTransactionsByIds(txids []string) ([]*ProcessedTransaction, error) {
	return call[[]*ProcessedTransaction](c, MethodGetTransactionsByIds, map[string][]string{"txids": txids})
}

// RecentTransactions lists recent transactions with optional pagination and
// account filtering.
func (c *Client) RecentTransactions(params TransactionListParams) ([]ProcessedTransaction, error) {
	return call[[]ProcessedTransaction](c, MethodRecentTransactions, params)
}

// GetMultipleAccounts fetches several accounts at once; missing accounts are
// nil.
func (c *Client) GetMultipleAccounts(pubkeys []Pubkey) ([]*AccountInfoWithPubkey, error) {
	return call[[]*AccountInfoWithPubkey](c, MethodGetMultipleAccounts, pubkeys)
}

// GetNetworkPubkey returns the network's distributed signing pubkey.
func (c *Client) GetNetworkPubkey() (string, error) {
	return callNoParams[string](c, MethodGetNetworkPubkey)
}

// CheckPreAnchorConflict reports whether any of the accounts has a pending
// pre-anchor conflict.
func (c *Client) CheckPreAnchorConflict(accounts []Pubkey) (bool, error) {
	return call[bool](c, MethodCheckPreAnchorConflict, accounts)
}

// GetTransactionStatus returns the status of up to 100 transactions by txid;
// unknown txids yield nil entries.
func (c *Client) GetTransactionStatus(txids []string) ([]*ProcessedTransactionStatus, error) {
	return call[[]*ProcessedTransactionStatus](c, MethodGetTransactionStatus, map[string][]string{"txids": txids})
}

// CreateNewAccount generates a fresh keypair and asks the node for its
// Bitcoin address, mirroring the TypeScript SDK's createNewAccount.
func (c *Client) CreateNewAccount() (CreatedAccount, error) {
	priv, err := NewPrivateKey()
	if err != nil {
		return CreatedAccount{}, err
	}
	pubkey := XOnlyPubkey(priv)
	address, err := c.GetAccountAddress(pubkey)
	if err != nil {
		return CreatedAccount{}, err
	}
	return CreatedAccount{
		Privkey: hex.EncodeToString(priv.Serialize()),
		Pubkey:  pubkey.String(),
		Address: address,
	}, nil
}
