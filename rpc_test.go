package arch

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// zeros32JSON is a JSON array of 32 zeros, matching the fixtures in
// arch-network's rpc_wire_format.rs.
var zeros32JSON = "[" + strings.Repeat("0,", 31) + "0]"

// capturedRequest is the JSON-RPC envelope received by the mock node.
type capturedRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	raw     map[string]json.RawMessage
}

// newMockNode starts a mock node that answers every request with result and
// records the last envelope it received.
func newMockNode(t *testing.T, result string) (*Client, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request: %v", err)
		}
		if err := json.Unmarshal(body, captured); err != nil {
			t.Errorf("parsing request envelope: %v", err)
		}
		if err := json.Unmarshal(body, &captured.raw); err != nil {
			t.Errorf("parsing request envelope keys: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"result":` + result + `}`)); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, nil), captured
}

// checkEnvelope asserts the standard JSON-RPC 2.0 envelope the Arch node
// expects (pinned by rpc_wire_format.rs).
func checkEnvelope(t *testing.T, req *capturedRequest, wantMethod string) {
	t.Helper()
	if req.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want \"2.0\"", req.JSONRPC)
	}
	if req.ID != "curlycurl" {
		t.Errorf("id = %q, want \"curlycurl\"", req.ID)
	}
	if req.Method != wantMethod {
		t.Errorf("method = %q, want %q", req.Method, wantMethod)
	}
}

func paramsJSON(t *testing.T, req *capturedRequest) string {
	t.Helper()
	return string(req.Params)
}

func TestSendTransaction(t *testing.T) {
	client, req := newMockNode(t, `"deadbeef"`)

	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := XOnlyPubkey(priv)
	msg, err := NewSanitizedMessage([]Instruction{Transfer(payer, pk(3), 10)}, &payer, Hash{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := BuildAndSignTransaction(msg, priv)
	if err != nil {
		t.Fatal(err)
	}

	txid, err := client.SendTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	if txid != "deadbeef" {
		t.Errorf("txid = %q", txid)
	}
	checkEnvelope(t, req, "send_transaction")

	// Params must be a single object with version/signatures/message, byte
	// fields as number arrays.
	var params map[string]json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("params not an object: %s", req.Params)
	}
	for _, key := range []string{"version", "signatures", "message"} {
		if _, ok := params[key]; !ok {
			t.Errorf("params missing %q", key)
		}
	}
	var sigs [][]int
	if err := json.Unmarshal(params["signatures"], &sigs); err != nil || len(sigs) != 1 || len(sigs[0]) != 64 {
		t.Errorf("signatures must be one 64-number array, got %s", params["signatures"])
	}
}

func TestSendTransactions(t *testing.T) {
	client, req := newMockNode(t, `["a","b"]`)
	txids, err := client.SendTransactions([]RuntimeTransaction{
		{Version: 0, Signatures: []Signature{}, Message: SanitizedMessage{AccountKeys: []Pubkey{}, Instructions: []SanitizedInstruction{}}},
		{Version: 0, Signatures: []Signature{}, Message: SanitizedMessage{AccountKeys: []Pubkey{}, Instructions: []SanitizedInstruction{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(txids) != 2 || txids[0] != "a" {
		t.Errorf("txids = %v", txids)
	}
	checkEnvelope(t, req, "send_transactions")
	var arr []json.RawMessage
	if err := json.Unmarshal(req.Params, &arr); err != nil || len(arr) != 2 {
		t.Errorf("params must be an array of 2 transactions, got %s", req.Params)
	}
}

func TestReadAccountInfo(t *testing.T) {
	// Fixture from rpc_wire_format.rs account_info_response_deserialization.
	client, req := newMockNode(t, `{"lamports":1000000,"owner":`+zeros32JSON+`,"data":[1,2,3,4],"utxo":"abc123:0","is_executable":false}`)

	info, err := client.ReadAccountInfo(pk(1))
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "read_account_info")

	var arr []int
	if err := json.Unmarshal(req.Params, &arr); err != nil || len(arr) != 32 {
		t.Errorf("params must be a 32-number array, got %s", req.Params)
	}
	if arr[0] != 1 {
		t.Errorf("params[0] = %d, want 1", arr[0])
	}

	if info.Lamports != 1000000 || info.Utxo != "abc123:0" || info.IsExecutable {
		t.Errorf("info = %+v", info)
	}
	if len(info.Data) != 4 || info.Data[3] != 4 {
		t.Errorf("data = %v", info.Data)
	}
}

func TestGetAccountAddress(t *testing.T) {
	client, req := newMockNode(t, `"bc1p..."`)
	addr, err := client.GetAccountAddress(pk(0xAA))
	if err != nil {
		t.Fatal(err)
	}
	if addr != "bc1p..." {
		t.Errorf("addr = %q", addr)
	}
	checkEnvelope(t, req, "get_account_address")
	var arr []int
	if err := json.Unmarshal(req.Params, &arr); err != nil || len(arr) != 32 || arr[0] != 0xAA {
		t.Errorf("params = %s", req.Params)
	}
}

func TestGetBestBlockHashOmitsParams(t *testing.T) {
	client, req := newMockNode(t, `"abcd"`)
	hash, err := client.GetBestBlockHash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != "abcd" {
		t.Errorf("hash = %q", hash)
	}
	checkEnvelope(t, req, "get_best_block_hash")
	if _, present := req.raw["params"]; present {
		t.Error("params must be omitted for get_best_block_hash")
	}
}

func TestGetBlock(t *testing.T) {
	// Fixture from rpc_wire_format.rs block_response_deserialization.
	client, req := newMockNode(t, `{"transactions":[`+zeros32JSON+`],"previous_block_hash":`+zeros32JSON+`,"timestamp":1700000000000,"block_height":42,"bitcoin_block_height":800000}`)

	block, err := client.GetBlock("aabb")
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_block")
	if got := paramsJSON(t, req); got != `["aabb"]` {
		t.Errorf("params = %s, want [\"aabb\"]", got)
	}
	if block == nil || block.BlockHeight != 42 || block.BitcoinBlockHeight != 800000 || len(block.Transactions) != 1 {
		t.Errorf("block = %+v", block)
	}
}

func TestGetFullBlockByHeight(t *testing.T) {
	client, req := newMockNode(t, `{"transactions":[],"previous_block_hash":`+zeros32JSON+`,"timestamp":1700000000000,"block_height":100,"bitcoin_block_height":800001}`)

	block, err := client.GetFullBlockByHeight(100)
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_block_by_height")
	if got := paramsJSON(t, req); got != `[100,"full"]` {
		t.Errorf("params = %s, want [100,\"full\"]", got)
	}
	if block == nil || block.BlockHeight != 100 {
		t.Errorf("block = %+v", block)
	}
}

func TestGetBlockNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"code":404,"message":"not found"}}`))
	}))
	t.Cleanup(server.Close)
	client := NewClient(server.URL, nil)

	block, err := client.GetBlock("missing")
	if err != nil {
		t.Fatalf("404 should map to nil, nil; got err %v", err)
	}
	if block != nil {
		t.Errorf("block = %+v, want nil", block)
	}

	tx, err := client.GetProcessedTransaction("missing")
	if err != nil || tx != nil {
		t.Errorf("processed tx 404: got %+v, %v", tx, err)
	}
}

func TestGetBlockCountAndHash(t *testing.T) {
	client, req := newMockNode(t, `12345`)
	count, err := client.GetBlockCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 12345 {
		t.Errorf("count = %d", count)
	}
	checkEnvelope(t, req, "get_block_count")
	if _, present := req.raw["params"]; present {
		t.Error("params must be omitted for get_block_count")
	}

	client2, req2 := newMockNode(t, `"cafe"`)
	hash, err := client2.GetBlockHash(42)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "cafe" {
		t.Errorf("hash = %q", hash)
	}
	checkEnvelope(t, req2, "get_block_hash")
	// Bare number, not wrapped in an array (matches the TS SDK).
	if got := paramsJSON(t, req2); got != `42` {
		t.Errorf("params = %s, want 42", got)
	}
}

func TestGetProcessedTransaction(t *testing.T) {
	// Fixture from rpc_wire_format.rs minimal_processed_tx_json.
	result := `{"runtime_transaction":{"version":0,"signatures":[],"message":{"header":{"num_required_signatures":0,"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":0},"account_keys":[],"recent_blockhash":` + zeros32JSON + `,"instructions":[]}},"status":{"type":"failed","message":"out of gas"},"bitcoin_txid":null,"logs":["Program log: hello"],"rollback_status":{"type":"notRolledback"},"inner_instructions_list":[]}`
	client, req := newMockNode(t, result)

	tx, err := client.GetProcessedTransaction("aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_processed_transaction")
	if got := paramsJSON(t, req); got != `"aabbcc"` {
		t.Errorf("params = %s, want bare txid string", got)
	}
	if tx == nil {
		t.Fatal("tx = nil")
	}
	if tx.Status.Type != StatusFailed || tx.Status.Message != "out of gas" {
		t.Errorf("status = %+v", tx.Status)
	}
	if tx.BitcoinTxid != nil {
		t.Error("bitcoin_txid should be nil")
	}
	if len(tx.Logs) != 1 || tx.Logs[0] != "Program log: hello" {
		t.Errorf("logs = %v", tx.Logs)
	}
	if tx.RollbackStatus.Type != RollbackStatusNotRolledback {
		t.Errorf("rollback = %+v", tx.RollbackStatus)
	}
}

func TestGetProgramAccounts(t *testing.T) {
	// Fixture from rpc_wire_format.rs program_account_response_deserialization.
	fives := "[" + strings.Repeat("5,", 31) + "5]"
	client, req := newMockNode(t, `[{"pubkey":`+fives+`,"account":{"lamports":999,"owner":`+zeros32JSON+`,"data":[10,20],"utxo":"txid:1","is_executable":true}}]`)

	accounts, err := client.GetProgramAccounts(pk(1), []AccountFilter{DataSizeFilter(64)})
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_program_accounts")

	// Params: [pubkey_bytes, filters].
	var params []json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil || len(params) != 2 {
		t.Fatalf("params must be a 2-element array, got %s", req.Params)
	}
	if string(params[1]) != `[{"DataSize":64}]` {
		t.Errorf("filters = %s", params[1])
	}

	if len(accounts) != 1 || accounts[0].Account.Lamports != 999 || !accounts[0].Account.IsExecutable {
		t.Errorf("accounts = %+v", accounts)
	}
	var wantPubkey Pubkey
	for i := range wantPubkey {
		wantPubkey[i] = 5
	}
	if accounts[0].Pubkey != wantPubkey {
		t.Errorf("pubkey = %s", accounts[0].Pubkey)
	}
}

func TestRequestAirdropAndFaucet(t *testing.T) {
	client, req := newMockNode(t, `null`)
	if err := client.RequestAirdrop(pk(1)); err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "request_airdrop")

	// Fixture from rpc_wire_format.rs runtime_transaction_response_deserialization.
	ones := "[" + strings.Repeat("1,", 31) + "1]"
	sig := "[" + strings.Repeat("0,", 63) + "0]"
	result := `{"version":0,"signatures":[` + sig + `],"message":{"header":{"num_required_signatures":1,"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":1},"account_keys":[` + zeros32JSON + `,` + ones + `],"recent_blockhash":` + zeros32JSON + `,"instructions":[{"program_id_index":1,"accounts":[0],"data":[1,2,3]}]}}`
	client2, req2 := newMockNode(t, result)

	tx, err := client2.CreateAccountWithFaucet(pk(2))
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req2, "create_account_with_faucet")
	if len(tx.Signatures) != 1 || len(tx.Message.AccountKeys) != 2 || len(tx.Message.Instructions) != 1 {
		t.Errorf("tx = %+v", tx)
	}
	if got := tx.Message.Instructions[0].Data; len(got) != 3 || got[0] != 1 {
		t.Errorf("instruction data = %v", got)
	}
}

func TestGetMultipleAccounts(t *testing.T) {
	client, req := newMockNode(t, `[{"key":`+zeros32JSON+`,"lamports":500,"owner":`+zeros32JSON+`,"data":[],"utxo":"","is_executable":false},null]`)

	accounts, err := client.GetMultipleAccounts([]Pubkey{pk(1), pk(2)})
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_multiple_accounts")

	var params [][]int
	if err := json.Unmarshal(req.Params, &params); err != nil || len(params) != 2 || len(params[0]) != 32 {
		t.Errorf("params must be an array of 32-number arrays, got %s", req.Params)
	}

	if len(accounts) != 2 {
		t.Fatalf("got %d accounts", len(accounts))
	}
	if accounts[0] == nil || accounts[0].Lamports != 500 {
		t.Errorf("accounts[0] = %+v", accounts[0])
	}
	if accounts[1] != nil {
		t.Errorf("accounts[1] = %+v, want nil", accounts[1])
	}
}

func TestGetTransactionsByIdsAndStatus(t *testing.T) {
	client, req := newMockNode(t, `[null]`)
	txs, err := client.GetTransactionsByIds([]string{"aa"})
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_transactions_by_ids")
	if got := paramsJSON(t, req); got != `{"txids":["aa"]}` {
		t.Errorf("params = %s", got)
	}
	if len(txs) != 1 || txs[0] != nil {
		t.Errorf("txs = %v", txs)
	}

	client2, req2 := newMockNode(t, `[{"type":"queued"},null]`)
	statuses, err := client2.GetTransactionStatus([]string{"aa", "bb"})
	if err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req2, "get_transaction_status")
	if got := paramsJSON(t, req2); got != `{"txids":["aa","bb"]}` {
		t.Errorf("params = %s", got)
	}
	if statuses[0] == nil || statuses[0].Type != StatusQueued || statuses[1] != nil {
		t.Errorf("statuses = %v", statuses)
	}
}

func TestRecentTransactionsParamShape(t *testing.T) {
	client, req := newMockNode(t, `[]`)
	limit := uint64(10)
	if _, err := client.RecentTransactions(TransactionListParams{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "recent_transactions")
	// Unset optional fields must be omitted, not null.
	if got := paramsJSON(t, req); got != `{"limit":10}` {
		t.Errorf("params = %s, want {\"limit\":10}", got)
	}
}

func TestGetTransactionsByBlockParamShape(t *testing.T) {
	client, req := newMockNode(t, `[]`)
	if _, err := client.GetTransactionsByBlock(BlockTransactionsParams{BlockHash: "aa"}); err != nil {
		t.Fatal(err)
	}
	checkEnvelope(t, req, "get_transactions_by_block")
	if got := paramsJSON(t, req); got != `{"block_hash":"aa"}` {
		t.Errorf("params = %s", got)
	}
}

func TestCheckPreAnchorConflictAndNetworkPubkey(t *testing.T) {
	client, req := newMockNode(t, `true`)
	conflict, err := client.CheckPreAnchorConflict([]Pubkey{pk(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !conflict {
		t.Error("conflict = false")
	}
	checkEnvelope(t, req, "check_pre_anchor_conflict")

	client2, req2 := newMockNode(t, `"networkpubkey"`)
	npk, err := client2.GetNetworkPubkey()
	if err != nil {
		t.Fatal(err)
	}
	if npk != "networkpubkey" {
		t.Errorf("npk = %q", npk)
	}
	checkEnvelope(t, req2, "get_network_pubkey")
}

func TestRPCErrorPropagation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"code":500,"message":"internal error"}}`))
	}))
	t.Cleanup(server.Close)
	client := NewClient(server.URL, nil)

	_, err := client.GetBestBlockHash()
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *RPCError, got %v", err)
	}
	if rpcErr.Code != 500 || rpcErr.Message != "internal error" {
		t.Errorf("rpcErr = %+v", rpcErr)
	}

	// Non-404 errors must NOT be swallowed by the not-found mapping.
	if _, err := client.GetBlock("x"); err == nil {
		t.Error("expected error for 500 on GetBlock")
	}
}

func TestHTTPErrorPropagation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	client := NewClient(server.URL, nil)
	if _, err := client.GetBestBlockHash(); err == nil {
		t.Error("expected error for HTTP 502")
	}
}
