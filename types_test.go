package arch

import (
	"encoding/json"
	"reflect"
	"testing"
)

// These tests port the request/response shape pins from arch-network's
// sdk/tests/rpc_wire_format.rs.

func TestPubkeyJSONIsNumberArray(t *testing.T) {
	var p Pubkey
	for i := range p {
		p[i] = byte(i + 1)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var arr []int
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatalf("pubkey must marshal as JSON array of numbers, got %s", b)
	}
	if len(arr) != 32 || arr[0] != 1 || arr[31] != 32 {
		t.Errorf("unexpected pubkey array: %v", arr)
	}
}

func TestSignatureJSONIsNumberArray(t *testing.T) {
	var s Signature
	for i := range s {
		s[i] = 42
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var arr []int
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatalf("signature must marshal as JSON array, got %s", b)
	}
	if len(arr) != 64 || arr[0] != 42 {
		t.Errorf("unexpected signature array: %v", arr)
	}
}

func TestBytesJSON(t *testing.T) {
	b, err := json.Marshal(Bytes{1, 2, 255})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[1,2,255]" {
		t.Errorf("Bytes marshal = %s, want [1,2,255]", b)
	}

	if b, _ := json.Marshal(Bytes(nil)); string(b) != "[]" {
		t.Errorf("nil Bytes marshal = %s, want []", b)
	}

	var out Bytes
	if err := json.Unmarshal([]byte("[3,4,5]"), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != 3 || out[2] != 5 {
		t.Errorf("Bytes unmarshal = %v", out)
	}

	if err := json.Unmarshal([]byte("[300]"), &out); err == nil {
		t.Error("expected error for out-of-range byte")
	}
}

func TestRuntimeTransactionJSONShape(t *testing.T) {
	tx := RuntimeTransaction{
		Version:    0,
		Signatures: []Signature{{1}},
		Message: SanitizedMessage{
			Header:          MessageHeader{NumRequiredSignatures: 1, NumReadonlyUnsignedAccounts: 1},
			AccountKeys:     []Pubkey{SystemProgramID, pk(1)},
			RecentBlockhash: Hash{},
			Instructions:    []SanitizedInstruction{{ProgramIDIndex: 1, Accounts: Bytes{0}, Data: Bytes{1, 2, 3}}},
		},
	}

	b, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "signatures", "message"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("missing top-level field %q", key)
		}
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(obj["message"], &msg); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"header", "account_keys", "recent_blockhash", "instructions"} {
		if _, ok := msg[key]; !ok {
			t.Errorf("missing message field %q", key)
		}
	}

	var hdr map[string]int
	if err := json.Unmarshal(msg["header"], &hdr); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"num_required_signatures", "num_readonly_signed_accounts", "num_readonly_unsigned_accounts"} {
		if _, ok := hdr[key]; !ok {
			t.Errorf("missing header field %q", key)
		}
	}

	// Round trip.
	var tx2 RuntimeTransaction
	if err := json.Unmarshal(b, &tx2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx, tx2) {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", tx2, tx)
	}
}

func TestAccountFilterJSON(t *testing.T) {
	b, err := json.Marshal(DataSizeFilter(32))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"DataSize":32}` {
		t.Errorf("DataSize filter = %s", b)
	}

	b, err = json.Marshal(DataContentFilter(8, []byte{0xFF, 0x01}))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"DataContent":{"offset":8,"bytes":[255,1]}}` {
		t.Errorf("DataContent filter = %s", b)
	}
}

func TestBlockTransactionFilterJSON(t *testing.T) {
	b, _ := json.Marshal(BlockTransactionFilterFull)
	if string(b) != `"full"` {
		t.Errorf("full filter = %s", b)
	}
	b, _ = json.Marshal(BlockTransactionFilterSignatures)
	if string(b) != `"signatures"` {
		t.Errorf("signatures filter = %s", b)
	}
}

func TestStatusDeserialization(t *testing.T) {
	var s ProcessedTransactionStatus
	if err := json.Unmarshal([]byte(`{"type":"queued"}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Type != StatusQueued {
		t.Errorf("type = %s", s.Type)
	}

	if err := json.Unmarshal([]byte(`{"type":"failed","message":"out of gas"}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Type != StatusFailed || s.Message != "out of gas" {
		t.Errorf("failed status = %+v", s)
	}

	var rb RollbackStatus
	if err := json.Unmarshal([]byte(`{"type":"rolledback","message":"conflict detected"}`), &rb); err != nil {
		t.Fatal(err)
	}
	if rb.Type != RollbackStatusRolledback || rb.Message != "conflict detected" {
		t.Errorf("rollback status = %+v", rb)
	}
}

func TestProcessedTransactionRoundTrip(t *testing.T) {
	txid := Hash{0xFF}
	pt := ProcessedTransaction{
		RuntimeTransaction: RuntimeTransaction{
			Version:    0,
			Signatures: []Signature{},
			Message: SanitizedMessage{
				AccountKeys:  []Pubkey{},
				Instructions: []SanitizedInstruction{},
			},
		},
		Status:                ProcessedTransactionStatus{Type: StatusFailed, Message: "test error"},
		BitcoinTxid:           &txid,
		Logs:                  []string{"log1", "log2"},
		RollbackStatus:        RollbackStatus{Type: RollbackStatusRolledback, Message: "reason"},
		InnerInstructionsList: [][]InnerInstruction{},
	}

	b, err := json.Marshal(pt)
	if err != nil {
		t.Fatal(err)
	}
	var pt2 ProcessedTransaction
	if err := json.Unmarshal(b, &pt2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pt, pt2) {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", pt2, pt)
	}

	// bitcoin_txid: null must decode to nil.
	var pt3 ProcessedTransaction
	fixture := `{"runtime_transaction":{"version":0,"signatures":[],"message":{"header":{"num_required_signatures":0,"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":0},"account_keys":[],"recent_blockhash":` + zeros32JSON + `,"instructions":[]}},"status":{"type":"processed"},"bitcoin_txid":null,"logs":[],"rollback_status":{"type":"notRolledback"},"inner_instructions_list":[]}`
	if err := json.Unmarshal([]byte(fixture), &pt3); err != nil {
		t.Fatal(err)
	}
	if pt3.BitcoinTxid != nil {
		t.Error("bitcoin_txid null should decode to nil")
	}
	if pt3.Status.Type != StatusProcessed {
		t.Errorf("status = %+v", pt3.Status)
	}
}

func TestBlockRoundTrip(t *testing.T) {
	blk := Block{
		Transactions:       []Hash{{1}, {2}},
		PreviousBlockHash:  Hash{3},
		Timestamp:          1700000000000,
		BlockHeight:        100,
		BitcoinBlockHeight: 800000,
	}
	b, err := json.Marshal(blk)
	if err != nil {
		t.Fatal(err)
	}
	var blk2 Block
	if err := json.Unmarshal(b, &blk2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(blk, blk2) {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", blk2, blk)
	}
}
