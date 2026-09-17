package arch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// mockWSServer speaks the validator's WebSocket wire format (arch_sdk's
// subscription.rs): it records incoming requests and lets tests script
// responses and events.
type mockWSServer struct {
	t        *testing.T
	server   *httptest.Server
	requests chan map[string]any
	send     chan any // marshaled and pushed to the client
}

func newMockWSServer(t *testing.T) *mockWSServer {
	m := &mockWSServer{
		t:        t,
		requests: make(chan map[string]any, 16),
		send:     make(chan any, 16),
	}
	upgrader := websocket.Upgrader{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		go func() {
			for msg := range m.send {
				data, err := json.Marshal(msg)
				if err != nil {
					t.Errorf("marshaling server message: %v", err)
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					return
				}
			}
		}()

		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var req map[string]any
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Errorf("unmarshaling client request: %v", err)
				continue
			}
			m.requests <- req
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockWSServer) url() string {
	return "ws" + strings.TrimPrefix(m.server.URL, "http")
}

func (m *mockWSServer) nextRequest(t *testing.T) map[string]any {
	t.Helper()
	select {
	case req := <-m.requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client request")
		return nil
	}
}

func dialMock(t *testing.T, m *mockWSServer) *WSClient {
	t.Helper()
	client, err := DialWebSocket(context.Background(), m.url())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func subscribed(topic EventTopic, id string) map[string]any {
	return map[string]any{"status": "Subscribed", "subscription_id": id, "topic": string(topic)}
}

func TestSubscribeWireFormat(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicTransaction, "sub-1")
	sub, err := client.Subscribe(context.Background(), TopicTransaction, EventFilter{"hash": "tx2"})
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID() != "sub-1" {
		t.Errorf("subscription id = %q, want sub-1", sub.ID())
	}
	if sub.Topic() != TopicTransaction {
		t.Errorf("topic = %q, want transaction", sub.Topic())
	}

	// The request must match arch_sdk's WebSocketRequest serde shape.
	req := m.nextRequest(t)
	if req["method"] != "subscribe" {
		t.Errorf("method = %v, want subscribe", req["method"])
	}
	params, ok := req["params"].(map[string]any)
	if !ok {
		t.Fatalf("params missing or not an object: %v", req["params"])
	}
	if params["topic"] != "transaction" {
		t.Errorf("topic = %v, want transaction", params["topic"])
	}
	filter, ok := params["filter"].(map[string]any)
	if !ok {
		t.Fatalf("filter missing or not an object: %v", params["filter"])
	}
	if filter["hash"] != "tx2" {
		t.Errorf("filter.hash = %v, want tx2", filter["hash"])
	}
}

func TestSubscribeEmptyFilterSerializesAsEmptyObject(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicBlock, "sub-1")
	if _, err := client.Subscribe(context.Background(), TopicBlock, nil); err != nil {
		t.Fatal(err)
	}

	req := m.nextRequest(t)
	params := req["params"].(map[string]any)
	filter, ok := params["filter"].(map[string]any)
	if !ok || len(filter) != 0 {
		t.Errorf("filter = %v, want {}", params["filter"])
	}
}

func TestEventDeliveryAndTypedDecoding(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicTransaction, "sub-1")
	sub, err := client.Subscribe(context.Background(), TopicTransaction, nil)
	if err != nil {
		t.Fatal(err)
	}

	// An event on another topic must not be delivered.
	m.send <- map[string]any{
		"topic": "block",
		"data":  map[string]any{"hash": "blk", "timestamp": "12345678901234567890"},
	}
	// The node serializes TransactionEvent with a type-tagged status.
	m.send <- map[string]any{
		"topic": "transaction",
		"data": map[string]any{
			"hash":         "tx2",
			"status":       map[string]any{"type": "failed", "message": "compute budget exceeded"},
			"program_ids":  []string{"p1", "p2"},
			"block_height": 42,
		},
	}

	select {
	case ev := <-sub.Events():
		if ev.Topic != TopicTransaction {
			t.Fatalf("received topic %q, want transaction", ev.Topic)
		}
		txEv, err := ev.Transaction()
		if err != nil {
			t.Fatal(err)
		}
		if txEv.Hash != "tx2" || txEv.Status.Type != StatusFailed ||
			txEv.Status.Message != "compute budget exceeded" ||
			len(txEv.ProgramIDs) != 2 || txEv.BlockHeight != 42 {
			t.Errorf("unexpected event payload: %+v", txEv)
		}
		if _, err := ev.Block(); err == nil {
			t.Error("Block() on a transaction event should fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBlockEventDecoding(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicBlock, "sub-1")
	sub, err := client.Subscribe(context.Background(), TopicBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	// BlockEvent timestamps are u128 values serialized as strings.
	m.send <- map[string]any{
		"topic": "block",
		"data":  map[string]any{"hash": "blockhash", "timestamp": "340282366920938463463374607431768211455"},
	}

	select {
	case ev := <-sub.Events():
		blockEv, err := ev.Block()
		if err != nil {
			t.Fatal(err)
		}
		if blockEv.Hash != "blockhash" || blockEv.Timestamp != "340282366920938463463374607431768211455" {
			t.Errorf("unexpected payload: %+v", blockEv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestSubscribeErrorResponse(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- map[string]any{"status": "Error", "error": "Failed to parse request"}
	_, err := client.Subscribe(context.Background(), TopicDKG, nil)
	if err == nil || !strings.Contains(err.Error(), "Failed to parse request") {
		t.Errorf("err = %v, want error containing server message", err)
	}
}

func TestUnsubscribe(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicDKG, "sub-9")
	sub, err := client.Subscribe(context.Background(), TopicDKG, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.nextRequest(t) // consume the subscribe request

	m.send <- map[string]any{
		"status":          "Unsubscribed",
		"subscription_id": "sub-9",
		"message":         "Unsubscribed successfully",
	}
	if err := sub.Unsubscribe(context.Background()); err != nil {
		t.Fatal(err)
	}

	req := m.nextRequest(t)
	if req["method"] != "unsubscribe" {
		t.Errorf("method = %v, want unsubscribe", req["method"])
	}
	params := req["params"].(map[string]any)
	if params["topic"] != "dkg" || params["subscription_id"] != "sub-9" {
		t.Errorf("unexpected unsubscribe params: %v", params)
	}

	// The events channel must be closed.
	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("received event after unsubscribe")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("events channel not closed after unsubscribe")
	}
}

func TestCloseFailsPendingAndClosesChannels(t *testing.T) {
	m := newMockWSServer(t)
	client := dialMock(t, m)

	m.send <- subscribed(TopicBlock, "sub-1")
	sub, err := client.Subscribe(context.Background(), TopicBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	client.Close()

	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("received event after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("events channel not closed after close")
	}

	if _, err := client.Subscribe(context.Background(), TopicDKG, nil); err == nil {
		t.Error("Subscribe after Close should fail")
	}
}
