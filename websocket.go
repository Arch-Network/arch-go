package arch

// WebSocket event subscriptions. The Arch validator exposes a plain WebSocket
// server (default port 10081) speaking newline-free JSON text messages whose
// wire format is defined by arch_sdk's subscription.rs and event.rs:
//
//	subscribe:   {"method":"subscribe","params":{"topic":...,"filter":{...},"request_id":...}}
//	unsubscribe: {"method":"unsubscribe","params":{"topic":...,"subscription_id":...}}
//	response:    {"status":"Subscribed"|"Unsubscribed"|"Error", ...}
//	event:       {"topic":...,"data":{...}}
//
// Responses to requests are returned in request order on the connection, so
// the client correlates them FIFO. Events carry no subscription id; they are
// dispatched to every local subscription on the matching topic.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
)

// EventTopic is a subscription topic.
type EventTopic string

// Subscription topics, matching arch_sdk::EventTopic's serde names.
const (
	TopicBlock                  EventTopic = "block"
	TopicTransaction            EventTopic = "transaction"
	TopicAccountUpdate          EventTopic = "account_update"
	TopicRolledbackTransactions EventTopic = "rolledback_transactions"
	TopicReappliedTransactions  EventTopic = "reapplied_transactions"
	TopicDKG                    EventTopic = "dkg"
)

// EventFilter is a server-side event filter: a map of event data fields to
// required values. Scalar values must match exactly; an array value matches
// if the event's array field contains any of the listed values. An empty (or
// nil) filter matches every event on the topic.
type EventFilter map[string]any

// Event is a notification pushed by the node. Data is the topic-specific
// payload; decode it with the typed accessors.
type Event struct {
	Topic EventTopic      `json:"topic"`
	Data  json.RawMessage `json:"data"`
}

// BlockEvent is the payload of TopicBlock events. Timestamp is a decimal
// string (the node serializes its u128 milliseconds value as a string).
type BlockEvent struct {
	Hash      string `json:"hash"`
	Timestamp string `json:"timestamp"`
}

// TransactionEvent is the payload of TopicTransaction events.
type TransactionEvent struct {
	Hash        string                     `json:"hash"`
	Status      ProcessedTransactionStatus `json:"status"`
	ProgramIDs  []string                   `json:"program_ids"`
	BlockHeight uint64                     `json:"block_height"`
}

// AccountUpdateEvent is the payload of TopicAccountUpdate events.
type AccountUpdateEvent struct {
	Account         string `json:"account"`
	TransactionHash string `json:"transaction_hash"`
	BlockHeight     uint64 `json:"block_height"`
}

// TransactionsEvent is the payload of TopicRolledbackTransactions and
// TopicReappliedTransactions events.
type TransactionsEvent struct {
	BlockHeight       uint64   `json:"block_height"`
	TransactionHashes []string `json:"transaction_hashes"`
}

// DKGEvent is the payload of TopicDKG events.
type DKGEvent struct {
	Status string `json:"status"`
}

func decodeEvent[T any](e Event, topics ...EventTopic) (T, error) {
	var out T
	ok := false
	for _, t := range topics {
		ok = ok || e.Topic == t
	}
	if !ok {
		return out, fmt.Errorf("event topic is %q, not %v", e.Topic, topics)
	}
	if err := json.Unmarshal(e.Data, &out); err != nil {
		return out, fmt.Errorf("decoding %s event: %w", e.Topic, err)
	}
	return out, nil
}

// Block decodes a TopicBlock event payload.
func (e Event) Block() (BlockEvent, error) {
	return decodeEvent[BlockEvent](e, TopicBlock)
}

// Transaction decodes a TopicTransaction event payload.
func (e Event) Transaction() (TransactionEvent, error) {
	return decodeEvent[TransactionEvent](e, TopicTransaction)
}

// AccountUpdate decodes a TopicAccountUpdate event payload.
func (e Event) AccountUpdate() (AccountUpdateEvent, error) {
	return decodeEvent[AccountUpdateEvent](e, TopicAccountUpdate)
}

// Transactions decodes a TopicRolledbackTransactions or
// TopicReappliedTransactions event payload.
func (e Event) Transactions() (TransactionsEvent, error) {
	return decodeEvent[TransactionsEvent](e, TopicRolledbackTransactions, TopicReappliedTransactions)
}

// DKG decodes a TopicDKG event payload.
func (e Event) DKG() (DKGEvent, error) {
	return decodeEvent[DKGEvent](e, TopicDKG)
}

type wsRequest struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type wsSubscribeParams struct {
	Topic  EventTopic  `json:"topic"`
	Filter EventFilter `json:"filter"`
}

type wsUnsubscribeParams struct {
	Topic          EventTopic `json:"topic"`
	SubscriptionID string     `json:"subscription_id"`
}

// wsResponse is the union of the node's subscribe/unsubscribe/error
// responses.
type wsResponse struct {
	Status         string `json:"status"`
	SubscriptionID string `json:"subscription_id"`
	Message        string `json:"message"`
	Error          string `json:"error"`
}

// subEventBuffer is the per-subscription event channel capacity. If a
// consumer falls this far behind, further events are dropped.
const subEventBuffer = 256

// Subscription is an active event subscription. Read events from Events();
// the channel is closed when the subscription is unsubscribed or the client
// closes.
type Subscription struct {
	id     string
	topic  EventTopic
	events chan Event
	client *WSClient
	once   sync.Once
}

// ID returns the server-issued subscription id.
func (s *Subscription) ID() string { return s.id }

// Topic returns the subscribed topic.
func (s *Subscription) Topic() EventTopic { return s.topic }

// Events returns the channel on which matching events are delivered. Events
// are dropped if the consumer falls more than subEventBuffer events behind.
func (s *Subscription) Events() <-chan Event { return s.events }

// Unsubscribe cancels the subscription on the server and closes the events
// channel.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	resp, err := s.client.roundTrip(ctx, wsRequest{
		Method: "unsubscribe",
		Params: wsUnsubscribeParams{Topic: s.topic, SubscriptionID: s.id},
	})
	s.client.removeSubscription(s)
	if err != nil {
		return err
	}
	if resp.Status != "Unsubscribed" {
		return fmt.Errorf("unsubscribe failed: %s%s", resp.Message, resp.Error)
	}
	return nil
}

// WSClient is a client for the node's WebSocket subscription server.
// Construct one with DialWebSocket. Methods are safe for concurrent use.
type WSClient struct {
	conn *websocket.Conn

	writeMu sync.Mutex // serializes writes to conn

	mu      sync.Mutex
	pending []chan wsResponse // FIFO of requests awaiting a response
	subs    map[EventTopic][]*Subscription
	closed  bool
	readErr error

	done chan struct{}
}

// DialWebSocket connects to a node's WebSocket endpoint
// (e.g. "ws://localhost:10081").
func DialWebSocket(ctx context.Context, url string) (*WSClient, error) {
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, url, nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", url, err)
	}
	c := &WSClient{
		conn: conn,
		subs: make(map[EventTopic][]*Subscription),
		done: make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Subscribe subscribes to a topic. filter may be nil to receive every event
// on the topic.
func (c *WSClient) Subscribe(ctx context.Context, topic EventTopic, filter EventFilter) (*Subscription, error) {
	if filter == nil {
		filter = EventFilter{}
	}

	// Register before sending so no event published right after the server's
	// confirmation can be missed.
	sub := &Subscription{topic: topic, events: make(chan Event, subEventBuffer), client: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, c.closeReason()
	}
	c.subs[topic] = append(c.subs[topic], sub)
	c.mu.Unlock()

	resp, err := c.roundTrip(ctx, wsRequest{
		Method: "subscribe",
		Params: wsSubscribeParams{Topic: topic, Filter: filter},
	})
	if err != nil {
		c.removeSubscription(sub)
		return nil, err
	}
	if resp.Status != "Subscribed" {
		c.removeSubscription(sub)
		return nil, fmt.Errorf("subscribe failed: %s", resp.Error)
	}
	sub.id = resp.SubscriptionID
	return sub, nil
}

// Close closes the connection. All subscriptions' event channels are closed
// and pending calls fail.
func (c *WSClient) Close() error {
	return c.conn.Close()
}

// roundTrip sends a request and waits for the node's response, correlating
// FIFO (the node answers requests in order on a connection).
func (c *WSClient) roundTrip(ctx context.Context, req wsRequest) (wsResponse, error) {
	respCh := make(chan wsResponse, 1)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return wsResponse{}, c.closeReason()
	}
	c.pending = append(c.pending, respCh)
	c.mu.Unlock()

	c.writeMu.Lock()
	err := c.conn.WriteJSON(req)
	c.writeMu.Unlock()
	if err != nil {
		return wsResponse{}, fmt.Errorf("sending %s request: %w", req.Method, err)
	}

	select {
	case resp, ok := <-respCh:
		if !ok {
			return wsResponse{}, c.closeReason()
		}
		return resp, nil
	case <-ctx.Done():
		return wsResponse{}, ctx.Err()
	case <-c.done:
		return wsResponse{}, c.closeReason()
	}
}

func (c *WSClient) closeReason() error {
	if c.readErr != nil {
		return fmt.Errorf("websocket connection closed: %w", c.readErr)
	}
	return fmt.Errorf("websocket connection closed")
}

func (c *WSClient) removeSubscription(sub *Subscription) {
	c.mu.Lock()
	subs := c.subs[sub.topic]
	for i, s := range subs {
		if s == sub {
			c.subs[sub.topic] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	c.mu.Unlock()
	sub.once.Do(func() { close(sub.events) })
}

// wsMessage is the union shape of everything the server sends: events have
// topic+data, responses have status.
type wsMessage struct {
	Topic  EventTopic      `json:"topic"`
	Data   json.RawMessage `json:"data"`
	Status string          `json:"status"`

	SubscriptionID string `json:"subscription_id"`
	Message        string `json:"message"`
	Error          string `json:"error"`
}

func (c *WSClient) readLoop() {
	var readErr error
	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			readErr = err
			break
		}
		var msg wsMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue // not a message shape we know; ignore
		}

		if msg.Data != nil {
			// Event: fan out to every subscription on the topic.
			c.mu.Lock()
			subs := append([]*Subscription(nil), c.subs[msg.Topic]...)
			c.mu.Unlock()
			for _, sub := range subs {
				select {
				case sub.events <- Event{Topic: msg.Topic, Data: msg.Data}:
				default: // consumer too slow; drop
				}
			}
			continue
		}

		if msg.Status != "" {
			// Response: deliver to the oldest pending request.
			c.mu.Lock()
			var respCh chan wsResponse
			if len(c.pending) > 0 {
				respCh = c.pending[0]
				c.pending = c.pending[1:]
			}
			c.mu.Unlock()
			if respCh != nil {
				respCh <- wsResponse{
					Status:         msg.Status,
					SubscriptionID: msg.SubscriptionID,
					Message:        msg.Message,
					Error:          msg.Error,
				}
			}
		}
	}

	// Tear down: fail pending calls and close subscription channels.
	c.mu.Lock()
	c.closed = true
	c.readErr = readErr
	pending := c.pending
	c.pending = nil
	var allSubs []*Subscription
	for _, subs := range c.subs {
		allSubs = append(allSubs, subs...)
	}
	c.subs = make(map[EventTopic][]*Subscription)
	c.mu.Unlock()

	close(c.done)
	for _, ch := range pending {
		close(ch)
	}
	for _, sub := range allSubs {
		sub.once.Do(func() { close(sub.events) })
	}
	c.conn.Close()
}
