package arch

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestNetworkPubkeyFromHex(t *testing.T) {
	// get_network_pubkey returns a 33-byte compressed key.
	compressed := "034095f844aa2cb09b24380a7fea313f17bba8878675d8ebe329bd132484452b29"
	got, err := NetworkPubkeyFromHex(compressed)
	if err != nil {
		t.Fatal(err)
	}
	want := mustPubkey(t, compressed[2:])
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	// A 32-byte x-only key passes through.
	if got, err := NetworkPubkeyFromHex(compressed[2:]); err != nil || got != want {
		t.Errorf("x-only passthrough failed: %v %s", err, got)
	}

	if _, err := NetworkPubkeyFromHex("beef"); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestAccountAddressMatchesTestnetNode(t *testing.T) {
	// Fixture captured live from rpc.testnet.arch.network (node v0.10.0):
	// get_network_pubkey and get_account_address for account [7u8; 32], and
	// reproduced with arch-network v0.10.0's build_account_address.
	networkKey := mustPubkey(t, "4095f844aa2cb09b24380a7fea313f17bba8878675d8ebe329bd132484452b29")
	var account Pubkey
	for i := range account {
		account[i] = 7
	}

	addr, err := AccountAddress(networkKey, account, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	want := "tb1pa5rz5t0v5d5qtcl49n59qqm0plssq66y5yje77hkeyhwyzf67l8q6waj66"
	if addr != want {
		t.Errorf("address = %s, want %s", addr, want)
	}
}
