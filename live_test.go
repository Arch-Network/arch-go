package arch

// Live integration test against a real Arch node. Skipped unless ARCH_RPC_URL
// is set:
//
//	ARCH_RPC_URL=https://rpc.testnet.arch.network go test -run TestLive -v -timeout 600s
//
// The test is read-mostly; on networks with a faucet it also creates and
// funds throwaway accounts and submits real transactions signed by this SDK.

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestLiveTestnet(t *testing.T) {
	url := os.Getenv("ARCH_RPC_URL")
	if url == "" {
		t.Skip("set ARCH_RPC_URL to run live tests")
	}
	client := NewClient(url, &http.Client{Timeout: 30 * time.Second})

	// --- Read-only surface ---

	count, err := client.GetBlockCount()
	if err != nil {
		t.Fatalf("get_block_count: %v", err)
	}
	if count == 0 {
		t.Fatal("block count is zero")
	}
	t.Logf("block count: %d", count)

	bestHash, err := client.GetBestBlockHash()
	if err != nil {
		t.Fatalf("get_best_block_hash: %v", err)
	}
	t.Logf("best block hash: %s", bestHash)

	finalized, err := client.GetBestFinalizedBlockHash()
	if err != nil {
		t.Fatalf("get_best_finalized_block_hash: %v", err)
	}
	t.Logf("best finalized block hash: %s", finalized)

	block, err := client.GetBlock(bestHash)
	if err != nil {
		t.Fatalf("get_block: %v", err)
	}
	if block == nil {
		t.Fatal("best block not found by its own hash")
	}
	t.Logf("best block: height=%d bitcoin_height=%d txs=%d",
		block.BlockHeight, block.BitcoinBlockHeight, len(block.Transactions))

	byHeight, err := client.GetBlockByHeight(block.BlockHeight)
	if err != nil {
		t.Fatalf("get_block_by_height: %v", err)
	}
	if byHeight == nil || byHeight.PreviousBlockHash != block.PreviousBlockHash {
		t.Error("get_block_by_height disagrees with get_block")
	}

	hashAtHeight, err := client.GetBlockHash(block.BlockHeight)
	if err != nil {
		t.Fatalf("get_block_hash: %v", err)
	}
	if hashAtHeight != bestHash {
		t.Errorf("get_block_hash(%d) = %s, want %s", block.BlockHeight, hashAtHeight, bestHash)
	}

	networkPubkey, err := client.GetNetworkPubkey()
	if err != nil {
		t.Fatalf("get_network_pubkey: %v", err)
	}
	t.Logf("network pubkey: %s", networkPubkey)

	recent, err := client.RecentTransactions(TransactionListParams{})
	if err != nil {
		t.Fatalf("recent_transactions: %v", err)
	}
	t.Logf("recent transactions: %d", len(recent))
	if len(recent) > 0 {
		txid := recent[0].RuntimeTransaction.TxID()
		processed, err := client.GetProcessedTransaction(txid)
		if err != nil {
			t.Fatalf("get_processed_transaction(%s): %v", txid, err)
		}
		if processed == nil {
			t.Errorf("recent transaction %s not found by id", txid)
		} else {
			t.Logf("fetched recent tx %s, status=%s", txid, processed.Status.Type)
		}
	}

	// Missing entities must map to nil, not an error.
	missing, err := client.GetProcessedTransaction(
		"00000000000000000000000000000000000000000000000000000000000000ff")
	if err != nil {
		t.Fatalf("get_processed_transaction(missing): %v", err)
	}
	if missing != nil {
		t.Error("expected nil for unknown txid")
	}

	// --- Key and address derivation against the node ---

	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey := XOnlyPubkey(priv)

	nodeAddress, err := client.GetAccountAddress(pubkey)
	if err != nil {
		t.Fatalf("get_account_address: %v", err)
	}
	networkKey, err := NetworkPubkeyFromHex(networkPubkey)
	if err != nil {
		t.Fatal(err)
	}
	// Testnet bech32m addresses use the "tb" prefix (shared by testnet3/4).
	localAddress, err := AccountAddress(networkKey, pubkey, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	if nodeAddress != localAddress {
		t.Fatalf("node address %s != local AccountAddress derivation %s", nodeAddress, localAddress)
	}
	t.Logf("offline account-address derivation matches node: %s", nodeAddress)

	// --- Faucet + real signed transactions (testnet/regtest only) ---

	faucetTx, err := client.CreateAccountWithFaucet(pubkey)
	if err != nil {
		t.Logf("create_account_with_faucet unavailable (%v); skipping write path", err)
		return
	}
	t.Logf("faucet transaction: version=%d signers=%d required=%d",
		faucetTx.Version, len(faucetTx.Signatures), faucetTx.Message.Header.NumRequiredSignatures)

	// The faucet signs as payer; the account being created co-signs.
	sig, err := SignMessageBIP322(priv, faucetTx.Message.Hash())
	if err != nil {
		t.Fatal(err)
	}
	faucetTx.Signatures = append(faucetTx.Signatures, sig)

	txid, err := client.SendTransaction(faucetTx)
	if err != nil {
		t.Fatalf("send_transaction(faucet tx): %v", err)
	}
	t.Logf("faucet txid: %s", txid)
	waitProcessed(t, client, txid)

	funded, err := client.ReadAccountInfo(pubkey)
	if err != nil {
		t.Fatalf("read_account_info(funded): %v", err)
	}
	t.Logf("funded account: %d lamports, owner %s, utxo %s", funded.Lamports, funded.Owner, funded.Utxo)
	if funded.Lamports == 0 {
		t.Fatal("faucet account has no lamports")
	}

	// Build, hash, and BIP-322-sign a transaction with this SDK: create a
	// second account funded from the first.
	priv2, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey2 := XOnlyPubkey(priv2)

	blockhash, err := HashFromHex(bestHash)
	if err != nil {
		t.Fatal(err)
	}
	sendLamports := funded.Lamports / 2
	message, err := NewSanitizedMessage(
		[]Instruction{CreateAccount(pubkey, pubkey2, sendLamports, 0, SystemProgramID)},
		&pubkey,
		blockhash,
	)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := BuildAndSignTransaction(message, priv, priv2)
	if err != nil {
		t.Fatal(err)
	}

	txid2, err := client.SendTransaction(tx)
	if err != nil {
		t.Fatalf("send_transaction(SDK-signed create_account): %v", err)
	}
	if want := tx.TxID(); txid2 != want {
		t.Errorf("node txid %s != local TxID() %s", txid2, want)
	}
	t.Logf("SDK-signed txid: %s", txid2)
	waitProcessed(t, client, txid2)

	account2, err := client.ReadAccountInfo(pubkey2)
	if err != nil {
		t.Fatalf("read_account_info(new account): %v", err)
	}
	if account2.Lamports != sendLamports {
		t.Errorf("new account lamports = %d, want %d", account2.Lamports, sendLamports)
	}
	t.Logf("SDK-signed transaction accepted; new account holds %d lamports", account2.Lamports)
}

// waitProcessed polls until the transaction reaches a terminal status and
// fails the test if it did not process successfully.
func waitProcessed(t *testing.T, client *Client, txid string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		processed, err := client.GetProcessedTransaction(txid)
		if err != nil {
			t.Fatalf("get_processed_transaction(%s): %v", txid, err)
		}
		if processed != nil {
			switch processed.Status.Type {
			case StatusProcessed:
				return
			case StatusFailed:
				t.Fatalf("transaction %s failed: %s\nlogs: %v",
					txid, processed.Status.Message, processed.Logs)
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("transaction %s not processed within 90s", txid)
}
