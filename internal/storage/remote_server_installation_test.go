package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func newRemoteInstallationTestServer(t *testing.T) (*TrafficRepository, RemoteServer) {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "installation.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := RemoteServer{
		Name:           "install-edge",
		Token:          "install-edge-token",
		Status:         RemoteServerStatusPending,
		ConnectionMode: ConnectionModeWebSocket,
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	return repo, server
}

func TestRemoteServerInstallationLifecycleStoresOnlyNonceDigest(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	nonce := "one-time-installation-nonce"
	expiresAt := time.Now().Add(time.Minute)

	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, nonce, expiresAt); err != nil {
		t.Fatalf("BeginRemoteServerInstallation: %v", err)
	}

	var storedHash string
	if err := repo.db.QueryRowContext(ctx,
		`SELECT nonce_hash FROM remote_server_installations WHERE server_id = ?`, server.ID,
	).Scan(&storedHash); err != nil {
		t.Fatalf("read nonce hash: %v", err)
	}
	if storedHash == nonce || storedHash != remoteInstallationNonceHash(nonce) || len(storedHash) != 64 {
		t.Fatalf("stored nonce digest=%q", storedHash)
	}

	active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID)
	if err != nil || !active {
		t.Fatalf("IsRemoteServerInstallationActive=(%v, %v), want (true, nil)", active, err)
	}
	valid, err := repo.ValidateRemoteServerInstallation(ctx, server.ID, nonce)
	if err != nil || !valid {
		t.Fatalf("ValidateRemoteServerInstallation=(%v, %v), want (true, nil)", valid, err)
	}
	valid, err = repo.ValidateRemoteServerInstallation(ctx, server.ID, "wrong-nonce")
	if err != nil || valid {
		t.Fatalf("wrong nonce validation=(%v, %v), want (false, nil)", valid, err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, nonce); !errors.Is(err, ErrRemoteInstallationNotReady) {
		t.Fatalf("Finalize before ready error=%v", err)
	}
	if ready, err := repo.ValidateRemoteServerInstallationReady(ctx, server.ID, nonce); err != nil || ready {
		t.Fatalf("ready validation before MarkReady=(%v, %v)", ready, err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, nonce); !errors.Is(err, ErrRemoteInstallationNotReady) {
		t.Fatalf("MarkPrepared before ready error=%v", err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, "wrong-nonce"); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("MarkReady wrong nonce error=%v", err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, nonce); err != nil {
		t.Fatalf("MarkRemoteServerInstallationReady: %v", err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, nonce); err != nil {
		t.Fatalf("idempotent MarkRemoteServerInstallationReady: %v", err)
	}
	if ready, err := repo.ValidateRemoteServerInstallationReady(ctx, server.ID, nonce); err != nil || !ready {
		t.Fatalf("ready validation after MarkReady=(%v, %v)", ready, err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, nonce); !errors.Is(err, ErrRemoteInstallationNotPrepared) {
		t.Fatalf("Finalize before prepare error=%v", err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, "wrong-nonce"); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("MarkPrepared wrong nonce error=%v", err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, nonce); err != nil {
		t.Fatalf("MarkRemoteServerInstallationPrepared: %v", err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, nonce); err != nil {
		t.Fatalf("idempotent MarkRemoteServerInstallationPrepared: %v", err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, nonce); err != nil {
		t.Fatalf("FinalizeRemoteServerInstallation: %v", err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, nonce); err != nil {
		t.Fatalf("idempotent FinalizeRemoteServerInstallation: %v", err)
	}
	active, err = repo.IsRemoteServerInstallationActive(ctx, server.ID)
	if err != nil || active {
		t.Fatalf("active after finalize=(%v, %v), want (false, nil)", active, err)
	}
	if valid, err := repo.ValidateRemoteServerInstallation(ctx, server.ID, nonce); err != nil || valid {
		t.Fatalf("completed transaction validates=(%v, %v), want false", valid, err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, nonce, time.Now().Add(10*time.Minute)); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("same-nonce Begin after completion error=%v", err)
	}
	if active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID); err != nil || active {
		t.Fatalf("same-nonce retry reactivated tombstone: active=%v err=%v", active, err)
	}
	var completedAt int64
	if err := repo.db.QueryRowContext(ctx,
		`SELECT completed_at FROM remote_server_installations WHERE server_id = ?`, server.ID,
	).Scan(&completedAt); err != nil || completedAt == 0 {
		t.Fatalf("completed tombstone missing: completed_at=%d err=%v", completedAt, err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, nonce); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("Abort completed transaction error=%v", err)
	}
}

func TestRemoteServerInstallTicketIsDigestOnlySingleUseAndExpires(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	ticket := "short-lived-one-time-install-ticket"
	if err := repo.CreateRemoteServerInstallTicket(ctx, server.ID, ticket, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := repo.db.QueryRowContext(ctx, `SELECT ticket_hash FROM remote_server_install_tickets WHERE server_id = ?`, server.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == ticket || stored != remoteInstallationNonceHash(ticket) {
		t.Fatalf("stored ticket=%q", stored)
	}
	consumed, err := repo.ConsumeRemoteServerInstallTicket(ctx, ticket, time.Now())
	if err != nil || consumed.ID != server.ID {
		t.Fatalf("ConsumeRemoteServerInstallTicket=(%+v, %v)", consumed, err)
	}
	if _, err := repo.ConsumeRemoteServerInstallTicket(ctx, ticket, time.Now()); !errors.Is(err, ErrRemoteInstallTicketInvalid) {
		t.Fatalf("second consume error=%v", err)
	}
	expired := "expired-install-ticket"
	if err := repo.CreateRemoteServerInstallTicket(ctx, server.ID, expired, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeRemoteServerInstallTicket(ctx, expired, time.Now().Add(2*time.Minute)); !errors.Is(err, ErrRemoteInstallTicketInvalid) {
		t.Fatalf("expired consume error=%v", err)
	}
}

func TestRemoteServerInstallationRenewalHonorsHardDeadlineAndTerminalStates(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	nonce := "renewable-installation-nonce"
	started := time.Now()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, nonce, started.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Place the transaction one minute before its absolute deadline while
	// keeping its current lease live, then verify renewal clamps to the cap.
	storedStarted := time.Now().Add(-119 * time.Minute).UnixNano()
	if _, err := repo.db.ExecContext(ctx, `UPDATE remote_server_installations SET started_at = ?, expires_at = ? WHERE server_id = ?`,
		storedStarted, time.Now().Add(10*time.Minute).UnixNano(), server.ID); err != nil {
		t.Fatal(err)
	}
	renewAt := time.Now()
	if err := repo.RenewRemoteServerInstallation(ctx, server.ID, nonce, renewAt, 30*time.Minute, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	var expiresAt int64
	if err := repo.db.QueryRowContext(ctx, `SELECT expires_at FROM remote_server_installations WHERE server_id = ?`, server.ID).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	hardDeadline := time.Unix(0, storedStarted).Add(2 * time.Hour).UnixNano()
	if expiresAt != hardDeadline {
		t.Fatalf("renewed expiry=%d want hard deadline=%d", expiresAt, hardDeadline)
	}
	if err := repo.RenewRemoteServerInstallation(ctx, server.ID, nonce, time.Unix(0, hardDeadline), 30*time.Minute, 2*time.Hour); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("renew at hard deadline error=%v", err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, nonce); err != nil {
		t.Fatal(err)
	}

	rollingNonce := "rolling-back-renewal-nonce"
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, rollingNonce, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerInstallationRollingBack(ctx, server.ID, rollingNonce); err != nil {
		t.Fatal(err)
	}
	if err := repo.RenewRemoteServerInstallation(ctx, server.ID, rollingNonce, time.Now(), 30*time.Minute, 2*time.Hour); !errors.Is(err, ErrRemoteInstallationRollingBack) {
		t.Fatalf("rolling-back renew error=%v", err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, rollingNonce); err != nil {
		t.Fatal(err)
	}
	if err := repo.RenewRemoteServerInstallation(ctx, server.ID, rollingNonce, time.Now(), 30*time.Minute, 2*time.Hour); !errors.Is(err, ErrRemoteInstallationAborted) {
		t.Fatalf("aborted renew error=%v", err)
	}
}

func TestRemoteServerInstallationPolicyContextCoversPanelTrustInputs(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	base := RemoteInstallationPolicyContext{
		PanelSourceIPs:  []string{"2001:db8::10", "203.0.113.10"},
		MasterURL:       "https://panel.example",
		MasterPublicKey: "master-public-key",
	}
	fingerprint, err := RemoteServerInstallationPolicyFingerprintWithContext(&server, base)
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]RemoteInstallationPolicyContext{
		"panel IP":   {PanelSourceIPs: []string{"203.0.113.11"}, MasterURL: base.MasterURL, MasterPublicKey: base.MasterPublicKey},
		"master URL": {PanelSourceIPs: base.PanelSourceIPs, MasterURL: "https://other.example", MasterPublicKey: base.MasterPublicKey},
		"public key": {PanelSourceIPs: base.PanelSourceIPs, MasterURL: base.MasterURL, MasterPublicKey: "other-key"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RemoteServerInstallationPolicyFingerprintWithContext(&server, changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == fingerprint {
				t.Fatal("policy fingerprint did not change")
			}
		})
	}
	if err := repo.BeginRemoteServerInstallationWithPolicyContext(context.Background(), server.ID, "context-policy-nonce", time.Now().Add(time.Minute), fingerprint, base); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteServerInstallationBeginRejectsActiveTransaction(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Minute)

	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "old-nonce", expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, "old-nonce"); err != nil {
		t.Fatal(err)
	}
	var originalExpiry int64
	if err := repo.db.QueryRowContext(ctx,
		`SELECT expires_at FROM remote_server_installations WHERE server_id = ?`, server.ID,
	).Scan(&originalExpiry); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "old-nonce", expiresAt.Add(10*time.Minute)); err != nil {
		t.Fatalf("same-nonce Begin retry: %v", err)
	}
	var retryExpiry int64
	var readyCount int
	if err := repo.db.QueryRowContext(ctx,
		`SELECT expires_at, CASE WHEN ready_at IS NULL THEN 0 ELSE 1 END FROM remote_server_installations WHERE server_id = ?`, server.ID,
	).Scan(&retryExpiry, &readyCount); err != nil {
		t.Fatal(err)
	}
	if retryExpiry != originalExpiry || readyCount != 1 {
		t.Fatalf("same-nonce Begin changed state: expiry %d -> %d ready=%d", originalExpiry, retryExpiry, readyCount)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "new-nonce", expiresAt.Add(time.Minute)); !errors.Is(err, ErrRemoteInstallationActive) {
		t.Fatalf("duplicate Begin error=%v", err)
	}
	if valid, err := repo.ValidateRemoteServerInstallation(ctx, server.ID, "old-nonce"); err != nil || !valid {
		t.Fatalf("active nonce was replaced: validation=(%v, %v)", valid, err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, "old-nonce"); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, "old-nonce"); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "new-nonce", expiresAt.Add(time.Minute)); err != nil {
		t.Fatalf("Begin after finalize: %v", err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, server.ID, "new-nonce"); !errors.Is(err, ErrRemoteInstallationNotReady) {
		t.Fatalf("new transaction unexpectedly ready: %v", err)
	}
}

func TestRemoteServerInstallationConcurrentBeginHasSingleWinner(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	const contenders = 16
	start := make(chan struct{})
	results := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		nonce := "concurrent-nonce-" + strconv.Itoa(i)
		go func() {
			<-start
			results <- repo.BeginRemoteServerInstallation(ctx, server.ID, nonce, time.Now().Add(time.Minute))
		}()
	}
	close(start)

	succeeded := 0
	conflicted := 0
	for i := 0; i < contenders; i++ {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRemoteInstallationActive):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent Begin error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != contenders-1 {
		t.Fatalf("concurrent Begin succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestRemoteServerInstallationExpiryAndDelete(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(20 * time.Millisecond)
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "expiring-nonce", expiresAt); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expiresAt) + 10*time.Millisecond)

	active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID)
	if err != nil || active {
		t.Fatalf("expired active=(%v, %v), want (false, nil)", active, err)
	}
	if valid, err := repo.ValidateRemoteServerInstallation(ctx, server.ID, "expiring-nonce"); err != nil || valid {
		t.Fatalf("expired validation=(%v, %v), want (false, nil)", valid, err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, "expiring-nonce"); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("expired MarkReady error=%v", err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "expiring-nonce", time.Now().Add(time.Minute)); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("same-nonce expired Begin retry error=%v", err)
	}
	if active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID); err != nil || active {
		t.Fatalf("same-nonce expired retry extended TTL: active=%v err=%v", active, err)
	}

	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "delete-nonce", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); !errors.Is(err, ErrRemoteInstallationActive) {
		t.Fatalf("DeleteRemoteServer during installation error=%v", err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, "delete-nonce"); err != nil {
		t.Fatalf("AbortRemoteServerInstallation: %v", err)
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); err != nil {
		t.Fatalf("DeleteRemoteServer: %v", err)
	}
	var count int
	if err := repo.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM remote_server_installations WHERE server_id = ?`, server.ID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("installation rows after server delete=%d", count)
	}
}

func TestRemoteServerInstallationRejectsUnknownServer(t *testing.T) {
	repo, _ := newRemoteInstallationTestServer(t)
	err := repo.BeginRemoteServerInstallation(context.Background(), 999999, "nonce", time.Now().Add(time.Minute))
	if !errors.Is(err, ErrRemoteServerNotFound) {
		t.Fatalf("Begin unknown server error=%v", err)
	}
}

func TestAbortRemoteServerInstallationRequiresMatchingNonce(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "abort-nonce", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, "wrong-nonce"); !errors.Is(err, ErrRemoteInstallationInvalid) {
		t.Fatalf("Abort wrong nonce error=%v", err)
	}
	if active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID); err != nil || !active {
		t.Fatalf("wrong nonce removed installation: active=%v err=%v", active, err)
	}
	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, "abort-nonce"); err != nil {
		t.Fatalf("AbortRemoteServerInstallation: %v", err)
	}
	if active, err := repo.IsRemoteServerInstallationActive(ctx, server.ID); err != nil || active {
		t.Fatalf("active after abort=(%v, %v), want (false, nil)", active, err)
	}
}

func TestRemoteServerInstallationSchemaIncludesPrepareAndCompletion(t *testing.T) {
	repo, _ := newRemoteInstallationTestServer(t)
	rows, err := repo.db.Query(`PRAGMA table_info(remote_server_installations)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, pk int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server_id", "nonce_hash", "started_at", "expires_at", "ready_at", "prepared_at", "completed_at", "rolling_back_at", "aborted_at"} {
		if !columns[name] {
			t.Fatalf("installation schema missing %s", name)
		}
	}
}

func TestRemoteServerInstallationMigrationAddsPrepareAndCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-installation.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	server := RemoteServer{Name: "legacy-edge", Token: "legacy-token", Status: RemoteServerStatusPending}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE remote_server_installations`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE remote_server_installations (
			server_id INTEGER PRIMARY KEY,
			nonce_hash TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			ready_at INTEGER
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO remote_server_installations (server_id, nonce_hash, expires_at, ready_at) VALUES (?, ?, ?, ?)`,
		server.ID, remoteInstallationNonceHash("legacy-nonce"), time.Now().Add(time.Minute).UnixNano(), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("migrate legacy installation table: %v", err)
	}
	defer reopened.Close()
	var preparedAt, completedAt sql.NullInt64
	if err := reopened.db.QueryRow(`SELECT prepared_at, completed_at FROM remote_server_installations WHERE server_id = ?`, server.ID).
		Scan(&preparedAt, &completedAt); err != nil {
		t.Fatal(err)
	}
	if preparedAt.Valid || completedAt.Valid {
		t.Fatalf("legacy row gained state: prepared=%v completed=%v", preparedAt, completedAt)
	}
}

func TestBeginWaitsForInFlightAutomaticMutation(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	mutationStarted := make(chan struct{})
	releaseMutation := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- repo.WithRemoteServerMutationLease(ctx, server.ID, func(context.Context) error {
			close(mutationStarted)
			<-releaseMutation
			return nil
		})
	}()
	select {
	case <-mutationStarted:
	case <-time.After(time.Second):
		t.Fatal("automatic mutation did not acquire shared lease")
	}

	beginAttempted := make(chan struct{})
	beginDone := make(chan error, 1)
	go func() {
		close(beginAttempted)
		beginDone <- repo.BeginRemoteServerInstallation(ctx, server.ID, "lease-nonce", time.Now().Add(time.Minute))
	}()
	<-beginAttempted
	select {
	case err := <-beginDone:
		t.Fatalf("Begin returned before in-flight mutation drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseMutation)
	if err := <-mutationDone; err != nil {
		t.Fatalf("automatic mutation: %v", err)
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after mutation drain: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Begin remained blocked after automatic mutation completed")
	}

	called := false
	err := repo.WithRemoteServerMutationLease(ctx, server.ID, func(context.Context) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrRemoteInstallationActive) || called {
		t.Fatalf("active durable lock allowed automatic mutation: called=%v err=%v", called, err)
	}
	bypassCalled := false
	bypassCtx := repo.RemoteServerMutationLeaseBypassContext(ctx, server.ID)
	if err := repo.WithRemoteServerMutationLease(bypassCtx, server.ID, func(context.Context) error {
		bypassCalled = true
		return nil
	}); err != nil || !bypassCalled {
		t.Fatalf("explicit prepare bypass failed: called=%v err=%v", bypassCalled, err)
	}
}

func TestAcquireRemoteServerMutationLeaseIsReentrantAndReleaseIsIdempotent(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held, exclusive := repo.RemoteServerMutationLeaseState(leasedCtx, server.ID); !held || exclusive {
		t.Fatalf("shared lease state=(held=%v exclusive=%v)", held, exclusive)
	}
	if held, exclusive := repo.RemoteServerMutationLeaseState(ctx, server.ID); held || exclusive {
		t.Fatalf("unleased context state=(held=%v exclusive=%v)", held, exclusive)
	}
	nestedCtx, nestedRelease, err := repo.AcquireRemoteServerMutationLease(leasedCtx, server.ID)
	if err != nil {
		t.Fatalf("nested AcquireRemoteServerMutationLease: %v", err)
	}
	if nestedCtx != leasedCtx {
		t.Fatal("reentrant acquisition replaced the leased context")
	}
	nestedRelease()

	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(ctx, server.ID, "acquire-nonce", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("Begin returned before acquired lease released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release()
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Begin remained blocked after idempotent release")
	}
}

func TestAcquireRemoteServerExclusiveMutationLeaseSerializesOrdinaryMutations(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	leasedCtx, release, err := repo.AcquireRemoteServerExclusiveMutationLease(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if held, exclusive := repo.RemoteServerMutationLeaseState(leasedCtx, server.ID); !held || !exclusive {
		t.Fatalf("exclusive lease state=(held=%v exclusive=%v)", held, exclusive)
	}
	defer release()

	nestedCtx, nestedRelease, err := repo.AcquireRemoteServerMutationLease(leasedCtx, server.ID)
	if err != nil || nestedCtx != leasedCtx {
		t.Fatalf("nested ordinary lease under exclusive lease: ctx_same=%v err=%v", nestedCtx == leasedCtx, err)
	}
	nestedRelease()

	ordinaryDone := make(chan error, 1)
	go func() {
		ordinaryCtx, ordinaryRelease, acquireErr := repo.AcquireRemoteServerMutationLease(ctx, server.ID)
		if acquireErr == nil {
			ordinaryRelease()
			_ = ordinaryCtx
		}
		ordinaryDone <- acquireErr
	}()
	select {
	case err := <-ordinaryDone:
		t.Fatalf("ordinary mutation passed an active exclusive lease: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	release()
	select {
	case err := <-ordinaryDone:
		if err != nil {
			t.Fatalf("ordinary mutation after exclusive release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary mutation remained blocked after exclusive release")
	}
}

func TestAcquireRemoteServerExclusiveMutationLeaseRejectsUpgradeAndInstallation(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	sharedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.AcquireRemoteServerExclusiveMutationLease(sharedCtx, server.ID); err == nil {
		t.Fatal("shared mutation lease was upgraded in place")
	}
	release()

	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "exclusive-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.AcquireRemoteServerExclusiveMutationLease(ctx, server.ID); !errors.Is(err, ErrRemoteInstallationActive) {
		t.Fatalf("exclusive lease during installation error=%v", err)
	}
}

func TestRemoteServerAdminMutationsRejectActiveInstallation(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "admin-lock", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	err := repo.UpdateRemoteServer(ctx, server.ID, "renamed-edge", "renamed.example.test", 123, 1, "", "", "", "", nil)
	if !errors.Is(err, ErrRemoteInstallationActive) {
		t.Fatalf("UpdateRemoteServer during installation error=%v", err)
	}
	unchanged, err := repo.GetRemoteServer(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Name != server.Name {
		t.Fatalf("active installation allowed server rename: %q", unchanged.Name)
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); !errors.Is(err, ErrRemoteInstallationActive) {
		t.Fatalf("DeleteRemoteServer during installation error=%v", err)
	}
	if _, err := repo.GetRemoteServer(ctx, server.ID); err != nil {
		t.Fatalf("active installation allowed server deletion: %v", err)
	}

	if err := repo.AbortRemoteServerInstallation(ctx, server.ID, "admin-lock"); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateRemoteServer(ctx, server.ID, "renamed-edge", "renamed.example.test", 123, 1, "", "", "", "", nil); err != nil {
		t.Fatalf("UpdateRemoteServer after abort: %v", err)
	}
	updated, err := repo.GetRemoteServer(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed-edge" || updated.Domain != "renamed.example.test" {
		t.Fatalf("server was not updated after abort: name=%q domain=%q", updated.Name, updated.Domain)
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); err != nil {
		t.Fatalf("DeleteRemoteServer after abort: %v", err)
	}
}

func TestRemoteServerMutationLeaseIsReentrantWithWaitingBegin(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	outerStarted := make(chan struct{})
	runNested := make(chan struct{})
	outerDone := make(chan error, 1)
	nestedCalled := make(chan struct{}, 1)
	go func() {
		outerDone <- repo.WithRemoteServerMutationLease(ctx, server.ID, func(leasedCtx context.Context) error {
			close(outerStarted)
			<-runNested
			return repo.WithRemoteServerMutationLease(leasedCtx, server.ID, func(context.Context) error {
				nestedCalled <- struct{}{}
				return nil
			})
		})
	}()
	<-outerStarted

	beginAttempted := make(chan struct{})
	beginDone := make(chan error, 1)
	go func() {
		close(beginAttempted)
		beginDone <- repo.BeginRemoteServerInstallation(ctx, server.ID, "reentrant-nonce", time.Now().Add(time.Minute))
	}()
	<-beginAttempted
	// Give Begin time to block as the pending writer. A recursive RLock here
	// would deadlock because sync.RWMutex excludes new readers once it waits.
	time.Sleep(50 * time.Millisecond)
	close(runNested)
	select {
	case err := <-outerDone:
		if err != nil {
			t.Fatalf("nested mutation lease: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("nested mutation lease deadlocked behind waiting Begin")
	}
	select {
	case <-nestedCalled:
	default:
		t.Fatal("nested mutation action was not called")
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after reentrant lease: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Begin did not acquire exclusive lease after nested action completed")
	}
}

func TestRemoteServerPrepareBypassIsExclusiveAndReentrant(t *testing.T) {
	repo, server := newRemoteInstallationTestServer(t)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "prepare-nonce", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	bypassCtx := repo.RemoteServerMutationLeaseBypassContext(ctx, server.ID)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- repo.WithRemoteServerMutationLease(bypassCtx, server.ID, func(exclusiveCtx context.Context) error {
			close(firstStarted)
			// Nested non-GET forwarding reuses the exclusive context.
			if err := repo.WithRemoteServerMutationLease(exclusiveCtx, server.ID, func(context.Context) error { return nil }); err != nil {
				return err
			}
			<-releaseFirst
			return nil
		})
	}()
	<-firstStarted

	secondAttempted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempted)
		secondDone <- repo.WithRemoteServerMutationLease(bypassCtx, server.ID, func(context.Context) error { return nil })
	}()
	<-secondAttempted
	select {
	case err := <-secondDone:
		t.Fatalf("concurrent Prepare bypass was not serialized: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Prepare bypass: %v", err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second Prepare bypass: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Prepare bypass remained blocked")
	}
}
