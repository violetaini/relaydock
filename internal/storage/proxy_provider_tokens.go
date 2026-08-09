package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const proxyProviderAccessTokenPrefix = "arcway_pp_"

var ErrProxyProviderAccessNotFound = errors.New("proxy provider access not found")

func proxyProviderTokenAssociatedData(id int64, username string) []byte {
	return []byte("arcway:proxy-provider:access-token:v1:" + strconv.FormatInt(id, 10) + ":" + username)
}

func hashProxyProviderAccessToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newProxyProviderAccessToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate proxy provider access token: %w", err)
	}
	return proxyProviderAccessTokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validProxyProviderAccessToken(token string) bool {
	if !strings.HasPrefix(token, proxyProviderAccessTokenPrefix) || len(token) != len(proxyProviderAccessTokenPrefix)+43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, proxyProviderAccessTokenPrefix))
	return err == nil
}

func (r *TrafficRepository) sealProxyProviderAccessToken(id int64, username, token string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("proxy provider token encryption is not configured")
	}
	return box.Seal([]byte(token), proxyProviderTokenAssociatedData(id, username))
}

func (r *TrafficRepository) openProxyProviderAccessToken(id int64, username, ciphertext string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("proxy provider token encryption is not configured")
	}
	plaintext, err := box.Open(strings.TrimSpace(ciphertext), proxyProviderTokenAssociatedData(id, username))
	if err != nil {
		return "", fmt.Errorf("decrypt proxy provider access token %d: %w", id, err)
	}
	return string(plaintext), nil
}

// resealProxyProviderAccessTokensForUsernameRename updates the AAD-bound
// ciphertext after ownership columns have been renamed inside the same
// transaction. The plaintext token and its lookup hash remain unchanged, so
// existing Mihomo configurations continue to work across an account rename.
func (r *TrafficRepository) resealProxyProviderAccessTokensForUsernameRename(ctx context.Context, tx *sql.Tx, oldUsername, newUsername string) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(access_token_hash, ''), COALESCE(access_token_ciphertext, '')
		FROM proxy_provider_configs
		WHERE username = ? AND (access_token_hash != '' OR access_token_ciphertext != '')
		ORDER BY id`, newUsername)
	if err != nil {
		return fmt.Errorf("load proxy provider tokens for username rename: %w", err)
	}
	type tokenState struct {
		id         int64
		tokenHash  string
		ciphertext string
	}
	var states []tokenState
	for rows.Next() {
		var state tokenState
		if err := rows.Scan(&state.id, &state.tokenHash, &state.ciphertext); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan proxy provider token for username rename: %w", err)
		}
		states = append(states, state)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close proxy provider tokens for username rename: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate proxy provider tokens for username rename: %w", err)
	}

	for _, state := range states {
		if state.tokenHash == "" || state.ciphertext == "" {
			return fmt.Errorf("proxy provider %d has incomplete access token state", state.id)
		}
		token, err := r.openProxyProviderAccessToken(state.id, oldUsername, state.ciphertext)
		if err != nil {
			return fmt.Errorf("open proxy provider %d before username rename: %w", state.id, err)
		}
		if !validProxyProviderAccessToken(token) || hashProxyProviderAccessToken(token) != state.tokenHash {
			return fmt.Errorf("proxy provider %d access token integrity check failed", state.id)
		}
		ciphertext, err := r.sealProxyProviderAccessToken(state.id, newUsername, token)
		if err != nil {
			return fmt.Errorf("seal proxy provider %d after username rename: %w", state.id, err)
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE proxy_provider_configs SET access_token_ciphertext = ?
			WHERE id = ? AND username = ?`, ciphertext, state.id, newUsername)
		if err != nil {
			return fmt.Errorf("store proxy provider %d after username rename: %w", state.id, err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			if err != nil {
				return fmt.Errorf("proxy provider %d username rename rows affected: %w", state.id, err)
			}
			return fmt.Errorf("proxy provider %d disappeared during username rename", state.id)
		}
	}
	return nil
}

func (r *TrafficRepository) verifyExistingProxyProviderAccessTokens(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, COALESCE(access_token_hash, ''), COALESCE(access_token_ciphertext, '')
		FROM proxy_provider_configs
		WHERE access_token_hash != '' OR access_token_ciphertext != ''
		ORDER BY id`)
	if err != nil {
		return fmt.Errorf("scan proxy provider access tokens: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var username, tokenHash, ciphertext string
		if err := rows.Scan(&id, &username, &tokenHash, &ciphertext); err != nil {
			return fmt.Errorf("scan proxy provider access token: %w", err)
		}
		if tokenHash == "" || ciphertext == "" {
			return fmt.Errorf("proxy provider %d has incomplete access token state", id)
		}
		token, err := r.openProxyProviderAccessToken(id, username, ciphertext)
		if err != nil {
			return err
		}
		if !validProxyProviderAccessToken(token) || hashProxyProviderAccessToken(token) != tokenHash {
			return fmt.Errorf("proxy provider %d access token integrity check failed", id)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate proxy provider access tokens: %w", err)
	}
	return nil
}

// EnsureProxyProviderAccessToken returns a stable opaque token for a provider.
// Legacy rows are initialized lazily so deployments do not expose or rotate
// credentials merely by running a database migration.
func (r *TrafficRepository) EnsureProxyProviderAccessToken(ctx context.Context, id int64, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if id <= 0 || username == "" {
		return "", ErrProxyProviderAccessNotFound
	}

	var tokenHash, ciphertext string
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(access_token_hash, ''), COALESCE(access_token_ciphertext, '')
		FROM proxy_provider_configs WHERE id = ? AND username = ?`, id, username).Scan(&tokenHash, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrProxyProviderAccessNotFound
	}
	if err != nil {
		return "", fmt.Errorf("load proxy provider access token: %w", err)
	}
	if tokenHash != "" || ciphertext != "" {
		if tokenHash == "" || ciphertext == "" {
			return "", errors.New("proxy provider access token state is incomplete")
		}
		token, err := r.openProxyProviderAccessToken(id, username, ciphertext)
		if err != nil {
			return "", err
		}
		if !validProxyProviderAccessToken(token) || hashProxyProviderAccessToken(token) != tokenHash {
			return "", errors.New("proxy provider access token integrity check failed")
		}
		return token, nil
	}

	token, err := newProxyProviderAccessToken()
	if err != nil {
		return "", err
	}
	ciphertext, err = r.sealProxyProviderAccessToken(id, username, token)
	if err != nil {
		return "", err
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE proxy_provider_configs
		SET access_token_hash = ?, access_token_ciphertext = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND username = ? AND access_token_hash = '' AND access_token_ciphertext = ''`,
		hashProxyProviderAccessToken(token), ciphertext, id, username)
	if err != nil {
		return "", fmt.Errorf("initialize proxy provider access token: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 1 {
		return token, nil
	}
	// Another renderer may have initialized the row concurrently. Load the
	// committed winner instead of returning a token that was never persisted.
	return r.EnsureProxyProviderAccessToken(ctx, id, username)
}

func (r *TrafficRepository) RotateProxyProviderAccessToken(ctx context.Context, id int64, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if id <= 0 || username == "" {
		return "", ErrProxyProviderAccessNotFound
	}
	token, err := newProxyProviderAccessToken()
	if err != nil {
		return "", err
	}
	ciphertext, err := r.sealProxyProviderAccessToken(id, username, token)
	if err != nil {
		return "", err
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE proxy_provider_configs
		SET access_token_hash = ?, access_token_ciphertext = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND username = ?`, hashProxyProviderAccessToken(token), ciphertext, id, username)
	if err != nil {
		return "", fmt.Errorf("rotate proxy provider access token: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return "", ErrProxyProviderAccessNotFound
	}
	return token, nil
}

// ResolveProxyProviderAccess performs one owner-bound lookup for the public
// provider endpoint. Disabled/deleted users and detached source subscriptions
// deliberately collapse to the same not-found result as an invalid token.
func (r *TrafficRepository) ResolveProxyProviderAccess(ctx context.Context, token string) (*ProxyProviderConfig, *ExternalSubscription, error) {
	if r == nil || r.db == nil {
		return nil, nil, errors.New("traffic repository not initialized")
	}
	token = strings.TrimSpace(token)
	if !validProxyProviderAccessToken(token) {
		return nil, nil, ErrProxyProviderAccessNotFound
	}
	row := r.db.QueryRowContext(ctx, `
		SELECT p.id, p.username, p.external_subscription_id, p.name, p.type, p.interval, p.proxy, p.size_limit,
		       COALESCE(p.header, ''), p.health_check_enabled, p.health_check_url, p.health_check_interval,
		       p.health_check_timeout, p.health_check_lazy, p.health_check_expected_status,
		       COALESCE(p.filter, ''), COALESCE(p.exclude_filter, ''), COALESCE(p.exclude_type, ''),
		       COALESCE(p.geo_ip_filter, ''), COALESCE(p.override, ''), p.process_mode, p.created_at, p.updated_at,
		       e.id, e.username, e.name, e.url, COALESCE(e.user_agent, 'clash-meta/2.4.0'), e.node_count,
		       e.last_sync_at, COALESCE(e.upload, 0), COALESCE(e.download, 0), COALESCE(e.total, 0), e.expire,
		       COALESCE(e.traffic_mode, 'both'), e.created_at, e.updated_at,
		       p.access_token_ciphertext
		FROM proxy_provider_configs p
		JOIN external_subscriptions e ON e.id = p.external_subscription_id AND e.username = p.username
		JOIN users u ON u.username = p.username AND u.is_active = 1
		WHERE p.access_token_hash = ? LIMIT 1`, hashProxyProviderAccessToken(token))

	var cfg ProxyProviderConfig
	var sub ExternalSubscription
	var healthEnabled, healthLazy int
	var lastSync, expire sql.NullTime
	var ciphertext string
	if err := row.Scan(
		&cfg.ID, &cfg.Username, &cfg.ExternalSubscriptionID, &cfg.Name, &cfg.Type, &cfg.Interval, &cfg.Proxy, &cfg.SizeLimit,
		&cfg.Header, &healthEnabled, &cfg.HealthCheckURL, &cfg.HealthCheckInterval, &cfg.HealthCheckTimeout,
		&healthLazy, &cfg.HealthCheckExpectedStatus, &cfg.Filter, &cfg.ExcludeFilter, &cfg.ExcludeType,
		&cfg.GeoIPFilter, &cfg.Override, &cfg.ProcessMode, &cfg.CreatedAt, &cfg.UpdatedAt,
		&sub.ID, &sub.Username, &sub.Name, &sub.URL, &sub.UserAgent, &sub.NodeCount,
		&lastSync, &sub.Upload, &sub.Download, &sub.Total, &expire, &sub.TrafficMode, &sub.CreatedAt, &sub.UpdatedAt,
		&ciphertext,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrProxyProviderAccessNotFound
		}
		return nil, nil, fmt.Errorf("resolve proxy provider access: %w", err)
	}
	storedToken, err := r.openProxyProviderAccessToken(cfg.ID, cfg.Username, ciphertext)
	if err != nil || storedToken != token {
		// Credential corruption and token mismatches are deliberately
		// indistinguishable from an unknown public credential.
		return nil, nil, ErrProxyProviderAccessNotFound
	}
	cfg.HealthCheckEnabled = healthEnabled != 0
	cfg.HealthCheckLazy = healthLazy != 0
	if lastSync.Valid {
		sub.LastSyncAt = &lastSync.Time
	}
	if expire.Valid {
		sub.Expire = &expire.Time
	}
	return &cfg, &sub, nil
}
