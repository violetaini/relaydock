package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// UserAPIToken 是每用户 API 令牌的元数据(不含明文/hash)。
type UserAPIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// hashAPIToken 返回令牌的 sha256 十六进制串(库里只存这个)。
func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateUserAPIToken 为用户生成一枚新 API 令牌,返回明文(仅此一次)。库里只存其 sha256。
func (r *TrafficRepository) CreateUserAPIToken(ctx context.Context, username, name string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := "relaydock_" + base64.RawURLEncoding.EncodeToString(buf)
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO user_api_tokens (username, name, token_hash) VALUES (?, ?, ?)`,
		username, name, hashAPIToken(token)); err != nil {
		return "", fmt.Errorf("create api token: %w", err)
	}
	return token, nil
}

// ListUserAPITokens 返回某用户的所有 API 令牌元数据(不含明文)。
func (r *TrafficRepository) ListUserAPITokens(ctx context.Context, username string) ([]UserAPIToken, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_used_at FROM user_api_tokens WHERE username = ? ORDER BY id DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]UserAPIToken, 0)
	for rows.Next() {
		var t UserAPIToken
		var last sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &last); err != nil {
			return nil, err
		}
		if last.Valid {
			t.LastUsedAt = &last.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ResolveUsernameByAPIToken 用明文令牌(取 hash)解析出所属用户名;命中即顺手刷新 last_used_at。
func (r *TrafficRepository) ResolveUsernameByAPIToken(ctx context.Context, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	hash := hashAPIToken(token)
	var username string
	err := r.db.QueryRowContext(ctx,
		`SELECT username FROM user_api_tokens WHERE token_hash = ? LIMIT 1`, hash).Scan(&username)
	if err != nil {
		return "", false
	}
	// 异步刷新最近使用时间(失败忽略,不阻塞鉴权)
	_, _ = r.db.ExecContext(ctx, `UPDATE user_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`, hash)
	return username, true
}

// RevokeUserAPIToken 删除该用户名下指定 id 的令牌(限定 owner,防止越权吊销他人)。
func (r *TrafficRepository) RevokeUserAPIToken(ctx context.Context, username string, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_api_tokens WHERE id = ? AND username = ?`, id, username)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}
