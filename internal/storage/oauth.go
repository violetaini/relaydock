package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UserOAuthIdentity 代表用户关联的第三方快捷登录（OAuth / OIDC）身份信息。
type UserOAuthIdentity struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Provider  string    `json:"provider"` // "github", "google", "oidc"
	OAuthID   string    `json:"oauth_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// migrateOAuthIdentities 迁移并初始化 user_oauth_identities 数据表。
func migrateOAuthIdentities(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS user_oauth_identities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL,
    provider      TEXT NOT NULL,
    oauth_id      TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    avatar_url    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, oauth_id)
);
CREATE INDEX IF NOT EXISTS idx_user_oauth_username ON user_oauth_identities(username);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("migrate user_oauth_identities: %w", err)
	}
	return nil
}

// GetOAuthIdentity 根据第三方提供商与第三方账号 ID 查找对应的身份记录。
func (r *TrafficRepository) GetOAuthIdentity(ctx context.Context, provider, oauthID string) (*UserOAuthIdentity, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	oauthID = strings.TrimSpace(oauthID)
	if provider == "" || oauthID == "" {
		return nil, errors.New("provider and oauth_id are required")
	}

	row := r.db.QueryRowContext(ctx,
		`SELECT id, username, provider, oauth_id, email, name, avatar_url, created_at, updated_at
		 FROM user_oauth_identities
		 WHERE provider = ? AND oauth_id = ?
		 LIMIT 1`, provider, oauthID)

	var item UserOAuthIdentity
	if err := row.Scan(&item.ID, &item.Username, &item.Provider, &item.OAuthID, &item.Email, &item.Name, &item.AvatarURL, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	return &item, nil
}

// GetUserOAuthIdentities 获取指定用户已绑定的所有第三方账号列表。
func (r *TrafficRepository) GetUserOAuthIdentities(ctx context.Context, username string) ([]UserOAuthIdentity, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, provider, oauth_id, email, name, avatar_url, created_at, updated_at
		 FROM user_oauth_identities
		 WHERE username = ?
		 ORDER BY id ASC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserOAuthIdentity
	for rows.Next() {
		var item UserOAuthIdentity
		if err := rows.Scan(&item.ID, &item.Username, &item.Provider, &item.OAuthID, &item.Email, &item.Name, &item.AvatarURL, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// BindOAuthIdentity 绑定或更新第三方账号身份记录。
func (r *TrafficRepository) BindOAuthIdentity(ctx context.Context, identity *UserOAuthIdentity) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if identity == nil {
		return errors.New("identity is nil")
	}
	identity.Username = strings.TrimSpace(identity.Username)
	identity.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	identity.OAuthID = strings.TrimSpace(identity.OAuthID)
	identity.Email = strings.TrimSpace(identity.Email)
	identity.Name = strings.TrimSpace(identity.Name)
	identity.AvatarURL = strings.TrimSpace(identity.AvatarURL)

	if identity.Username == "" || identity.Provider == "" || identity.OAuthID == "" {
		return errors.New("username, provider and oauth_id are required")
	}

	now := time.Now().UTC()
	const stmt = `
INSERT INTO user_oauth_identities (username, provider, oauth_id, email, name, avatar_url, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(provider, oauth_id) DO UPDATE SET
    username = excluded.username,
    email = excluded.email,
    name = excluded.name,
    avatar_url = excluded.avatar_url,
    updated_at = excluded.updated_at`

	_, err := r.db.ExecContext(ctx, stmt,
		identity.Username, identity.Provider, identity.OAuthID,
		identity.Email, identity.Name, identity.AvatarURL,
		now, now)
	return err
}

// UnbindOAuthIdentity 解除指定用户对某第三方账号提供商的绑定。
func (r *TrafficRepository) UnbindOAuthIdentity(ctx context.Context, username, provider string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	provider = strings.ToLower(strings.TrimSpace(provider))
	if username == "" || provider == "" {
		return errors.New("username and provider are required")
	}

	_, err := r.db.ExecContext(ctx,
		`DELETE FROM user_oauth_identities WHERE username = ? AND provider = ?`,
		username, provider)
	return err
}

// GetUserByEmail 根据邮箱地址反查用户记录（用于第三方登录自动关联）。
func (r *TrafficRepository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var user User
	if r == nil || r.db == nil {
		return user, errors.New("traffic repository not initialized")
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return user, errors.New("email is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT username, password_hash, COALESCE(email, ''), COALESCE(nickname, ''), COALESCE(avatar_url, ''), COALESCE(role, ''), is_active, COALESCE(package_id, 0), authorization_mode, COALESCE(is_reset, 0), COALESCE(reset_day, 1), COALESCE(node_traffic_reset_period, 'monthly'), package_start_date, package_end_date, speed_limit_override, device_limit_override, traffic_limit_override, COALESCE(node_speed_limit_overrides, '{}'), COALESCE(node_traffic_limit_overrides, '{}'), COALESCE(node_device_limit_overrides, '{}'), COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(recovery_codes, '[]'), created_at, updated_at FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1`, email)
	var active, isReset, totpEnabled int
	var startDate, endDate sql.NullTime
	var speedOverride sql.NullFloat64
	var deviceOverride sql.NullInt64
	var trafficOverride sql.NullInt64
	var nodeSpeedJSON, nodeTrafficJSON, nodeDeviceJSON string
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.Nickname, &user.AvatarURL, &user.Role, &active, &user.PackageID, &user.AuthorizationMode, &isReset, &user.ResetDay, &user.NodeTrafficResetPeriod, &startDate, &endDate, &speedOverride, &deviceOverride, &trafficOverride, &nodeSpeedJSON, &nodeTrafficJSON, &nodeDeviceJSON, &user.TOTPSecret, &totpEnabled, &user.RecoveryCodes, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, err
	}
	user.IsActive = active == 1
	user.IsReset = isReset == 1
	user.TOTPEnabled = totpEnabled == 1
	if startDate.Valid {
		user.PackageStartDate = &startDate.Time
	}
	if endDate.Valid {
		user.PackageEndDate = &endDate.Time
	}
	if speedOverride.Valid {
		user.SpeedLimitOverride = &speedOverride.Float64
	}
	if deviceOverride.Valid {
		v := int(deviceOverride.Int64)
		user.DeviceLimitOverride = &v
	}
	if trafficOverride.Valid {
		user.TrafficLimitOverride = &trafficOverride.Int64
	}
	return user, nil
}
