package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InviteCode 邀请码记录。kind='new' 时 PackageID 可选(创建账号时自动绑该套餐);
// kind='bind' 时 BindUsername 必填(锁定到指定 username)。
type InviteCode struct {
	Code         string
	Kind         string // "new" | "bind"
	BindUsername string
	CreatedBy    string
	PackageID    *int64
	MaxUses      int
	UsedCount    int
	ExpiresAt    *time.Time
	Revoked      bool
	Remark       string
	CreatedAt    time.Time
	// DurationMonths 仅 kind=new 有用:注册时账号有效期 = now + N 个月。
	// 0 = 沿用套餐自身周期(cycle_days)的旧行为。>1 时 bind 自动开 is_reset(按月重置/续期)。
	DurationMonths int
}

// IsUsable 邀请码是否当前可消耗(未撤销 + 未达使用上限 + 未过期)。
func (ic InviteCode) IsUsable() bool {
	if ic.Revoked {
		return false
	}
	if ic.MaxUses > 0 && ic.UsedCount >= ic.MaxUses {
		return false
	}
	if ic.ExpiresAt != nil && time.Now().After(*ic.ExpiresAt) {
		return false
	}
	return true
}

// TGAudit 操作审计行。
type TGAudit struct {
	ID       int64
	TGID     int64 // 0 表示无 tg_id(如系统操作)
	Username string
	Action   string // 'register' | 'bind' | 'unbind' | 'admin_invite_create' | ...
	Detail   string // JSON 或纯文本
	At       time.Time
}

// ============ 用户 TG 字段读写 ============

// GetUsernameByTelegramID 用 tg_id 查 username;未绑定返回("", false)。
func (r *TrafficRepository) GetUsernameByTelegramID(ctx context.Context, tgID int64) (string, bool) {
	if tgID == 0 {
		return "", false
	}
	var u string
	err := r.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE telegram_id = ? LIMIT 1`, tgID).Scan(&u)
	if err != nil {
		return "", false
	}
	return u, true
}

// BindTelegram 把 (tg_id, tg_username) 绑到 username。
// 已经绑给别人 → 报错(部分唯一索引会拦);该 user 已绑别的 tg_id → 覆盖。
func (r *TrafficRepository) BindTelegram(ctx context.Context, username string, tgID int64, tgUsername string) error {
	if username == "" {
		return errors.New("username required")
	}
	if tgID == 0 {
		return errors.New("tg_id required")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE users
		   SET telegram_id = ?, telegram_username = ?, telegram_bound_at = CURRENT_TIMESTAMP,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE username = ?`,
		tgID, tgUsername, username)
	return err
}

// GetTelegramIDByUsername 查 username 已绑的 tg_id(0=未绑/不存在)。
func (r *TrafficRepository) GetTelegramIDByUsername(ctx context.Context, username string) int64 {
	var tg sql.NullInt64
	if err := r.db.QueryRowContext(ctx,
		`SELECT telegram_id FROM users WHERE username = ? LIMIT 1`, username).Scan(&tg); err != nil {
		return 0
	}
	if tg.Valid {
		return tg.Int64
	}
	return 0
}

// UnbindTelegram 解绑(置 NULL)。
func (r *TrafficRepository) UnbindTelegram(ctx context.Context, username string) error {
	if username == "" {
		return errors.New("username required")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE users
		   SET telegram_id = NULL, telegram_username = '', telegram_bound_at = NULL,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE username = ?`,
		username)
	return err
}

// ============ 用户自助通知开关 ============

// NotifyTarget 每日推送名单的一行(轻量,流量/套餐细节由 handler 现取)。
type NotifyTarget struct {
	Username       string
	TelegramID     int64
	PackageID      int64
	PackageEndDate *time.Time
}

// TGPackageUser is eligible for account-wide Telegram announcements.
type TGPackageUser struct {
	Username   string
	TelegramID int64
	PackageID  int64
}

// ListActivePackageTGUsers returns bound users whose package is still active.
func (r *TrafficRepository) ListActivePackageTGUsers(ctx context.Context) ([]TGPackageUser, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT username, telegram_id, COALESCE(package_id, 0) FROM users
		  WHERE telegram_id IS NOT NULL AND telegram_id != 0
		    AND is_active = 1
		    AND package_id IS NOT NULL AND package_id > 0
		    AND (package_end_date IS NULL OR package_end_date > CURRENT_TIMESTAMP)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]TGPackageUser, 0)
	for rows.Next() {
		var user TGPackageUser
		if err := rows.Scan(&user.Username, &user.TelegramID, &user.PackageID); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// SetTGNotify 按 tg_id 开关用户通知。未绑(影响 0 行)返回错误。
func (r *TrafficRepository) SetTGNotify(ctx context.Context, tgID int64, enabled bool) error {
	if tgID == 0 {
		return errors.New("tg_id required")
	}
	v := 0
	if enabled {
		v = 1
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET tg_notify_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?`,
		v, tgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("该 TG 未绑定任何账号")
	}
	return nil
}

// GetTGNotify 查 tg_id 的通知开关;ok=false 表示该 tg_id 未绑定。
func (r *TrafficRepository) GetTGNotify(ctx context.Context, tgID int64) (enabled bool, ok bool) {
	if tgID == 0 {
		return false, false
	}
	var v int
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(tg_notify_enabled, 0) FROM users WHERE telegram_id = ? LIMIT 1`, tgID).Scan(&v)
	if err != nil {
		return false, false
	}
	return v != 0, true
}

// ListNotifyUsers 列出已开通知的绑定用户(供 bot 每日推送)。
func (r *TrafficRepository) ListNotifyUsers(ctx context.Context) ([]NotifyTarget, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT username, telegram_id, COALESCE(package_id, 0), package_end_date
		   FROM users
		  WHERE telegram_id IS NOT NULL AND tg_notify_enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []NotifyTarget
	for rows.Next() {
		var t NotifyTarget
		var endDate sql.NullTime
		if err := rows.Scan(&t.Username, &t.TelegramID, &t.PackageID, &endDate); err != nil {
			return nil, err
		}
		if endDate.Valid {
			v := endDate.Time
			t.PackageEndDate = &v
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ============ 邀请码 ============

// GenerateInviteCode 生成 12 位大小写字母数字串(密码学随机)。
func GenerateInviteCode() (string, error) {
	buf := make([]byte, 9) // 9 bytes hex → 18 chars,截到 12 位够熵且短
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(buf))[:12], nil
}

// CreateInviteCode 写入新邀请码。code 为空时自动生成。
func (r *TrafficRepository) CreateInviteCode(ctx context.Context, ic InviteCode) (string, error) {
	if strings.TrimSpace(ic.CreatedBy) == "" {
		return "", errors.New("created_by required")
	}
	if ic.Kind != "new" && ic.Kind != "bind" {
		return "", errors.New("kind must be 'new' or 'bind'")
	}
	if ic.Kind == "bind" && strings.TrimSpace(ic.BindUsername) == "" {
		return "", errors.New("bind_username required for kind='bind'")
	}
	if ic.MaxUses <= 0 {
		ic.MaxUses = 1
	}
	if ic.Code == "" {
		c, err := GenerateInviteCode()
		if err != nil {
			return "", fmt.Errorf("gen code: %w", err)
		}
		ic.Code = c
	}

	var expiresArg any
	if ic.ExpiresAt != nil {
		expiresArg = *ic.ExpiresAt
	}
	var pkgArg any
	if ic.PackageID != nil {
		pkgArg = *ic.PackageID
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO invite_codes (code, kind, bind_username, created_by, package_id,
		                          max_uses, used_count, expires_at, revoked, remark, duration_months)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?)`,
		ic.Code, ic.Kind, ic.BindUsername, ic.CreatedBy, pkgArg,
		ic.MaxUses, expiresArg, ic.Remark, ic.DurationMonths)
	if err != nil {
		return "", err
	}
	return ic.Code, nil
}

// GetInviteCode 查邀请码;未找到返回 (zero, false)。
func (r *TrafficRepository) GetInviteCode(ctx context.Context, code string) (InviteCode, bool) {
	var ic InviteCode
	var pkgID sql.NullInt64
	var expiresAt sql.NullTime
	var revokedInt int

	err := r.db.QueryRowContext(ctx,
		`SELECT code, kind, bind_username, created_by, package_id,
		        max_uses, used_count, expires_at, revoked, remark, created_at, duration_months
		   FROM invite_codes WHERE code = ?`, code).
		Scan(&ic.Code, &ic.Kind, &ic.BindUsername, &ic.CreatedBy, &pkgID,
			&ic.MaxUses, &ic.UsedCount, &expiresAt, &revokedInt, &ic.Remark, &ic.CreatedAt, &ic.DurationMonths)
	if err != nil {
		return InviteCode{}, false
	}
	if pkgID.Valid {
		v := pkgID.Int64
		ic.PackageID = &v
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		ic.ExpiresAt = &t
	}
	ic.Revoked = revokedInt != 0
	return ic, true
}

// ConsumeInviteCode 原子消耗一次邀请码。
// 校验通过后 invite_codes.used_count++ 并写入 invite_code_uses。
// 任一步失败回滚,保证 used_count 不超 max_uses。
func (r *TrafficRepository) ConsumeInviteCode(ctx context.Context, code, username string, tgID int64) error {
	if code == "" || username == "" {
		return errors.New("code and username required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 锁定一行进行原子 increment + 检查
	var revokedInt, maxUses, usedCount int
	var expiresAt sql.NullTime
	err = tx.QueryRowContext(ctx,
		`SELECT revoked, max_uses, used_count, expires_at FROM invite_codes WHERE code = ?`, code).
		Scan(&revokedInt, &maxUses, &usedCount, &expiresAt)
	if err == sql.ErrNoRows {
		return errors.New("邀请码不存在")
	}
	if err != nil {
		return err
	}
	if revokedInt != 0 {
		return errors.New("邀请码已被撤销")
	}
	if maxUses > 0 && usedCount >= maxUses {
		return errors.New("邀请码已用尽")
	}
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return errors.New("邀请码已过期")
	}

	// 写使用记录;同 (code, username) 唯一键会拦重复消耗
	var tgArg any
	if tgID != 0 {
		tgArg = tgID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO invite_code_uses (code, username, tg_id) VALUES (?, ?, ?)`,
		code, username, tgArg); err != nil {
		return fmt.Errorf("record use: %w", err)
	}

	// 计数 +1
	if _, err := tx.ExecContext(ctx,
		`UPDATE invite_codes SET used_count = used_count + 1 WHERE code = ?`, code); err != nil {
		return fmt.Errorf("inc used_count: %w", err)
	}

	return tx.Commit()
}

// RevokeInviteCode 撤销(已经被用过的不影响,但后续不可再消耗)。
func (r *TrafficRepository) RevokeInviteCode(ctx context.Context, code string) error {
	if code == "" {
		return errors.New("code required")
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE invite_codes SET revoked = 1 WHERE code = ?`, code)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("邀请码不存在")
	}
	return nil
}

// DeleteInviteCode 硬删除邀请码(连同使用记录)。从列表彻底移除。
func (r *TrafficRepository) DeleteInviteCode(ctx context.Context, code string) error {
	if code == "" {
		return errors.New("code required")
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM invite_codes WHERE code = ?`, code)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("邀请码不存在")
	}
	_, _ = r.db.ExecContext(ctx, `DELETE FROM invite_code_uses WHERE code = ?`, code)
	return nil
}

// ListInviteCodes 列出邀请码;createdBy 非空时按创建者过滤。按 created_at DESC 排。
func (r *TrafficRepository) ListInviteCodes(ctx context.Context, createdBy string, limit int) ([]InviteCode, error) {
	if limit <= 0 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	if createdBy == "" {
		rows, err = r.db.QueryContext(ctx,
			`SELECT code, kind, bind_username, created_by, package_id,
			        max_uses, used_count, expires_at, revoked, remark, created_at, duration_months
			   FROM invite_codes ORDER BY created_at DESC LIMIT ?`, limit)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT code, kind, bind_username, created_by, package_id,
			        max_uses, used_count, expires_at, revoked, remark, created_at, duration_months
			   FROM invite_codes WHERE created_by = ? ORDER BY created_at DESC LIMIT ?`,
			createdBy, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []InviteCode
	for rows.Next() {
		var ic InviteCode
		var pkgID sql.NullInt64
		var expiresAt sql.NullTime
		var revokedInt int
		if err := rows.Scan(&ic.Code, &ic.Kind, &ic.BindUsername, &ic.CreatedBy, &pkgID,
			&ic.MaxUses, &ic.UsedCount, &expiresAt, &revokedInt, &ic.Remark, &ic.CreatedAt, &ic.DurationMonths); err != nil {
			return nil, err
		}
		if pkgID.Valid {
			v := pkgID.Int64
			ic.PackageID = &v
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			ic.ExpiresAt = &t
		}
		ic.Revoked = revokedInt != 0
		out = append(out, ic)
	}
	return out, rows.Err()
}

// ============ 审计 ============

// WriteTGAudit 写一条审计。失败时打 log 即可,不影响主流程(由调用方决定)。
func (r *TrafficRepository) WriteTGAudit(ctx context.Context, a TGAudit) error {
	var tgArg any
	if a.TGID != 0 {
		tgArg = a.TGID
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tg_audit (tg_id, username, action, detail) VALUES (?, ?, ?, ?)`,
		tgArg, a.Username, a.Action, a.Detail)
	return err
}
