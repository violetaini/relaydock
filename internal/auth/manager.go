package auth

import (
	"context"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/violetaini/relaydock/internal/storage"
)

type Credentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type Manager struct {
	repo *storage.TrafficRepository
	// mu serializes credential mutations with the final session issuance step.
	// A login authenticated against the old hash must not create a session after
	// a concurrent password reset has removed all existing sessions.
	mu *sync.RWMutex
}

func NewManager(repo *storage.TrafficRepository) (*Manager, error) {
	if repo == nil {
		return nil, errors.New("auth manager requires repository")
	}

	m := &Manager{repo: repo, mu: repo.AuthMutationMutex()}
	return m, nil
}

func (m *Manager) Authenticate(ctx context.Context, username, password string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok, err := m.authenticateLocked(ctx, username, password)
	return ok, err
}

// AuthenticateAndRun keeps a successful password verification and the caller's
// session issuance callback in one credential critical section.
func (m *Manager) AuthenticateAndRun(ctx context.Context, username, password string, run func(storage.User) error) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, ok, err := m.authenticateLocked(ctx, username, password)
	if err != nil || !ok {
		return ok, err
	}
	if run != nil {
		if err := run(user); err != nil {
			return false, err
		}
	}
	return true, nil
}

// RunForActiveUser serializes a session issuance following a completed 2FA
// challenge with credential mutations for the same process.
func (m *Manager) RunForActiveUser(ctx context.Context, username string, run func(storage.User) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, err := m.activeUserLocked(ctx, username)
	if err != nil {
		return err
	}
	if run != nil {
		return run(user)
	}
	return nil
}

func (m *Manager) authenticateLocked(ctx context.Context, username, password string) (storage.User, bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return storage.User{}, false, nil
	}

	user, err := m.repo.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return storage.User{}, false, nil
		}
		return storage.User{}, false, err
	}
	if !user.IsActive {
		return storage.User{}, false, nil
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return storage.User{}, false, nil
	}

	return user, true, nil
}

func (m *Manager) activeUserLocked(ctx context.Context, username string) (storage.User, error) {
	user, err := m.repo.GetUser(ctx, strings.TrimSpace(username))
	if err != nil {
		return storage.User{}, err
	}
	if !user.IsActive {
		return storage.User{}, errors.New("user is disabled")
	}
	return user, nil
}

func (m *Manager) Update(ctx context.Context, currentUsername, username, password string) (string, error) {
	return m.UpdateAndRun(ctx, currentUsername, username, password, nil)
}

func (m *Manager) UpdateAndRun(ctx context.Context, currentUsername, username, password string, run func(string)) (string, error) {
	currentUsername = strings.TrimSpace(currentUsername)
	username = strings.TrimSpace(username)
	if currentUsername == "" {
		return "", errors.New("current username is required")
	}
	if username == "" && password == "" {
		return "", errors.New("username or password must be provided")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var hash string
	if password != "" {
		generated, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		hash = string(generated)
	}

	updated, err := m.repo.UpdateCredentialsAndDeleteSessions(ctx, currentUsername, username, hash)
	if err == nil && run != nil {
		run(updated)
	}
	return updated, err
}

func (m *Manager) ChangePassword(ctx context.Context, username, currentPassword, newPassword string) error {
	return m.ChangePasswordAndRun(ctx, username, currentPassword, newPassword, nil)
}

func (m *Manager) ChangePasswordAndRun(ctx context.Context, username, currentPassword, newPassword string, run func()) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if currentPassword == "" || newPassword == "" {
		return errors.New("passwords are required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	user, err := m.activeUserLocked(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return errors.New("user not found")
		}
		return err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)) != nil {
		return errors.New("current password is incorrect")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := m.repo.UpdateUserPasswordAndDeleteSessions(ctx, username, string(hash)); err != nil {
		return err
	}
	if run != nil {
		run()
	}

	return nil
}

// ResetPasswordAndRun is the administrator reset variant. The caller must
// validate reset authorization before invoking it.
func (m *Manager) ResetPasswordAndRun(ctx context.Context, username, passwordHash string, run func()) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.repo.UpdateUserPasswordAndDeleteSessions(ctx, username, passwordHash); err != nil {
		return err
	}
	if run != nil {
		run()
	}
	return nil
}

func (m *Manager) Credentials(ctx context.Context, username string) (Credentials, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return Credentials{}, errors.New("username is required")
	}
	user, err := m.repo.GetUser(ctx, username)
	if err != nil {
		return Credentials{}, err
	}

	return Credentials{Username: user.Username, PasswordHash: user.PasswordHash}, nil
}

// 用户检索所提供的用户名的存储的用户记录。
func (m *Manager) User(ctx context.Context, username string) (storage.User, error) {
	return m.repo.GetUser(ctx, username)
}

// 检查给定用户提供的密码是否正确。
func (m *Manager) ValidatePassword(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if password == "" {
		return errors.New("password is required")
	}

	user, err := m.repo.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return errors.New("user not found")
		}
		return err
	}

	if !user.IsActive {
		return errors.New("user is disabled")
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return errors.New("password is incorrect")
	}

	return nil
}
