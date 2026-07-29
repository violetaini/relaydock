package handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// 备份加密格式(下载时由管理员现场输入口令派生密钥,口令不落盘):
//
//	magic(8) || salt(16) || nonce(12) || AES-256-GCM 密文(含 16 字节 tag)
//
// 密钥 = scrypt(口令, salt, N=1<<15, r=8, p=1)。AAD = magic,防止头部被篡改。
// 这样即便备份 zip 泄露(T2),没有口令也无法解出其中的 agent token 与 master 私钥。
var backupMagic = []byte("RLDKBKP1")

const (
	backupSaltLen  = 16
	backupNonceLen = 12
	backupKeyLen   = 32
	scryptN        = 1 << 15
	scryptR        = 8
	scryptP        = 1
	// 口令下限:挡住 "1"、"abc" 这类一猜即中的弱口令;不是强度上限。
	backupMinPassphraseLen = 8
)

func deriveBackupKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, backupKeyLen)
}

// encryptBackup 用口令加密 plaintext,把 magic||salt||nonce||密文 写入 w。
func encryptBackup(w io.Writer, plaintext []byte, passphrase string) error {
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, backupNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, backupMagic)

	for _, part := range [][]byte{backupMagic, salt, nonce, ciphertext} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

// isEncryptedBackup 报告 data 是否为本程序加密格式的备份(用于兼容旧的明文 zip 备份)。
func isEncryptedBackup(data []byte) bool {
	return len(data) >= len(backupMagic) && bytes.Equal(data[:len(backupMagic)], backupMagic)
}

// decryptBackup 用口令解密 encryptBackup 产出的数据,返回原始 zip 字节。
func decryptBackup(data []byte, passphrase string) ([]byte, error) {
	header := len(backupMagic) + backupSaltLen + backupNonceLen
	if len(data) < header+16 {
		return nil, errors.New("备份文件已损坏或格式不正确")
	}
	if !isEncryptedBackup(data) {
		return nil, errors.New("不是加密备份")
	}
	off := len(backupMagic)
	salt := data[off : off+backupSaltLen]
	off += backupSaltLen
	nonce := data[off : off+backupNonceLen]
	off += backupNonceLen
	ciphertext := data[off:]

	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, backupMagic)
	if err != nil {
		// GCM 校验失败基本就是口令错误(或文件被篡改)。
		return nil, errors.New("解密失败:备份口令错误或文件已损坏")
	}
	return plaintext, nil
}
