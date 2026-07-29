package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/violetaini/relaydock/internal/securechan"
)

// 联邦(分享服务器)端到端加密:消费方↔拥有方两个主控之间没有预置身份公钥,
// 唯一共享秘密是分享令牌。做法是双方临时 ECDH,再把分享令牌混入派生密钥——
// 只有同时知道令牌的双方才能算出相同会话密钥(令牌揭示的 ECDH),在 HTTPS 之上
// 叠加端到端加密。消费方为发起方(initiator),拥有方为响应方(responder)。
//
// 握手头:X-Fed-KeyEx: base64(临时公钥)
// 加密头:X-Encrypted: 1(沿用现有约定)

const fedKeyExchangeHeader = "X-Fed-KeyEx"

// mixTokenSecret 把分享令牌折叠进 ECDH 原始密钥,得到带令牌鉴权的共享秘密。
func mixTokenSecret(ecdhSecret []byte, shareToken string) []byte {
	mac := hmac.New(sha256.New, []byte(shareToken))
	mac.Write(ecdhSecret)
	return mac.Sum(nil)
}

// deriveFederationSession 由对端临时公钥 + 本端临时密钥对 + 分享令牌派生会话。
// 角色固定:消费方 isInitiator=true,拥有方 isInitiator=false。
// salt 顺序统一为 (ownerPub, consumerPub),两端必须一致。
func deriveFederationSession(myPriv, ownerPub, consumerPub []byte, shareToken string, isInitiator bool) (*securechan.Session, error) {
	var peerPub []byte
	if isInitiator {
		peerPub = ownerPub // 发起方(消费方)的对端是拥有方
	} else {
		peerPub = consumerPub // 响应方(拥有方)的对端是消费方
	}
	ecdh, err := securechan.ComputeSharedSecret(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	mixed := mixTokenSecret(ecdh, shareToken)
	// DeriveSession(secret, agentEphPub, masterEphPub, isMaster):
	// 消费方=master(initiator),拥有方=agent(responder)。
	// agentEphPub=ownerPub,masterEphPub=consumerPub。
	return securechan.DeriveSession(mixed, ownerPub, consumerPub, isInitiator)
}

func encodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeKey(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, false
	}
	return b, true
}
