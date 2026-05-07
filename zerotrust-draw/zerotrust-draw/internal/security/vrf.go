// Package security: 검증 가능한 공정 추첨용 VRF + Multi-party Beacon 프리미티브.
//
// 본 모듈은 기존 Argon2id/Pepper 기반 비밀번호 보호 위에
// "검증 가능한 공정 추첨"을 위한 두 가지 보안 프리미티브를 추가합니다.
//
//  1. VRF (Verifiable Random Function) — Sign-to-VRF over Ed25519
//     proof  = Ed25519.Sign(priv, seed)              // RFC 8032 결정적 서명
//     output = SHA-512(proof || pubkey || seed)      // 의사난수 출력
//     누구나 (pubkey, seed, proof)로 output을 재계산·검증 가능합니다.
//     서명자는 동일 입력에 대해 출력을 임의로 바꿀 수 없습니다(determinism).
//
//  2. Multi-party Beacon — commit-reveal nonce contribution
//     각 참가자가 무작위 nonce를 commit한 뒤 reveal하면, 모든 nonce를
//     userID 오름차순으로 정렬·연결하여 SHA-256으로 결합 시드를 만듭니다.
//     어떤 한 참가자도 단독으로 시드를 결정/조작할 수 없습니다(bias resistance).
//
// 결합 효과:
//   - 시드는 다자간 합의로 결정 → 한 명도 시드 단독 조작 불가
//   - VRF는 운영자 키로 시드를 결정적·검증 가능 출력으로 변환 → 운영자도 결과 사후 조작 불가
//   - 운영자 pubkey는 라운드 생성 시점에 미리 commit → 키 grinding 공격 차단
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
)

// ─────────────────────────────────────────────
//  VRF (Sign-to-VRF over Ed25519)
// ─────────────────────────────────────────────

// VRFKeyPair는 Ed25519 기반 VRF 키쌍입니다.
type VRFKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateVRFKey는 새로운 Ed25519 키쌍을 생성합니다.
func GenerateVRFKey() (*VRFKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &VRFKeyPair{Public: pub, Private: priv}, nil
}

// VRFEvaluate는 seed로부터 (output, proof)를 결정적으로 계산합니다.
//
//	proof  = Ed25519.Sign(priv, seed)
//	output = SHA-512(proof || pubkey || seed)
func VRFEvaluate(priv ed25519.PrivateKey, seed []byte) (output, proof []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid ed25519 private key length")
	}
	proof = ed25519.Sign(priv, seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("failed to derive public key")
	}
	h := sha512.New()
	h.Write(proof)
	h.Write(pub)
	h.Write(seed)
	return h.Sum(nil), proof, nil
}

// VRFVerify는 (pubkey, seed, proof)로 output을 재계산하고 서명을 검증합니다.
// proof가 올바른 서명이면 ok=true와 함께 결정적 output을 반환합니다.
func VRFVerify(pub ed25519.PublicKey, seed, proof []byte) (output []byte, ok bool) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	if !ed25519.Verify(pub, seed, proof) {
		return nil, false
	}
	h := sha512.New()
	h.Write(proof)
	h.Write(pub)
	h.Write(seed)
	return h.Sum(nil), true
}

// SelectWinnerIndex는 VRF output을 [0, n) 범위 정수로 변환합니다.
// output 앞 8바이트를 빅엔디안 uint64로 해석한 뒤 n으로 나머지 연산합니다.
// 참가자 수 n이 2^64에 비해 매우 작으므로 modulo bias는 무시할 수준입니다.
func SelectWinnerIndex(output []byte, n int) int {
	if n <= 0 || len(output) < 8 {
		return 0
	}
	v := binary.BigEndian.Uint64(output[:8])
	return int(v % uint64(n))
}

// ─────────────────────────────────────────────
//  Multi-party Beacon (commit-reveal nonce)
// ─────────────────────────────────────────────

// BeaconCommit은 참가자의 nonce commit 해시를 계산합니다.
// 포맷: SHA-256(userID + ":" + nonce + ":" + salt)
// 기존 ComputeCommitHash와 동일한 입력 포맷을 따라 코드/테스트 재활용을 극대화합니다.
func BeaconCommit(userID, nonce, salt string) string {
	raw := userID + ":" + nonce + ":" + salt
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// VerifyBeaconCommit은 (nonce, salt) 공개값이 commit과 일치하는지 검증합니다.
func VerifyBeaconCommit(userID, nonce, salt, commit string) bool {
	return BeaconCommit(userID, nonce, salt) == commit
}

// NonceContribution은 한 참가자가 reveal한 nonce 기여분입니다.
type NonceContribution struct {
	UserID string
	Nonce  string
}

// CombineNonces는 reveal된 nonce들을 결정적 순서(userID 오름차순)로 결합하여
// 추첨 시드를 만듭니다. 누구든 동일한 입력으로 동일한 시드를 재계산할 수 있어야 하며
// (공개 검증성), 어떤 한 참가자도 시드를 단독으로 조작할 수 없습니다(bias resistance).
func CombineNonces(items []NonceContribution) []byte {
	sorted := make([]NonceContribution, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].UserID < sorted[j].UserID })

	h := sha256.New()
	for _, it := range sorted {
		h.Write([]byte(it.UserID))
		h.Write([]byte(":"))
		h.Write([]byte(it.Nonce))
		h.Write([]byte(";"))
	}
	return h.Sum(nil)
}

// GenerateNonceHex는 클라이언트/테스트가 사용할 32바이트(64-hex) nonce 생성 도우미입니다.
func GenerateNonceHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
