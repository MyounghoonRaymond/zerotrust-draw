// Package security는 비밀번호 해싱(Argon2id), 솔트 생성, 입력값 검증을 담당합니다.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

// GenerateSaltBytes는 size 바이트의 암호학적으로 안전한 솔트를 반환합니다.
func GenerateSaltBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// HashPassword는 비밀번호 + ServerPepper + salt를 Argon2id로 해싱하여 hex 문자열을 반환합니다.
//
// 보안 특성:
//   - Argon2id: GPU 공격 저항성 (메모리 하드)
//   - ServerPepper: DB 탈취 시 오프라인 크래킹 방지
//   - salt: 레인보우 테이블 공격 방지
//   - GO_ENV=test 시 빠른 파라미터 사용 (테스트 속도 최적화)
func HashPassword(password string, salt []byte) string {
	p := GetArgon2Params()
	hash := argon2.IDKey(
		[]byte(password+GetServerPepper()),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		Argon2KeyLength,
	)
	return hex.EncodeToString(hash)
}

// VerifyPassword는 입력 비밀번호와 저장된 해시를 상수 시간으로 비교합니다.
//
// 보안 특성:
//   - subtle.ConstantTimeCompare: 타이밍 공격 방지
func VerifyPassword(password string, salt []byte, storedHashHex string) bool {
	inputHashHex := HashPassword(password, salt)

	inputHash, err1 := hex.DecodeString(inputHashHex)
	storedHash, err2 := hex.DecodeString(storedHashHex)
	if err1 != nil || err2 != nil {
		return false
	}
	if len(inputHash) != len(storedHash) {
		return false
	}
	return subtle.ConstantTimeCompare(inputHash, storedHash) == 1
}
