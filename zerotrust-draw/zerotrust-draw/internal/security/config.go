package security

import "os"

// Argon2id 파라미터 및 서버 Pepper 관리
// ServerPepper는 환경변수 AUCTION_PEPPER 에서 읽습니다.
// 값이 없으면 빈 문자열이 반환되며, main.go에서 시작 시 패닉 처리합니다.

// 운영 환경 파라미터 (64MB / 3회 반복)
const (
	Argon2SaltLength = 16
	Argon2KeyLength  uint32 = 32
)

// Argon2Params는 환경에 따라 선택되는 Argon2id 파라미터 집합입니다.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// GetArgon2Params는 현재 환경에 맞는 Argon2id 파라미터를 반환합니다.
// GO_ENV=test 일 때는 속도 우선(4MB / 1회)으로 전환하여 테스트 시간을 단축합니다.
func GetArgon2Params() Argon2Params {
	if os.Getenv("GO_ENV") == "test" {
		return Argon2Params{
			Memory:      4 * 1024, // 4MB (테스트 전용)
			Iterations:  1,
			Parallelism: 1,
		}
	}
	return Argon2Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 2,
	}
}

// GetServerPepper는 환경변수 AUCTION_PEPPER 를 반환합니다.
// 런타임 시 매번 읽어 컨테이너 시크릿 교체 등을 즉시 반영합니다.
func GetServerPepper() string {
	return os.Getenv("AUCTION_PEPPER")
}
