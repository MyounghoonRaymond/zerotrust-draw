package security

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeInput은 유니코드 입력을 NFC(Canonical Decomposition, Canonical Composition)로
// 정규화합니다. 시각적으로 동일하나 내부 코드포인트가 다른 homoglyph 공격을 방어합니다.
// 모든 사용자 입력은 검증 전에 이 함수를 통과해야 합니다.
func NormalizeInput(input string) string {
	return norm.NFC.String(input)
}

// ValidateHash는 SHA-256 해시값의 형식을 검증합니다.
// 64자리 16진수 문자열이어야 합니다.
func ValidateHash(hash string) bool {
	matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, strings.ToLower(hash))
	return matched
}

// ContainsDangerousChars는 쉘 명령어/SQL Injection 유도 문자를 검사합니다.
func ContainsDangerousChars(input string) bool {
	dangerousPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/",
		"`", "$", "|", "&", ">", "<",
		"(", ")", "{", "}",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

