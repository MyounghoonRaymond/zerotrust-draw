package handler

import "regexp"

// uuidV4Regex는 UUID v4 형식 검증용 정규식입니다 (8-4-4-4-12 hex).
// 경로 파라미터로 들어오는 ID 가 임의의 문자열이 아니라 UUID 형식임을 강제하여
// 경로 분기 / DB 조회 / 로그 출력 시 발생할 수 있는 부작용(아주 긴 입력, 제어문자 등)을 차단합니다.
var uuidV4Regex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsValidID는 경로 파라미터로 들어온 ID 의 형식을 검증합니다.
func IsValidID(id string) bool {
	return uuidV4Regex.MatchString(id)
}
