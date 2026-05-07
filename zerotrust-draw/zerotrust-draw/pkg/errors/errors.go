package errors

// AppError는 애플리케이션 에러를 나타냅니다.
// Message는 클라이언트에 노출되는 메시지로, 내부 구조를 유추할 수 없도록 최소한의 정보만 담습니다.
// Internal은 서버 로그에만 기록하며 클라이언트 응답 바디에 절대 포함하지 않습니다.
type AppError struct {
	Code     string
	Message  string // 클라이언트 노출용 — 내부 구조·조건을 유추할 수 없도록 단순하게 유지
	Internal error  // 서버 로그 전용 — 절대 응답 바디에 포함하지 않음
}

func (e *AppError) Error() string {
	return e.Message
}

// 인증 / 세션 에러
// ※ ERR_AUTH_001과 ERR_AUTH_003은 클라이언트에 동일한 메시지를 반환합니다.
//
//	공격자가 세션 존재 여부나 만료 여부를 유추할 수 없도록 구분하지 않습니다.
var (
	ErrAuthInvalid    = &AppError{Code: "ERR_AUTH_001", Message: "인증이 필요합니다."}
	ErrForbidden      = &AppError{Code: "ERR_AUTH_002", Message: "요청을 처리할 수 없습니다."}
	ErrSessionInvalid = &AppError{Code: "ERR_AUTH_003", Message: "인증이 필요합니다."}
)

// 입찰 에러
// ※ ERR_BID_001~004 모두 동일한 메시지로 통일합니다.
//
//	어느 필드·조건이 실패했는지 응답에서 알 수 없도록 합니다.
var (
	ErrBidPeriodClosed = &AppError{Code: "ERR_BID_001", Message: "요청을 처리할 수 없습니다."}
	ErrRevealTooEarly  = &AppError{Code: "ERR_BID_002", Message: "요청을 처리할 수 없습니다."}
	ErrDuplicateBid    = &AppError{Code: "ERR_BID_003", Message: "요청을 처리할 수 없습니다."}
	ErrInvalidHashFmt  = &AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}
)

// 검증 에러
// ※ 해시 불일치와 가격 오류를 같은 메시지로 통일합니다.
//
//	공격자가 어떤 값이 틀렸는지 피드백을 받지 못하도록 합니다.
var (
	ErrHashMismatch = &AppError{Code: "ERR_VER_001", Message: "요청을 처리할 수 없습니다."}
	ErrInvalidPrice = &AppError{Code: "ERR_VER_002", Message: "요청을 처리할 수 없습니다."}
)

// 레이트 제한 에러
// ※ 재시도 시간은 응답 헤더(Retry-After)로만 전달하고 바디에는 노출하지 않습니다.
var (
	ErrRateLimit = &AppError{Code: "ERR_RATE_001", Message: "잠시 후 다시 시도하세요."}
)

// 시스템 에러
// ※ 스택 트레이스·DB 오류 등 내부 정보는 Internal 필드에만 기록합니다.
var (
	ErrSystemError = &AppError{Code: "ERR_SYS_001", Message: "요청을 처리할 수 없습니다."}
)
