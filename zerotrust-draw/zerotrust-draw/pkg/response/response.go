// Package response는 standards.md에 정의된 공통 HTTP 응답 포맷을 제공합니다.
//
// 성공: { "success": true,  "data": {...}, "error": null, "meta": {...} }
// 실패: { "success": false, "data": null,  "error": {...}, "meta": {...} }
package response

import (
	"encoding/json"
	"net/http"
	"time"

	appErrors "zerotrust-draw/pkg/errors"
	"github.com/google/uuid"
)

// Meta는 모든 응답에 포함되는 메타데이터입니다.
type Meta struct {
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id"`
}

// ErrorBody는 실패 응답의 error 필드입니다.
// Detail 필드는 내부 정보 노출 위험으로 제거됩니다.
// 내부 에러 원인은 서버 로그에만 기록합니다.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// envelope는 공통 응답 래퍼입니다.
type envelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   *ErrorBody  `json:"error"`
	Meta    Meta        `json:"meta"`
}

func newMeta(reqID string) Meta {
	if reqID == "" {
		reqID = uuid.NewString()
	}
	return Meta{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: reqID,
	}
}

// JSON은 성공 응답을 씁니다.
func JSON(w http.ResponseWriter, status int, data interface{}, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{
		Success: true,
		Data:    data,
		Error:   nil,
		Meta:    newMeta(reqID),
	})
}

// Error는 실패 응답을 씁니다.
// *appErrors.AppError이면 Code와 Message를 그대로 사용하고,
// 그 외 error는 ERR_SYS_001 / 500으로 처리합니다.
func Error(w http.ResponseWriter, err error, reqID string) {
	var status int
	var body ErrorBody

	if ae, ok := err.(*appErrors.AppError); ok {
		status = codeToHTTPStatus(ae.Code)
		body = ErrorBody{Code: ae.Code, Message: ae.Message}
	} else {
		status = http.StatusInternalServerError
		body = ErrorBody{
			Code:    appErrors.ErrSystemError.Code,
			Message: appErrors.ErrSystemError.Message,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{
		Success: false,
		Data:    nil,
		Error:   &body,
		Meta:    newMeta(reqID),
	})
}

// codeToHTTPStatus는 에러 코드를 HTTP 상태 코드로 변환합니다.
func codeToHTTPStatus(code string) int {
	switch code {
	case "ERR_AUTH_001":
		return http.StatusUnauthorized
	case "ERR_AUTH_002":
		return http.StatusForbidden
	case "ERR_BID_003":
		return http.StatusConflict
	case "ERR_RATE_001":
		return http.StatusTooManyRequests
	case "ERR_SYS_001":
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}
