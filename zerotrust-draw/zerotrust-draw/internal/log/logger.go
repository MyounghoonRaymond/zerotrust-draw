package log

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// LogEntry는 JSON Lines 포맷의 로그 항목입니다.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	AuctionID string `json:"auction_id"`
	UserID    string `json:"user_id"`
	RequestID string `json:"request_id"`
	Message   string `json:"message"`
	ErrorCode string `json:"error_code"`
}

// ─────────────────────────────────────────────
//  DB 연동 (선택적)
// ─────────────────────────────────────────────

var (
	dbMu   sync.Mutex
	auditDB *sql.DB
)

// SetDB는 감사 로그를 DB에도 저장하도록 설정합니다.
// main.go에서 DB 초기화 후 호출합니다.
// 호출하지 않으면 stdout JSON Lines만 출력합니다.
func SetDB(db *sql.DB) {
	dbMu.Lock()
	defer dbMu.Unlock()
	auditDB = db
}

// ─────────────────────────────────────────────
//  공개 로깅 함수
// ─────────────────────────────────────────────

// Audit는 감사 로그를 stdout + DB(설정 시)에 출력합니다.
func Audit(event, auctionID, userID, reqID, msg string) {
	writeLog("AUDIT", event, auctionID, userID, reqID, msg, "")
}

// Warn은 경고 로그를 stdout + DB(설정 시)에 출력합니다.
func Warn(event, auctionID, userID, reqID, msg, errCode string) {
	writeLog("WARN", event, auctionID, userID, reqID, msg, errCode)
}

// Error는 에러 로그를 stdout + DB(설정 시)에 출력합니다.
func Error(event, auctionID, userID, reqID, msg, errCode string) {
	writeLog("ERROR", event, auctionID, userID, reqID, msg, errCode)
}

// ─────────────────────────────────────────────
//  내부 구현
// ─────────────────────────────────────────────

func writeLog(level, event, auctionID, userID, reqID, msg, errCode string) {
	now := time.Now().UTC()
	entry := LogEntry{
		Timestamp: now.Format(time.RFC3339),
		Level:     level,
		Event:     event,
		AuctionID: auctionID,
		UserID:    userID,
		RequestID: reqID,
		Message:   msg,
		ErrorCode: errCode,
	}

	// stdout JSON Lines 출력 (항상)
	data, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(data))

	// DB 저장 (SetDB로 연결된 경우에만)
	dbMu.Lock()
	db := auditDB
	dbMu.Unlock()

	if db == nil {
		return
	}

	// DB 쓰기 실패는 stdout에만 기록하고 패닉하지 않습니다.
	_, err := db.Exec(`
		INSERT INTO audit_logs (timestamp, level, event, auction_id, user_id, request_id, message, error_code)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		now.Format(time.RFC3339), level, event,
		nullableStr(auctionID), nullableStr(userID),
		nullableStr(reqID), msg, nullableStr(errCode),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[LOG_DB_ERR] audit_logs 저장 실패: %v\n", err)
	}
}

// nullableStr은 빈 문자열을 nil로 변환합니다 (DB NULL 저장용).
func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
