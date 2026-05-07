// Package handler는 경매 관련 HTTP 핸들러를 제공합니다.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"zerotrust-draw/internal/auction"
	"zerotrust-draw/internal/middleware"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/response"
)

// AuctionHandler는 경매 관련 HTTP 핸들러를 담습니다.
type AuctionHandler struct {
	svc *auction.Service
}

// NewAuctionHandler는 AuctionHandler를 생성합니다.
func NewAuctionHandler(svc *auction.Service) *AuctionHandler {
	return &AuctionHandler{svc: svc}
}

// ─────────────────────────────────────────────
//  GET /api/auctions  (경매 목록 + 페이지네이션)
// ─────────────────────────────────────────────

// ListAuctions handles GET /api/auctions?page=1&limit=20
func (h *AuctionHandler) ListAuctions(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	q := r.URL.Query()

	page, err := strconv.Atoi(q.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err2 := strconv.Atoi(q.Get("limit"))
	if err2 != nil || limit < 1 {
		limit = 20
	}
	// 최대 페이지 크기 초과 시 명시적 거부 (서버 자원 보호)
	if limit > 50 {
		response.Error(w, &appErrors.AppError{
			Code:    "ERR_BID_004",
			Message: "limit은 50 이하여야 합니다.",
		}, reqID)
		return
	}
	// 극단적 offset 방지 (page 상한: 10,000)
	if page > 10_000 {
		response.Error(w, &appErrors.AppError{
			Code:    "ERR_BID_004",
			Message: "page는 10000 이하여야 합니다.",
		}, reqID)
		return
	}

	result, err3 := h.svc.ListAuctions(page, limit)
	if err3 != nil {
		response.Error(w, err3, reqID)
		return
	}

	response.JSON(w, http.StatusOK, result, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/auctions
// ─────────────────────────────────────────────

type createAuctionRequest struct {
	ItemName string `json:"itemName"`
	StartAt  string `json:"startAt"` // RFC3339
	EndAt    string `json:"endAt"`   // RFC3339
}

type createAuctionResponse struct {
	ID       string `json:"id"`
	ItemName string `json:"itemName"`
	Status   string `json:"status"`
	StartAt  string `json:"startAt"`
	EndAt    string `json:"endAt"`
}

// CreateAuction handles POST /api/auctions
// 변경: Authorization 헤더 토큰 → context의 세션 claims 사용
func (h *AuctionHandler) CreateAuction(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	// context에서 세션 claims 확인 (Auth 미들웨어가 이미 검증 완료)
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	// 요청 바디 파싱
	var req createAuctionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회/파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청 형식이 올바르지 않습니다."}, reqID)
		return
	}
	startAt, err := time.Parse(time.RFC3339, req.StartAt)
	if err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "startAt 형식 오류 (RFC3339 사용)"}, reqID)
		return
	}
	endAt, err := time.Parse(time.RFC3339, req.EndAt)
	if err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "endAt 형식 오류 (RFC3339 사용)"}, reqID)
		return
	}

	// 변경: 토큰 문자열 대신 context에서 꺼낸 claims를 service에 직접 전달
	a, err := h.svc.CreateAuction(claims, auction.CreateAuctionInput{
		ItemName: req.ItemName,
		StartAt:  startAt,
		EndAt:    endAt,
	})
	if err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusCreated, createAuctionResponse{
		ID:       a.ID,
		ItemName: a.ItemName,
		Status:   a.Status,
		StartAt:  a.StartAt.Format(time.RFC3339),
		EndAt:    a.EndAt.Format(time.RFC3339),
	}, reqID)
}

// ─────────────────────────────────────────────
//  GET /api/auctions/:auctionId
// ─────────────────────────────────────────────

// GetAuction handles GET /api/auctions/{auctionId}
func (h *AuctionHandler) GetAuction(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	auctionID := extractAuctionID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "auctionId가 필요합니다."}, reqID)
		return
	}

	a, err := h.svc.GetAuction(auctionID)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"id":        a.ID,
		"itemName":  a.ItemName,
		"createdBy": a.CreatedBy,
		"status":    a.Status,
		"startAt":   a.StartAt.Format(time.RFC3339),
		"endAt":     a.EndAt.Format(time.RFC3339),
		"createdAt": a.CreatedAt.Format(time.RFC3339),
	}, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/auctions/:auctionId/close
// ─────────────────────────────────────────────

// CloseAuction handles POST /api/auctions/{auctionId}/close
// 변경: Authorization 헤더 토큰 → context의 세션 claims 사용
func (h *AuctionHandler) CloseAuction(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	auctionID := extractAuctionID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "auctionId가 필요합니다."}, reqID)
		return
	}

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	if err := h.svc.CloseAuction(claims, auctionID); err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"auctionId": auctionID,
		"status":    "CLOSED",
	}, reqID)
}

// ─────────────────────────────────────────────
//  GET /api/auctions/:auctionId/result
// ─────────────────────────────────────────────

// GetAuctionResult handles GET /api/auctions/{auctionId}/result
func (h *AuctionHandler) GetAuctionResult(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	auctionID := extractAuctionID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "auctionId가 필요합니다."}, reqID)
		return
	}

	result, err := h.svc.GetAuctionResult(auctionID)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusOK, result, reqID)
}

// ─────────────────────────────────────────────
//  내부 헬퍼
// ─────────────────────────────────────────────

// extractAuctionID는 /api/auctions/{id} 또는 /api/auctions/{id}/xxx 에서 id를 추출합니다.
func extractAuctionID(path string) string {
	trimmed := strings.TrimPrefix(path, "/api/auctions/")
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}
