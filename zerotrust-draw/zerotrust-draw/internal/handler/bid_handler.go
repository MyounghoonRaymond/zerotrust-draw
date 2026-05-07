package handler

import (
	"encoding/json"
	"net/http"

	"zerotrust-draw/internal/bid"
	"zerotrust-draw/internal/middleware"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/response"
)

// BidHandler는 입찰 관련 HTTP 핸들러를 담습니다.
type BidHandler struct {
	svc *bid.Service
}

// NewBidHandler는 BidHandler를 생성합니다.
func NewBidHandler(svc *bid.Service) *BidHandler {
	return &BidHandler{svc: svc}
}

// ─────────────────────────────────────────────
//  POST /api/auctions/:auctionId/bids
// ─────────────────────────────────────────────

type commitBidRequest struct {
	CommitHash string `json:"commitHash"` // 64자리 hex (SHA-256)
}

// CommitBid handles POST /api/auctions/{auctionId}/bids
// 변경: Authorization 헤더 토큰 → context의 세션 claims 사용
func (h *BidHandler) CommitBid(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	// Auth 미들웨어가 이미 검증 완료 → context에서 claims 추출
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	auctionID := extractAuctionID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "auctionId가 필요합니다."}, reqID)
		return
	}

	var req commitBidRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회/파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청 형식이 올바르지 않습니다."}, reqID)
		return
	}

	// 변경: 토큰 대신 claims를 service에 직접 전달
	result, err := h.svc.CommitBidWithResult(claims, auctionID, req.CommitHash)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusCreated, map[string]interface{}{
		"bidId":       result.BidID,
		"auctionId":   result.AuctionID,
		"committedAt": result.CommittedAt,
	}, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/auctions/:auctionId/reveal
// ─────────────────────────────────────────────

type revealBidRequest struct {
	Price int    `json:"price"`
	Salt  string `json:"salt"` // 32자리 이상 hex
}

// RevealBid handles POST /api/auctions/{auctionId}/reveal
// 변경: Authorization 헤더 토큰 → context의 세션 claims 사용
func (h *BidHandler) RevealBid(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	auctionID := extractAuctionID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "auctionId가 필요합니다."}, reqID)
		return
	}

	var req revealBidRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회/파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청 형식이 올바르지 않습니다."}, reqID)
		return
	}
	// price: 0 이상, 최대 10억 (정수 오버플로우 및 비현실적 가격 방지)
	if req.Price < 0 || req.Price > 1_000_000_000 {
		response.Error(w, appErrors.ErrInvalidHashFmt, reqID)
		return
	}
	// salt: 최대 128자 (과도한 입력 거부)
	if len(req.Salt) > 128 {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}, reqID)
		return
	}

	// 변경: 토큰 대신 claims를 service에 직접 전달
	result, err := h.svc.RevealBid(claims, auctionID, req.Price, req.Salt)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"bidId":      result.BidID,
		"isValid":    result.IsValid,
		"revealedAt": result.RevealedAt,
	}, reqID)
}
