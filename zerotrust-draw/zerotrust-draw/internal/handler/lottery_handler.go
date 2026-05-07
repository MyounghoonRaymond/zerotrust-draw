// Package handler - 검증 가능한 공정 추첨 HTTP 엔드포인트.
//
// 라우트 (router.go 에서 등록):
//
//	POST /api/lotteries                            → CreateLotteryRound  (AUCTIONEER)
//	POST /api/lotteries/{id}/commit                → CommitNonce         (BIDDER)
//	POST /api/lotteries/{id}/reveal                → RevealNonce         (BIDDER)
//	POST /api/lotteries/{id}/draw                  → DrawLottery         (AUCTIONEER/ADMIN)
//	GET  /api/lotteries/{id}/verify                → VerifyLottery       (Public)
//	GET  /api/lotteries/{id}/whitelist-proof       → WhitelistProof      (Public)
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"zerotrust-draw/internal/auction"
	"zerotrust-draw/internal/bid"
	"zerotrust-draw/internal/middleware"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"
	"zerotrust-draw/pkg/response"
)

// LotteryHandler는 추첨 라운드 관련 HTTP 엔드포인트 핸들러입니다.
type LotteryHandler struct {
	auctionSvc *auction.Service
	bidSvc     *bid.Service
	drawer     *auction.LotteryDrawer
}

// NewLotteryHandler 생성자.
func NewLotteryHandler(auctionSvc *auction.Service, bidSvc *bid.Service, drawer *auction.LotteryDrawer) *LotteryHandler {
	return &LotteryHandler{auctionSvc: auctionSvc, bidSvc: bidSvc, drawer: drawer}
}

// ─────────────────────────────────────────────
//  Request DTOs
// ─────────────────────────────────────────────

type createLotteryRequest struct {
	ItemName string `json:"itemName"`
	StartAt  string `json:"startAt"` // RFC3339
	EndAt    string `json:"endAt"`   // RFC3339
}

type lotteryCommitRequest struct {
	CommitHash string `json:"commitHash"`
}

type lotteryRevealRequest struct {
	Nonce string `json:"nonce"`
	Salt  string `json:"salt"`
}

// ─────────────────────────────────────────────
//  POST /api/lotteries  (AUCTIONEER)
// ─────────────────────────────────────────────

// CreateLotteryRound: 라운드 생성 + VRF pubkey commit + 화이트리스트 머클 root commit.
func (h *LotteryHandler) CreateLotteryRound(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	var req createLotteryRequest
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

	a, err := h.drawer.CreateLotteryRound(h.auctionSvc, claims, auction.CreateAuctionInput{
		ItemName: req.ItemName, StartAt: startAt, EndAt: endAt,
	})
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	response.JSON(w, http.StatusCreated, map[string]interface{}{
		"id":       a.ID,
		"itemName": a.ItemName,
		"status":   a.Status,
		"startAt":  a.StartAt.Format(time.RFC3339),
		"endAt":    a.EndAt.Format(time.RFC3339),
	}, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/lotteries/{id}/commit  (BIDDER)
// ─────────────────────────────────────────────

// CommitNonce: 다자간 베이컨 commit 단계.
func (h *LotteryHandler) CommitNonce(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	auctionID := extractLotteryID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "lotteryId가 필요합니다."}, reqID)
		return
	}

	var req lotteryCommitRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회/파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청 형식이 올바르지 않습니다."}, reqID)
		return
	}

	res, err := h.bidSvc.CommitNonce(claims, auctionID, req.CommitHash)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	response.JSON(w, http.StatusCreated, res, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/lotteries/{id}/reveal  (BIDDER)
// ─────────────────────────────────────────────

// RevealNonce: 다자간 베이컨 reveal 단계.
func (h *LotteryHandler) RevealNonce(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	auctionID := extractLotteryID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "lotteryId가 필요합니다."}, reqID)
		return
	}

	var req lotteryRevealRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회/파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청 형식이 올바르지 않습니다."}, reqID)
		return
	}

	res, err := h.bidSvc.RevealNonce(claims, auctionID, req.Nonce, req.Salt)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	response.JSON(w, http.StatusOK, res, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/lotteries/{id}/draw  (AUCTIONEER/ADMIN)
// ─────────────────────────────────────────────

// DrawLottery: 마감 후 결정적·검증 가능 추첨 실행.
func (h *LotteryHandler) DrawLottery(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}
	// AUCTIONEER 또는 ADMIN 만 추첨 실행 가능.
	if !claims.HasRole(models.RoleAuctioneer) && !claims.HasRole(models.RoleAdmin) {
		response.Error(w, appErrors.ErrForbidden, reqID)
		return
	}

	auctionID := extractLotteryID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "lotteryId가 필요합니다."}, reqID)
		return
	}

	winner, err := h.drawer.DrawLottery(auctionID)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	if winner == nil {
		response.JSON(w, http.StatusOK, map[string]string{"message": "참가자가 없어 추첨이 종료되었습니다."}, reqID)
		return
	}
	response.JSON(w, http.StatusOK, winner, reqID)
}

// ─────────────────────────────────────────────
//  GET /api/lotteries/{id}/verify  (Public)
// ─────────────────────────────────────────────

// VerifyLottery: 공개 검증 페이지용.
func (h *LotteryHandler) VerifyLottery(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	auctionID := extractLotteryID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "lotteryId가 필요합니다."}, reqID)
		return
	}
	res, err := h.drawer.VerifyLottery(auctionID)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	response.JSON(w, http.StatusOK, res, reqID)
}

// ─────────────────────────────────────────────
//  GET /api/lotteries/{id}/whitelist-proof?username=X  (Public)
// ─────────────────────────────────────────────

// WhitelistProof: 머클 화이트리스트 멤버십 증명.
func (h *LotteryHandler) WhitelistProof(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	auctionID := extractLotteryID(r.URL.Path)
	if !IsValidID(auctionID) {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "lotteryId가 필요합니다."}, reqID)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "username 쿼리가 필요합니다."}, reqID)
		return
	}
	res, err := h.drawer.WhitelistProof(auctionID, username)
	if err != nil {
		response.Error(w, err, reqID)
		return
	}
	response.JSON(w, http.StatusOK, res, reqID)
}

// ─────────────────────────────────────────────
//  내부 헬퍼: /api/lotteries/{id}/... 에서 id 추출
// ─────────────────────────────────────────────

func extractLotteryID(path string) string {
	trimmed := strings.TrimPrefix(path, "/api/lotteries/")
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}
