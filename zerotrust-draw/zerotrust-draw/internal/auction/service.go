// Package auction은 경매 관련 비즈니스 로직을 담당합니다.
// DB 접근은 Repository를 통해서만 수행합니다.
package auction

import (
	"time"

	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"

	"github.com/google/uuid"
)

// Service는 경매 비즈니스 로직을 처리합니다.
type Service struct {
	repo *Repository
}

// NewService는 Service를 생성합니다.
// 변경: auth.Authenticator 의존성 제거 — 인증은 미들웨어+세션이 전담합니다.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// ─────────────────────────────────────────────
//  1. 경매 생성  POST /api/auctions
// ─────────────────────────────────────────────

// CreateAuctionInput은 경매 생성 요청 파라미터입니다.
type CreateAuctionInput struct {
	ItemName string
	StartAt  time.Time
	EndAt    time.Time
}

// CreateAuction은 새로운 경매를 생성합니다.
// 변경: token string → *auth.UserClaims (미들웨어가 이미 검증 완료)
// AUCTIONEER 역할만 호출할 수 있습니다.
func (s *Service) CreateAuction(claims *auth.UserClaims, input CreateAuctionInput) (*models.Auction, error) {
	// 1. 권한 확인 (인증은 미들웨어가 완료, 여기서는 역할만 확인)
	if !claims.HasRole(models.RoleAuctioneer) {
		return nil, appErrors.ErrForbidden
	}

	// 2. 입력 검증
	if input.ItemName == "" {
		return nil, &appErrors.AppError{Code: "ERR_BID_004", Message: "상품명을 입력해주세요."}
	}
	// itemName: 최대 256자 (DB 저장 및 응답 크기 제한)
	if len([]rune(input.ItemName)) > 256 {
		return nil, &appErrors.AppError{Code: "ERR_BID_004", Message: "상품명은 256자 이하여야 합니다."}
	}
	if err := validateAuctionTimes(input.StartAt, input.EndAt); err != nil {
		return nil, err
	}

	// 3. DB INSERT
	id := uuid.NewString()
	now := time.Now().UTC()

	if err := s.repo.InsertAuction(id, input.ItemName, claims.UserID, input.StartAt, input.EndAt); err != nil {
		applog.Error("AUCTION_CREATE_FAIL", id, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	applog.Audit("AUCTION_CREATED", id, claims.UserID, "", "경매 생성 완료")

	return &models.Auction{
		ID:        id,
		ItemName:  input.ItemName,
		CreatedBy: claims.UserID,
		Status:    "OPEN",
		StartAt:   input.StartAt,
		EndAt:     input.EndAt,
		CreatedAt: now,
	}, nil
}

// ─────────────────────────────────────────────
//  2. 경매 목록  GET /api/auctions
// ─────────────────────────────────────────────

// AuctionListResult는 경매 목록 응답입니다.
type AuctionListResult struct {
	Auctions []*models.Auction `json:"auctions"`
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	Limit    int               `json:"limit"`
}

// ListAuctions는 경매 목록을 페이지네이션하여 반환합니다.
// page: 1부터 시작, limit: 최대 50
func (s *Service) ListAuctions(page, limit int) (*AuctionListResult, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 50 {
		limit = 20
	}
	offset := (page - 1) * limit

	auctions, total, err := s.repo.ListAuctions(limit, offset)
	if err != nil {
		applog.Error("AUCTION_LIST_FAIL", "", "", "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	return &AuctionListResult{
		Auctions: auctions,
		Total:    total,
		Page:     page,
		Limit:    limit,
	}, nil
}

// ─────────────────────────────────────────────
//  3. 경매 조회  GET /api/auctions/:auctionId
// ─────────────────────────────────────────────

// GetAuction은 경매 정보를 조회합니다. 인증 불필요.
func (s *Service) GetAuction(auctionID string) (*models.Auction, error) {
	auction, err := s.repo.FindAuctionByID(auctionID)
	if err != nil {
		applog.Error("AUCTION_GET_FAIL", auctionID, "", "", err.Error(), "ERR_SYS_001")
		return nil, err
	}
	return auction, nil
}

// ─────────────────────────────────────────────
//  3. 경매 마감  POST /api/auctions/:auctionId/close
// ─────────────────────────────────────────────

// CloseAuction은 경매 상태를 OPEN → CLOSED로 변경합니다.
// 변경: token string → *auth.UserClaims
// AUCTIONEER 또는 ADMIN만 호출 가능, Race Condition 방지를 위해 트랜잭션 사용.
func (s *Service) CloseAuction(claims *auth.UserClaims, auctionID string) error {
	if !claims.HasRole(models.RoleAuctioneer) {
		return appErrors.ErrForbidden
	}

	tx, err := s.repo.BeginTx()
	if err != nil {
		return appErrors.ErrSystemError
	}
	defer tx.Rollback() //nolint:errcheck

	status, err := s.repo.FindAuctionStatusForUpdate(tx, auctionID)
	if err != nil {
		return err
	}
	if status != "OPEN" {
		return &appErrors.AppError{Code: "ERR_BID_001", Message: "이미 마감된 경매입니다."}
	}

	if err := s.repo.UpdateAuctionStatus(tx, auctionID, "CLOSED"); err != nil {
		applog.Error("AUCTION_CLOSE_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return appErrors.ErrSystemError
	}

	// Reveal 마감 시각 설정: 마감 후 24시간 이내만 Reveal 허용
	revealDeadline := time.Now().UTC().Add(24 * time.Hour)
	if err := s.repo.SetRevealDeadline(tx, auctionID, revealDeadline); err != nil {
		applog.Error("REVEAL_DEADLINE_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return appErrors.ErrSystemError
	}

	if err := tx.Commit(); err != nil {
		return appErrors.ErrSystemError
	}

	applog.Audit("AUCTION_CLOSED", auctionID, claims.UserID, "", "경매 마감 완료 (Reveal 마감: "+revealDeadline.Format(time.RFC3339)+")")
	return nil
}

// ─────────────────────────────────────────────
//  4. 낙찰 결과 조회  GET /api/auctions/:auctionId/result
// ─────────────────────────────────────────────

// AuctionResult는 낙찰 결과 응답 데이터입니다.
type AuctionResult struct {
	AuctionID      string     `json:"auctionId"`
	Status         string     `json:"status"`
	WinnerID       *string    `json:"winnerId"`
	WinnerUsername *string    `json:"winnerUsername"`
	WinnerPrice    *int       `json:"winnerPrice"`
	Bids           []BidEntry `json:"bids"`
}

// BidEntry는 낙찰 결과 안에 포함되는 입찰 항목입니다.
type BidEntry struct {
	BidID   string `json:"bidId"`
	UserID  string `json:"userId"`
	IsValid *int   `json:"isValid"`
	Price   *int   `json:"price"`
}

// GetAuctionResult는 낙찰 결과를 조회합니다.
// 경매 상태가 CLOSED 또는 VERIFIED일 때만 입찰 데이터를 반환합니다.
func (s *Service) GetAuctionResult(auctionID string) (*AuctionResult, error) {
	auction, err := s.repo.FindAuctionByID(auctionID)
	if err != nil {
		return nil, err
	}
	if auction.Status == "OPEN" {
		return nil, &appErrors.AppError{Code: "ERR_BID_002", Message: "경매가 아직 진행 중입니다."}
	}

	bids, err := s.repo.FindBidsByAuctionID(auctionID)
	if err != nil {
		applog.Error("RESULT_QUERY_FAIL", auctionID, "", "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	result := &AuctionResult{
		AuctionID: auctionID,
		Status:    auction.Status,
		Bids:      bids,
	}

	// 낙찰자 선정: is_valid=1이고 최고가인 첫 번째 입찰
	for _, b := range bids {
		if b.IsValid != nil && *b.IsValid == 1 && b.Price != nil {
			winnerID := b.UserID
			winnerPrice := *b.Price
			result.WinnerID = &winnerID
			result.WinnerPrice = &winnerPrice
			if name := s.repo.FindUsernameByID(winnerID); name != "" {
				result.WinnerUsername = &name
			}
			break
		}
	}

	return result, nil
}

// ─────────────────────────────────────────────
//  내부 헬퍼
// ─────────────────────────────────────────────

func validateAuctionTimes(startAt, endAt time.Time) error {
	if startAt.IsZero() || endAt.IsZero() {
		return &appErrors.AppError{Code: "ERR_BID_004", Message: "시작/종료 시간을 입력해주세요."}
	}
	if !endAt.After(startAt) {
		return &appErrors.AppError{Code: "ERR_BID_004", Message: "종료 시간은 시작 시간보다 이후여야 합니다."}
	}
	return nil
}
