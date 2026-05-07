package models

import "time"

// Auction은 경매 정보를 나타냅니다.
type Auction struct {
	ID             string     // UUID v4
	ItemName       string     // 경매 물품명
	CreatedBy      string     // 생성자 user_id (FK)
	Status         string     // OPEN | CLOSED | VERIFIED
	StartAt        time.Time  // 경매 시작 시각
	EndAt          time.Time  // 경매 종료 시각
	RevealDeadline *time.Time // Reveal 마감 시각 (CLOSED 전환 시 설정, nil이면 무제한)
	CreatedAt      time.Time
}

// Bid는 입찰 정보를 나타냅니다.
type Bid struct {
	ID            string     // UUID v4
	AuctionID     string     // FK → auctions.id
	UserID        string     // FK → users.id
	CommitHash    string     // SHA-256 해시값 (64자리 hex)
	RevealedPrice *int       // 공개 단계 실제 가격
	RevealedSalt  *string    // 공개 단계 Salt
	IsValid       *int       // 1(유효) / 0(무효) / NULL(미검증)
	CommittedAt   time.Time  // 입찰 시각
	RevealedAt    *time.Time // 공개 시각
	CreatedAt     time.Time
}
