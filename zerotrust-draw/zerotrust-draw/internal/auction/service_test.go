package auction_test

import (
	"database/sql"
	"testing"
	"time"

	"zerotrust-draw/internal/bid"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"

	_ "github.com/mattn/go-sqlite3"
)

// ─────────────────────────────────────────────
//  공통 DB 세팅
// ─────────────────────────────────────────────

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL, salt BLOB NOT NULL,
			role TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS auctions (
			id TEXT PRIMARY KEY, item_name TEXT NOT NULL,
			created_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',
			start_at DATETIME NOT NULL, end_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (created_by) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS bids (
			id TEXT PRIMARY KEY, auction_id TEXT NOT NULL,
			user_id TEXT NOT NULL, commit_hash TEXT NOT NULL,
			revealed_price INTEGER, revealed_salt TEXT,
			is_valid INTEGER, committed_at DATETIME NOT NULL,
			revealed_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (auction_id) REFERENCES auctions(id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			UNIQUE(auction_id, user_id)
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		INSERT INTO users (id, username, password, salt, role) VALUES
		('auctioneer-1', 'seller', 'hash', X'00', 'AUCTIONEER'),
		('bidder-1',     'buyer1', 'hash', X'00', 'BIDDER'),
		('bidder-2',     'buyer2', 'hash', X'00', 'BIDDER')
	`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ─────────────────────────────────────────────
//  헬퍼: Service + Claims 생성
//  변경: bid.NewService 인자 1개 (repo만) — auth 의존성 제거됨
// ─────────────────────────────────────────────

func newBidSvc(db *sql.DB) *bid.Service {
	// 수정: authenticator 인자 제거 — NewService(repo)만 받습니다.
	return bid.NewService(bid.NewRepository(db))
}

// bidderClaims는 *auth.UserClaims를 직접 반환합니다.
// 변경: MockAuthenticator 래퍼 없이 claims를 service에 직접 주입합니다.
func bidderClaims(userID, username string) *auth.UserClaims {
	return auth.NewMockBidder(userID, username).Claims
}

// ─────────────────────────────────────────────
//  헬퍼: 경매 / 입찰 데이터 삽입
// ─────────────────────────────────────────────

func insertOpenAuction(t *testing.T, db *sql.DB, auctionID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO auctions (id, item_name, created_by, status, start_at, end_at)
		VALUES (?, 'item', 'auctioneer-1', 'OPEN',
		        datetime('now','-1 hour'), datetime('now','+1 hour'))`, auctionID)
	if err != nil {
		t.Fatal("TC-DB-01: 사전 조건 설정 실패:", err)
	}
}

func insertClosedAuction(t *testing.T, db *sql.DB, auctionID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO auctions (id, item_name, created_by, status, start_at, end_at)
		VALUES (?, 'item', 'auctioneer-1', 'CLOSED',
		        datetime('now','-3 hour'), datetime('now','-1 hour'))`, auctionID)
	if err != nil {
		t.Fatal("TC-DB-02: 사전 조건 설정 실패:", err)
	}
}

func insertCommit(t *testing.T, db *sql.DB, auctionID, userID, hash string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO bids (id, auction_id, user_id, commit_hash, committed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"bid-"+auctionID+"-"+userID,
		auctionID, userID, hash,
		time.Now().UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatal("TC-DB-03: 사전 조건 설정 실패:", err)
	}
}

func insertReveal(t *testing.T, db *sql.DB, auctionID, userID, hash string, price int, salt string) {
	t.Helper()
	insertCommit(t, db, auctionID, userID, hash)
	_, err := db.Exec(`
		UPDATE bids SET revealed_price = ?, revealed_salt = ?, revealed_at = ?
		WHERE auction_id = ? AND user_id = ?`,
		price, salt, time.Now().UTC().Format(time.RFC3339),
		auctionID, userID,
	)
	if err != nil {
		t.Fatal("TC-DB-04: 사전 조건 설정 실패:", err)
	}
}

func assertErrCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error code %s, got nil", code)
	}
	ae, ok := err.(*appErrors.AppError)
	if !ok || ae.Code != code {
		t.Errorf("want %s, got %v", code, err)
	}
}

// ─────────────────────────────────────────────
//  CommitBid 테스트
// ─────────────────────────────────────────────

func TestCommitBid_Success(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertOpenAuction(t, db, "auction-c01")

	claims := bidderClaims("bidder-1", "buyer1")
	hash := bid.ComputeCommitHash("bidder-1", 10000, "salt-abc")
	if err := svc.CommitBid(claims, "auction-c01", hash); err != nil {
		t.Fatalf("TC-COMMIT-01: want nil, got %v", err)
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM bids WHERE auction_id='auction-c01' AND user_id='bidder-1'`).Scan(&count)
	if count != 1 {
		t.Errorf("TC-COMMIT-01: DB row count want 1, got %d", count)
	}
}

func TestCommitBid_AuctionClosed(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-c03")

	claims := bidderClaims("bidder-1", "buyer1")
	hash := bid.ComputeCommitHash("bidder-1", 5000, "salt")
	assertErrCode(t, svc.CommitBid(claims, "auction-c03", hash), "ERR_BID_001")
}

func TestCommitBid_DuplicateBid(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertOpenAuction(t, db, "auction-c04")

	claims := bidderClaims("bidder-1", "buyer1")
	hash := bid.ComputeCommitHash("bidder-1", 8000, "salt-dup")
	_ = svc.CommitBid(claims, "auction-c04", hash)

	assertErrCode(t, svc.CommitBid(claims, "auction-c04", hash), "ERR_BID_003")
}

func TestCommitBid_AuctionNotFound(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)

	claims := bidderClaims("bidder-1", "buyer1")
	hash := bid.ComputeCommitHash("bidder-1", 3000, "salt")
	assertErrCode(t, svc.CommitBid(claims, "no-such-auction", hash), "ERR_BID_001")
}

// ─────────────────────────────────────────────
//  RevealBid 테스트
// ─────────────────────────────────────────────

func TestRevealBid_Success(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-r01")

	price, salt := 15000, "mysalt"
	hash := bid.ComputeCommitHash("bidder-1", price, salt)
	insertCommit(t, db, "auction-r01", "bidder-1", hash)

	claims := bidderClaims("bidder-1", "buyer1")
	result, err := svc.RevealBid(claims, "auction-r01", price, salt)
	if err != nil {
		t.Fatalf("TC-REVEAL-01: want nil, got %v", err)
	}
	if result == nil || !result.IsValid {
		t.Error("TC-REVEAL-01: want IsValid=true")
	}

	var revealedPrice int
	db.QueryRow(`SELECT revealed_price FROM bids WHERE auction_id='auction-r01' AND user_id='bidder-1'`).Scan(&revealedPrice)
	if revealedPrice != price {
		t.Errorf("TC-REVEAL-01: revealed_price want %d, got %d", price, revealedPrice)
	}
}

func TestRevealBid_AuctionStillOpen(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertOpenAuction(t, db, "auction-r03")

	price, salt := 5000, "opensalt"
	hash := bid.ComputeCommitHash("bidder-1", price, salt)
	insertCommit(t, db, "auction-r03", "bidder-1", hash)

	claims := bidderClaims("bidder-1", "buyer1")
	_, err := svc.RevealBid(claims, "auction-r03", price, salt)
	assertErrCode(t, err, "ERR_BID_002")
}

func TestRevealBid_HashMismatch(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-r04")

	correctHash := bid.ComputeCommitHash("bidder-1", 20000, "correct-salt")
	insertCommit(t, db, "auction-r04", "bidder-1", correctHash)

	claims := bidderClaims("bidder-1", "buyer1")
	_, err := svc.RevealBid(claims, "auction-r04", 99999, "wrong-salt")
	assertErrCode(t, err, "ERR_VER_001")
}

func TestRevealBid_NoCommitFound(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-r05")

	claims := bidderClaims("bidder-1", "buyer1")
	_, err := svc.RevealBid(claims, "auction-r05", 5000, "salt")
	assertErrCode(t, err, "ERR_BID_001")
}

// ─────────────────────────────────────────────
//  VerifyBid 테스트
// ─────────────────────────────────────────────

func TestVerifyBid_SingleValidBid(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-v01")

	price, salt := 10000, "v-salt"
	hash := bid.ComputeCommitHash("bidder-1", price, salt)
	insertReveal(t, db, "auction-v01", "bidder-1", hash, price, salt)

	winner, err := svc.VerifyBid("auction-v01")
	if err != nil {
		t.Fatalf("TC-VERIFY-01: want nil, got %v", err)
	}
	if winner == nil {
		t.Fatal("TC-VERIFY-01: want winner, got nil")
	}
	if winner.UserID != "bidder-1" {
		t.Errorf("TC-VERIFY-01: winner want bidder-1, got %s", winner.UserID)
	}
}

func TestVerifyBid_InvalidHash(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-v02")

	correctHash := bid.ComputeCommitHash("bidder-1", 9999, "real-salt")
	insertReveal(t, db, "auction-v02", "bidder-1", correctHash, 1, "tampered-salt")

	winner, err := svc.VerifyBid("auction-v02")
	if err != nil {
		t.Fatalf("TC-VERIFY-02: want nil, got %v", err)
	}
	if winner != nil {
		t.Errorf("TC-VERIFY-02: want winner=nil, got %+v", winner)
	}
}

func TestVerifyBid_MultipleUsers_MixedValidity(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-v03")

	p1, s1 := 5000, "salt-valid"
	h1 := bid.ComputeCommitHash("bidder-1", p1, s1)
	insertReveal(t, db, "auction-v03", "bidder-1", h1, p1, s1)

	h2 := bid.ComputeCommitHash("bidder-2", 20000, "salt-real")
	insertReveal(t, db, "auction-v03", "bidder-2", h2, 1, "tampered")

	winner, err := svc.VerifyBid("auction-v03")
	if err != nil {
		t.Fatalf("TC-VERIFY-03: want nil, got %v", err)
	}
	if winner == nil || winner.UserID != "bidder-1" {
		t.Errorf("TC-VERIFY-03: want winner=bidder-1, got %v", winner)
	}
}

func TestVerifyBid_HighestPriceWins(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertClosedAuction(t, db, "auction-v04")

	p1, s1 := 5000, "salt1"
	h1 := bid.ComputeCommitHash("bidder-1", p1, s1)
	insertReveal(t, db, "auction-v04", "bidder-1", h1, p1, s1)

	p2, s2 := 15000, "salt2"
	h2 := bid.ComputeCommitHash("bidder-2", p2, s2)
	insertReveal(t, db, "auction-v04", "bidder-2", h2, p2, s2)

	winner, err := svc.VerifyBid("auction-v04")
	if err != nil {
		t.Fatalf("TC-VERIFY-04: want nil, got %v", err)
	}
	if winner == nil || winner.UserID != "bidder-2" {
		t.Errorf("TC-VERIFY-04: want winner=bidder-2, got %v", winner)
	}
	if winner.Price != p2 {
		t.Errorf("TC-VERIFY-04: price want %d, got %d", p2, winner.Price)
	}
}

func TestVerifyBid_AlreadyVerified(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)

	_, err := db.Exec(`
		INSERT INTO auctions (id, item_name, created_by, status, start_at, end_at)
		VALUES ('auction-v05', 'item', 'auctioneer-1', 'VERIFIED',
		        datetime('now','-3 hour'), datetime('now','-1 hour'))`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.VerifyBid("auction-v05")
	assertErrCode(t, err, "ERR_BID_001")
}

func TestVerifyBid_AuctionStillOpen(t *testing.T) {
	db := setupTestDB(t)
	svc := newBidSvc(db)
	insertOpenAuction(t, db, "auction-v06")

	_, err := svc.VerifyBid("auction-v06")
	assertErrCode(t, err, "ERR_BID_001")
}

// ─────────────────────────────────────────────
//  ComputeCommitHash 단위 테스트
// ─────────────────────────────────────────────

func TestComputeCommitHash_Deterministic(t *testing.T) {
	h1 := bid.ComputeCommitHash("user-1", 10000, "salt-abc")
	h2 := bid.ComputeCommitHash("user-1", 10000, "salt-abc")
	if h1 != h2 {
		t.Errorf("TC-HASH-01: not deterministic: %s vs %s", h1, h2)
	}
}

func TestComputeCommitHash_Length(t *testing.T) {
	h := bid.ComputeCommitHash("user-1", 10000, "salt-abc")
	if len(h) != 64 {
		t.Errorf("TC-HASH-02: want len=64, got %d", len(h))
	}
}

func TestComputeCommitHash_DifferentPrice(t *testing.T) {
	h1 := bid.ComputeCommitHash("user-1", 10000, "salt")
	h2 := bid.ComputeCommitHash("user-1", 10001, "salt")
	if h1 == h2 {
		t.Error("TC-HASH-03: different price must produce different hash")
	}
}

func TestComputeCommitHash_DifferentSalt(t *testing.T) {
	h1 := bid.ComputeCommitHash("user-1", 10000, "saltA")
	h2 := bid.ComputeCommitHash("user-1", 10000, "saltB")
	if h1 == h2 {
		t.Error("TC-HASH-04: different salt must produce different hash")
	}
}
