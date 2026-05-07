// create_admin은 최초 관리자(ADMIN) 계정을 생성하는 일회성 CLI 도구입니다.
//
// 사용법:
//
//	AUCTION_PEPPER=<pepper> DB_PATH=auction.db \
//	  go run ./cmd/create_admin \
//	    -username admin \
//	    -password <strong_password>
//
// 주의사항:
//   - 이 도구는 운영 초기화 용도로만 사용합니다.
//   - AUCTION_PEPPER 환경변수가 반드시 설정되어 있어야 합니다.
//   - 이미 같은 username이 존재하면 에러를 반환하고 종료합니다.
package main

import (
	"flag"
	"log"
	"os"

	"zerotrust-draw/internal/db"
	"zerotrust-draw/internal/security"
	"zerotrust-draw/pkg/models"
)

func main() {
	username := flag.String("username", "", "생성할 관리자 계정명 (필수)")
	password := flag.String("password", "", "관리자 비밀번호 (필수, 8자 이상 128자 이하)")
	flag.Parse()

	// ─── 필수 인수 검증 ───────────────────────────────────────────────────
	if *username == "" || *password == "" {
		flag.Usage()
		log.Fatal("[ERROR] -username 과 -password 는 필수입니다.")
	}

	if os.Getenv("AUCTION_PEPPER") == "" {
		log.Fatal("[ERROR] 환경변수 AUCTION_PEPPER 가 설정되지 않았습니다.")
	}

	if len(*password) < 8 || len(*password) > 128 {
		log.Fatal("[ERROR] 비밀번호는 8자 이상 128자 이하이어야 합니다.")
	}

	// ─── DB 초기화 ────────────────────────────────────────────────────────
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "auction.db"
	}

	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("[ERROR] DB 초기화 실패: %v", err)
	}
	defer database.Close()

	userStore := db.NewUserStore(database)

	// ─── 중복 확인 ────────────────────────────────────────────────────────
	existing, err := userStore.GetByUsername(*username)
	if err != nil {
		log.Fatalf("[ERROR] 사용자 조회 실패: %v", err)
	}
	if existing != nil {
		log.Fatalf("[ERROR] '%s' 계정이 이미 존재합니다. (역할: %s)", *username, existing.Role)
	}

	// ─── Argon2id 해싱 ────────────────────────────────────────────────────
	salt, err := security.GenerateSaltBytes(security.Argon2SaltLength)
	if err != nil {
		log.Fatalf("[ERROR] 솔트 생성 실패: %v", err)
	}
	hashedPassword := security.HashPassword(*password, salt)

	// ─── ADMIN 계정 생성 ──────────────────────────────────────────────────
	user, err := userStore.CreateUser(*username, hashedPassword, salt, models.RoleAdmin)
	if err != nil {
		log.Fatalf("[ERROR] 계정 생성 실패: %v", err)
	}

	log.Printf("[OK] ADMIN 계정 생성 완료 — ID: %s, Username: %s", user.ID, user.Username)
}
