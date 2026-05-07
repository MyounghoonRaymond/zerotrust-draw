// ZeroTrust Draw - 서버 진입점.
// 라운드 생성 시 VRF pubkey + 화이트리스트 머클 root 동시 commit, 다자간 베이컨 + Sign-to-VRF 추첨.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"zerotrust-draw/internal/auction"
	internalauth "zerotrust-draw/internal/auth"
	"zerotrust-draw/internal/bid"
	"zerotrust-draw/internal/db"
	"zerotrust-draw/internal/handler"
	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/internal/middleware"
	pkgauth "zerotrust-draw/pkg/auth"
)

func main() {
	// ─── 환경변수 ────────────────────────────────────────────────────────────
	if os.Getenv("AUCTION_PEPPER") == "" {
		log.Fatal("[ERROR] 환경변수 AUCTION_PEPPER 가 설정되지 않았습니다. 서버를 시작할 수 없습니다.")
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "auction.db"
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	useTLS := tlsCertFile != "" && tlsKeyFile != ""

	// ─── DB 초기화 (schema.sql 자동 실행) ───────────────────────────────────
	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Printf("[ERROR] DB 초기화 실패: %v", err)
		log.Fatal("서버를 시작할 수 없습니다.")
	}
	defer database.Close()

	// ─── 감사 로그 DB 연동 ───────────────────────────────────────────────────
	applog.SetDB(database)

	// ─── 저장소 ──────────────────────────────────────────────────────────────
	userStore := db.NewUserStore(database)
	sessionStore := db.NewSessionStore(database)
	whitelistStore := db.NewWhitelistStore(database)

	// ─── 만료 세션 주기적 정리 ──────────────────────────────────────────────
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = sessionStore.DeleteExpired()
		}
	}()

	// ─── 인증 ────────────────────────────────────────────────────────────────
	authSvc := internalauth.NewService(userStore, sessionStore, whitelistStore)
	authHandler := internalauth.NewHandler(authSvc)
	sessionAuthenticator := internalauth.NewSessionAuthenticator(sessionStore)
	var authenticator pkgauth.Authenticator = sessionAuthenticator

	// ─── 추첨 라운드 / 입찰 서비스 ──────────────────────────────────────────
	auctionRepo := auction.NewRepository(database)
	auctionSvc := auction.NewService(auctionRepo)
	bidRepo := bid.NewRepository(database)
	bidSvc := bid.NewService(bidRepo)

	// ─── 추첨 자동화 (라운드 마감 자동 CLOSE) ────────────────────────────────
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			if n, err := auctionRepo.CloseExpiredAuctions(); err != nil {
				log.Printf("[WARN] 라운드 자동 마감 실패: %v", err)
			} else if n > 0 {
				log.Printf("[INFO] 라운드 자동 마감: %d건 CLOSED", n)
			}
		}
	}()

	// ─── 핸들러 ──────────────────────────────────────────────────────────────
	auctionH := handler.NewAuctionHandler(auctionSvc)
	bidH := handler.NewBidHandler(bidSvc)
	drawer := auction.NewLotteryDrawer(auctionRepo, bidRepo)
	lotteryH := handler.NewLotteryHandler(auctionSvc, bidSvc, drawer)

	// ─── 미들웨어 ────────────────────────────────────────────────────────────
	authMW := middleware.Auth(authenticator)
	rateLimiter := middleware.NewRateLimiter(10, time.Minute)

	// ─── 라우터 ──────────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux, authHandler, auctionH, bidH, lotteryH, authMW, rateLimiter)

	// ─── 서버 시작 ───────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if useTLS {
		log.Printf("[INFO] 서버 시작 (HTTPS): https://localhost%s", addr)
		if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
			log.Fatalf("[ERROR] 서버 종료: %v", err)
		}
	} else {
		log.Printf("[INFO] 서버 시작 (HTTP — 운영 환경에서는 TLS_CERT_FILE/TLS_KEY_FILE을 설정하세요): http://localhost%s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("[ERROR] 서버 종료: %v", err)
		}
	}
}
