package handler

import (
	"net/http"

	authhandler "zerotrust-draw/internal/auth"
	"zerotrust-draw/internal/middleware"
)

// RegisterRoutes는 모든 API 라우트를 등록합니다.
//
// 인증 불필요 (Public):
//
//	POST /api/auth/signup                          (IP rate limit)
//	POST /api/auth/login                           (IP rate limit)
//	POST /api/auth/logout                          (IP rate limit)
//	GET  /api/auctions                             (legacy 경매 목록)
//	GET  /api/auctions/{id}                        (legacy 경매 상세)
//	GET  /api/auctions/{id}/result                 (legacy 결과)
//	GET  /api/lotteries/{id}/verify                (공개 검증 페이지)
//	GET  /api/lotteries/{id}/whitelist-proof       (멤버십 증명)
//
// 인증 필요 (Protected):
//
//	GET  /api/auth/me
//	POST /api/auctions                             (legacy 경매 생성)
//	POST /api/auctions/{id}/bids                   (legacy 입찰)
//	POST /api/auctions/{id}/reveal                 (legacy 공개)
//	POST /api/auctions/{id}/close                  (legacy 마감)
//	POST /api/lotteries                            (라운드 생성, AUCTIONEER)
//	POST /api/lotteries/{id}/commit                (BIDDER)
//	POST /api/lotteries/{id}/reveal                (BIDDER)
//	POST /api/lotteries/{id}/draw                  (AUCTIONEER/ADMIN)
func RegisterRoutes(
	mux *http.ServeMux,
	auth *authhandler.Handler,
	ah *AuctionHandler,
	bh *BidHandler,
	lh *LotteryHandler,
	authMW func(http.Handler) http.Handler,
	rl *middleware.RateLimiter,
) {
	// 전역 미들웨어: 보안 헤더 + 바디 크기 제한 + Content-Type 검증
	global := func(h http.Handler) http.Handler {
		return middleware.SecurityHeaders(middleware.LimitBody(middleware.RequireJSON(h)))
	}
	protected := func(h http.Handler) http.Handler {
		return global(authMW(rl.Limit(h)))
	}
	public := func(h http.Handler) http.Handler {
		return global(rl.LimitByIP(h))
	}

	// ─── 인증 라우트 ─────────────────────────────────────────────────────────
	mux.Handle("/api/auth/signup", public(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			auth.Signup(w, r)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})))
	mux.Handle("/api/auth/login", public(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			auth.Login(w, r)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})))
	mux.Handle("/api/auth/logout", public(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			auth.Logout(w, r)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})))
	mux.Handle("/api/auth/me", protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			auth.Me(w, r)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})))

	// ─── [LEGACY] 경매 라우트 ───────────────────────────────────────────────
	mux.Handle("/api/auctions", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			public(http.HandlerFunc(ah.ListAuctions)).ServeHTTP(w, r)
		case http.MethodPost:
			protected(http.HandlerFunc(ah.CreateAuction)).ServeHTTP(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.Handle("/api/auctions/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case hasSuffix(path, "/result") && r.Method == http.MethodGet:
			public(http.HandlerFunc(ah.GetAuctionResult)).ServeHTTP(w, r)
		case hasSuffix(path, "/close") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(ah.CloseAuction)).ServeHTTP(w, r)
		case hasSuffix(path, "/bids") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(bh.CommitBid)).ServeHTTP(w, r)
		case hasSuffix(path, "/reveal") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(bh.RevealBid)).ServeHTTP(w, r)
		case r.Method == http.MethodGet:
			public(http.HandlerFunc(ah.GetAuction)).ServeHTTP(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	// ─── 추첨(Lottery) 라우트 ────────────────────────────────────────────────
	mux.Handle("/api/lotteries", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			protected(http.HandlerFunc(lh.CreateLotteryRound)).ServeHTTP(w, r)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))
	mux.Handle("/api/lotteries/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		// GET 공개 검증 / 멤버십 증명
		case hasSuffix(path, "/verify") && r.Method == http.MethodGet:
			public(http.HandlerFunc(lh.VerifyLottery)).ServeHTTP(w, r)
		case hasSuffix(path, "/whitelist-proof") && r.Method == http.MethodGet:
			public(http.HandlerFunc(lh.WhitelistProof)).ServeHTTP(w, r)
		// POST 보호 엔드포인트
		case hasSuffix(path, "/commit") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(lh.CommitNonce)).ServeHTTP(w, r)
		case hasSuffix(path, "/reveal") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(lh.RevealNonce)).ServeHTTP(w, r)
		case hasSuffix(path, "/draw") && r.Method == http.MethodPost:
			protected(http.HandlerFunc(lh.DrawLottery)).ServeHTTP(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
}

// hasSuffix는 경로 접미사 검사용 헬퍼입니다 (strings 패키지 미사용).
func hasSuffix(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}
