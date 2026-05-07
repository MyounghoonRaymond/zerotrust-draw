# OWASP 보안 점검 체크리스트 — ZeroTrust Draw

전수 점검 결과 + 본 패치에서 적용한 항목을 OWASP Top 10 (2021) 기준으로 정리합니다.
표의 ✅ 는 적용 완료, ⚠ 는 v2 강화 권장, ❌ 는 미해결입니다.

## 한눈에 보기

| OWASP 항목 | 상태 | 비고 |
|---|---|---|
| A01 Broken Access Control | ✅ | RBAC + 미들웨어, GUEST 명시적 차단 |
| A02 Cryptographic Failures | ✅⚠ | Argon2id+Pepper, Ed25519 VRF; ⚠ vrf_privkey 평문 저장 |
| A03 Injection | ✅ | 전 SQL prepared, Content-Type 강제, JSON DisallowUnknownFields |
| A04 Insecure Design | ✅⚠ | commit-reveal, 다자간 베이컨, 머클 봉인; ⚠ KEK 미적용 |
| A05 Security Misconfiguration | ✅ | 보안 헤더 풀세트, X-Powered-By 차단, 쿠키 일관성 |
| A06 Vulnerable Components | ✅ | go.mod 최소 의존(go-sqlite3, uuid, argon2 등) |
| A07 Identification & Auth Failures | ✅ | 세션 + 더미 해싱 + 잠금 + jitter, 통일 에러 |
| A08 Software/Data Integrity | ✅ | 머클 화이트리스트 commit, VRF self-verify |
| A09 Logging & Monitoring | ✅ | JSON Lines + DB 이중 적재, audit 이벤트 표준화 |
| A10 SSRF | N/A | 외부 fetch 없음 |

## 본 패치에서 수정한 8가지

### 1. (CRITICAL) middleware.go 컴파일 깨짐
원본 `realIP` 함수에 `{ ... }` 리터럴 자리표시자가 남아있어 **빌드 자체가 실패**. 동시에 X-Forwarded-For 스푸핑 가능성도 제거.

```go
// 수정 후 핵심
if len(trustedProxies) == 0 {           // TRUSTED_PROXY 미설정 → XFF 무시
    return remoteHost
}
if _, trusted := trustedProxies[remoteHost]; !trusted {
    return remoteHost                     // 비신뢰 출처면 RemoteAddr 만 사용
}
// 신뢰 프록시 뒤일 때만 XFF 첫 항목(원 클라이언트) 사용
```

영향: A05 Security Misconfiguration (rate limit 우회 차단), A07 (계정 잠금 우회 차단).

### 2. (HIGH) JSON 바디에 잉여 필드 거부
모든 핸들러의 JSON 디코더에 `DisallowUnknownFields()` 적용.

```go
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()
if err := dec.Decode(&req); err != nil { ... }
```

영향: A03 Injection — Mass Assignment / 파라미터 오염(`{"role":"ADMIN", "username":"alice"}` 같은 권한 우회 시도) 차단.

### 3. (HIGH) 경로 파라미터 UUID 형식 강제
`/api/auctions/{id}/...` 와 `/api/lotteries/{id}/...` 의 ID 가 UUID v4 형식이 아니면 즉시 거부.

```go
auctionID := extractAuctionID(r.URL.Path)
if !IsValidID(auctionID) {
    response.Error(w, ..., reqID); return
}
```

영향: A03 Injection (이상 입력 차단), A09 Logging (제어문자/거대 입력으로 인한 로그 오염 차단).

### 4. (MEDIUM) 로그아웃 쿠키 속성 일치
원본은 발급 시 `Secure` 가 켜지는데 삭제 시 빠져 있어 일부 브라우저에서 쿠키 미삭제 가능. 단일 헬퍼로 통일.

```go
func sessionCookieAttrs(value string, expires time.Time, maxAge int) *http.Cookie {
    return &http.Cookie{
        Name: session.CookieName, Value: value, Expires: expires, MaxAge: maxAge,
        HttpOnly: true, Secure: isSecureCookie(),
        SameSite: http.SameSiteStrictMode, Path: "/",
    }
}
```

영향: A02/A07 — 세션 잔존으로 인한 재인증 우회 가능성 차단.

### 5. (MEDIUM) RevealBid 에러 코드 노출 최소화
가격 범위 검증 실패 시 `ErrInvalidPrice` (`ERR_VER_002`) 를 반환하면 **"가격 검증에서 실패함"** 이라는 사실이 코드로 노출. 일반 형식 에러로 통일.

```go
- response.Error(w, appErrors.ErrInvalidPrice, reqID)
+ response.Error(w, appErrors.ErrInvalidHashFmt, reqID)   // ERR_BID_004 통일
```

영향: A04 Insecure Design — 검증 실패 원인 추론 차단 (response.Error 메시지는 이미 "요청을 처리할 수 없습니다" 통일).

### 6. (MEDIUM) Server / X-Powered-By 헤더 차단
`SecurityHeaders` 미들웨어에 `Server: ""`, `X-Powered-By: ""` 명시.

영향: A05 — 서버 스택/버전 fingerprinting 차단.

### 7. (LOW) 회원가입 정책 메시지 통일
원본은 "비밀번호는 8자 이상이어야 합니다" 같은 정책 세부를 에러 메시지로 노출. 단일 "요청을 처리할 수 없습니다" 로 통일.

영향: A07 — 비밀번호 정책 추정 공격 어렵게.

### 8. (LOW) realIP IPv6 호환
`strings.LastIndex(":")` 으로 포트 자르던 부분이 IPv6 (`[::1]:8080`) 에서 깨졌음. `net.SplitHostPort` 로 교체.

영향: A05 — IPv6 환경에서 rate limit 키가 깨져 우회 가능했던 부분 차단.

## 카테고리별 상세 체크리스트

### A01 Broken Access Control

- [x] 모든 protected 엔드포인트가 `Auth` 미들웨어 통과 후에만 호출됨
- [x] `claims.HasRole(...)` 로 역할 검증, GUEST 는 명시적 경로에서만 통과
- [x] `DrawLottery` 핸들러에서 AUCTIONEER/ADMIN 만 호출 가능
- [x] AUCTIONEER 가 자기 라운드만이 아니라 전체 라운드를 마감/추첨할 수 있음 → 의도적 (단일 운영자 모델). 세분화하려면 `auctions.created_by == claims.UserID` 체크 추가
- [x] BIDDER 의 commit/reveal 은 자기 user_id 만 가능 (서비스 레이어에서 claims.UserID 강제)
- [x] 경로 ID 가 UUID 형식 강제

### A02 Cryptographic Failures

- [x] 비밀번호: Argon2id (운영 64MB / 3-iter / 2-parallel) + ServerPepper (env)
- [x] 솔트: 사용자별 16바이트 crypto/rand
- [x] 비교: `subtle.ConstantTimeCompare` (timing attack 방지)
- [x] 세션 ID: 32바이트 crypto/rand → 64-hex
- [x] HttpOnly + Secure (TLS) + SameSite=Strict 쿠키
- [x] HSTS 1년 + 보안 헤더 풀세트
- [x] VRF: Ed25519 (RFC 8032 결정적 서명) + SHA-512 hash → Sign-to-VRF
- [⚠] **vrf_privkey 가 DB 평문 저장** — KEK 봉투 암호화 또는 외부 KMS 권장 (v2)
- [⚠] **AUCTION_PEPPER 가 단일 비밀** — Shamir 분할 또는 KEK 도입 가능 (v2)

### A03 Injection

- [x] 전 SQL Prepared Statement (`?` placeholder), 동적 문자열 결합 0건
- [x] `Content-Type: application/json` 강제
- [x] JSON 디코더 `DisallowUnknownFields` (모든 핸들러 적용)
- [x] 입력 NFC 정규화 (`security.NormalizeInput`) — homoglyph 공격 차단
- [x] 비밀번호 길이 상한 128자 (Argon2 DoS 방지)
- [x] 입력 길이 상한: 바디 16KB, salt 8~64자, nonce 16~128자, hash 64자

### A04 Insecure Design

- [x] commit-reveal: 가격/nonce 비공개 보장
- [x] 다자간 베이컨: 단일 참가자 시드 조작 차단
- [x] VRF 의 pubkey/privkey 가 라운드 생성 시점에 commit → grinding 차단
- [x] 머클 화이트리스트 root 가 라운드 생성 시점에 commit → 명단 변조 차단
- [x] reveal 마감 시각(reveal_deadline) 으로 무한대 reveal 시도 차단
- [x] reveal 안 한 참가자 자동 제외 → last-revealer attack 무력화
- [x] VRF self-verify (서버 자체 일관성 검증) → 로직 버그 즉시 감지
- [x] 공개 검증 페이지 (`/verify`) — 누구나 결과 재계산 가능

### A05 Security Misconfiguration

- [x] X-Content-Type-Options: nosniff
- [x] X-Frame-Options: DENY
- [x] Strict-Transport-Security: max-age=31536000; includeSubDomains
- [x] Content-Security-Policy: default-src 'none' (API 서버용)
- [x] Cache-Control: no-store
- [x] Referrer-Policy: strict-origin-when-cross-origin
- [x] **Server / X-Powered-By 빈 값 강제 설정** (이번 패치)
- [x] DB foreign_keys=ON, journal_mode=WAL
- [x] AUCTION_PEPPER 미설정 시 즉시 fail-fast (서버 시작 거부)
- [x] TLS 미설정 시 [WARN] 로그 출력

### A06 Vulnerable and Outdated Components

- [x] 직접 의존 최소화 (sqlite3, uuid, argon2, unicode/norm)
- [ ] **`go list -m -u all` 정기 실행 + Dependabot 권장** (CI 통합)

### A07 Identification and Authentication Failures

- [x] 로그인 실패 원인 구분 없이 단일 응답 (사용자 존재 여부 / 잠금 여부 모두 숨김)
- [x] 사용자 미존재 시에도 더미 Argon2 해싱 (timing attack 방지)
- [x] 3회 실패 → 30분±jitter 잠금
- [x] 세션 만료 즉시 삭제 (`Get` 호출 시 만료 검출 + DELETE)
- [x] 세션 ID HttpOnly 쿠키, 응답 바디에 ID 포함 안 함
- [x] 로그아웃 시 DB 세션 삭제 + 쿠키 즉시 만료 (속성 일관)
- [x] 회원가입 정책 메시지 노출 차단 (이번 패치)

### A08 Software and Data Integrity Failures

- [x] schema.sql 멱등성 (CREATE TABLE IF NOT EXISTS)
- [x] 추첨 결과 저장은 트랜잭션 (combined_seed/output/proof/winner + status='VERIFIED' 한 번에)
- [x] 화이트리스트 스냅샷 저장도 트랜잭션
- [x] VRF self-verify (output mismatch 시 추첨 거부)
- [x] 머클 root 가 변조되면 `/whitelist-proof` 의 `verified: false` 로 즉시 발각
- [x] 공개 검증 페이지에서 winnerMatch / vrfProofValid / seedRecomputeMatch 모두 true 인지 외부 검증 가능

### A09 Security Logging and Monitoring Failures

- [x] JSON Lines stdout + DB 이중 적재 (`audit_logs`)
- [x] AUDIT/WARN/ERROR 3단계 + error_code 표준화
- [x] 로그인 성공/실패, 잠금, 세션 무효, rate limit, 추첨 모든 단계 audit
- [x] 클라이언트 응답에는 내부 에러 메시지 비노출 (`Internal` 필드는 로그 전용)

### A10 Server-Side Request Forgery

- N/A — 본 시스템은 외부 URL 을 fetch 하지 않음

## API 추가 권장 (v2)

이번 v1 범위 밖이지만 발표 슬라이드 "추후 강화" 부분에 넣으면 좋은 항목:

- **KEK 봉투 암호화**: vrf_privkey, AUCTION_PEPPER 를 KEK 로 wrap → 키 회전 시 데이터 재암호화 불필요
- **`__Host-` 쿠키 prefix**: 더 강력한 쿠키 격리 (Path=/ 강제 + Domain 금지 + Secure 강제)
- **MFA / WebAuthn**: 비밀번호 자체를 서버가 못 보게 (OPAQUE PAKE 또는 패스키)
- **SBOM 생성 + Dependabot**: A06 대응 자동화
- **secure_delete PRAGMA**: 삭제 데이터 잔여 차단
- **DB 파일 권한 0600 강제**: 기동 시 chmod 검증

## 발표용 한 줄

> "OWASP Top 10 9개 카테고리에 대해 적용된 통제를 갖추고, 발표 시연으로 인증/세션/추첨 결과 변조를 모두 즉시 발각시킬 수 있다."
