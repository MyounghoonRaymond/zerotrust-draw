# ZeroTrust Draw

Go 기반의 **공개 검증 가능한 공정 추첨 시스템 (ZeroTrust Draw)**. 운영자도, 참가자 누구도 결과를 단독으로 조작할 수 없으며, 누구나 외부에서 결과를 재계산해 정직성을 검증할 수 있습니다.

## 보안 핵심

| 보안 속성 | 적용 기술 |
|---|---|
| 운영자 키 grinding 차단 | 라운드 생성 시점에 VRF pubkey commit (Ed25519) |
| 명단 사후 변조 차단 | 라운드 생성 시점에 화이트리스트 머클 root commit (SHA-256) |
| 단일 참가자의 시드 조작 차단 | 다자간 베이컨 (commit-reveal nonce) |
| 운영자의 결과 사후 조작 차단 | Sign-to-VRF (RFC 8032 결정적 서명 + SHA-512) |
| Last-revealer attack 차단 | reveal 안 한 참가자는 추첨 풀 자동 제외 |
| 공개 검증 가능성 | `/verify` 엔드포인트로 누구나 재계산 |
| 변조방지 인증 자산 | Argon2id + Server Pepper, HttpOnly 세션 |

## 프로젝트 구조

```
cmd/auction/main.go                      # 진입점
db/schema.sql                            # 통합 스키마 (자동 실행)
internal/
  auction/
    repository.go                        # 라운드 기본 SQL
    repository_lottery.go                # VRF/머클/추첨 결과 SQL
    service.go                           # CreateAuction, ListAuctions...
    draw.go                              # LotteryDrawer (라운드 생성/추첨/검증/멤버십 증명)
    scan.go
  bid/
    repository.go                        # bids 기본 SQL
    repository_lottery.go                # nonce reveal SQL
    service.go                           # (legacy 가격 기반 commit-reveal — 호환 유지)
    service_lottery.go                   # CommitNonce / RevealNonce
  security/
    crypto.go                            # Argon2id + Pepper
    config.go validation.go
    vrf.go                               # Sign-to-VRF + 다자간 베이컨
    merkle.go                            # 머클 화이트리스트
  handler/
    auction_handler.go bid_handler.go    # legacy
    lottery_handler.go                   # 추첨 엔드포인트
    router.go                            # 라우트 등록
  auth/, db/, log/, middleware/          # 기존 자산 그대로
pkg/
  auth/, errors/, models/, response/, session/
tests/
  integration/flow_test.go
```

## API

### 인증 불필요 (Public)

```
GET  /api/lotteries/{id}/verify                       — 공개 검증 페이지 (재계산 결과 포함)
GET  /api/lotteries/{id}/whitelist-proof?username=X   — 머클 멤버십 증명
```

### 인증 필요 (Protected)

```
POST /api/lotteries                                   — 라운드 생성 (AUCTIONEER)
                                                        VRF pubkey commit + 화이트리스트 머클 root commit 동시 실행
POST /api/lotteries/{id}/commit                       — nonce commit (BIDDER)
                                                        body: { "commitHash": "<SHA-256(userID:nonce:salt) hex>" }
POST /api/lotteries/{id}/reveal                       — nonce reveal (BIDDER)
                                                        body: { "nonce": "<hex>", "salt": "<8~64자>" }
POST /api/lotteries/{id}/draw                         — 추첨 실행 (AUCTIONEER/ADMIN)
```

레거시(블라인드 경매) 엔드포인트는 그대로 살아있습니다 (`/api/auctions/...`).

## 동작 흐름

```
[1] AUCTIONEER 라운드 생성
    POST /api/lotteries
    → 서버: Ed25519 VRF 키쌍 생성 → pubkey/privkey 라운드에 commit
    → 서버: 현재 whitelist 스냅샷 → 머클 root 라운드에 commit
    → 의의: 사후 키 grinding/명단 변조 모두 root/pubkey 불일치로 발각

[2] 참가자들이 nonce commit (status=OPEN)
    POST /api/lotteries/{id}/commit
    body: { commitHash: SHA-256(userID:nonce:salt) }

[3] 라운드 마감 (status=CLOSED, 자동/수동)

[4] 참가자들이 nonce reveal
    POST /api/lotteries/{id}/reveal
    → reveal 안 하면 추첨 풀에서 자동 제외 (last-revealer attack 무력화)

[5] AUCTIONEER 추첨 실행
    POST /api/lotteries/{id}/draw
    → seed   = SHA-256(sorted(userID,nonce) 결합)        ← 다자간 베이컨
    → proof  = Ed25519.Sign(privkey, seed)                ← Sign-to-VRF (RFC 8032)
    → output = SHA-512(proof || pubkey || seed)
    → idx    = uint64(output[:8]) mod N
    → 결과 + proof 트랜잭션 저장, status=VERIFIED

[6] 누구나 공개 검증
    GET /api/lotteries/{id}/verify
    → 모든 (참가자, nonce, pubkey, proof, root) 노출
    → 클라이언트가 재계산해서 winnerMatch / vrfProofValid / seedRecomputeMatch 모두 true 인지 확인

[7] 멤버십 증명 (사후)
    GET /api/lotteries/{id}/whitelist-proof?username=alice
    → leafHash + Merkle proof + root 반환
    → 라운드 종료 후에도 "내가 명단에 있었다" 검증 가능
```

## 발표 시연 시나리오

### 시연 1: "운영자가 결과를 조작하려고 한다"
1. 추첨 완료 후 `auctions.winner_user_id` 를 직접 UPDATE 로 변경
2. `/verify` 호출 → `winnerMatch: false`, 운영자 변조가 즉시 발각

### 시연 2: "악성 참가자가 마지막에 reveal 안 해서 결과를 비틀려 한다"
1. 참가자 A 가 reveal 안 함
2. A 는 추첨 풀에서 자동 제외 → 결과 모니터링으로 자기 유리하게 만들 방법 없음

### 시연 3: "운영자가 유리한 VRF 키로 grinding 하려 한다"
1. 라운드 생성 시점에 pubkey 가 DB 에 박힘
2. 참가자 nonce 가 그 후에 commit 되므로 grinding 불가

### 시연 4: "운영자가 명단을 사후 변조하려 한다"
1. `whitelist` 테이블에 가짜 사용자 INSERT
2. `/whitelist-proof?username=가짜` → `verified: false`, root 불일치로 발각

## 설치 및 실행

```bash
# 1) Go 1.22.x 이상
go version

# 2) 환경변수
export AUCTION_PEPPER="<32자 이상의 랜덤 문자열>"   # 필수
export DB_PATH="auction.db"                         # 선택
export ADDR=":8080"                                 # 선택

# 3) 의존성
go mod download && go mod tidy

# 4) 실행
go run cmd/auction/main.go

# 5) 테스트
go test -race ./...
```

## v1 알려진 한계 (발표용 솔직 보고)

- `vrf_privkey` 가 DB 에 평문 저장 → KEK 봉투 암호화 또는 외부 KMS 로 강화 가능
- VRF 가 RFC 9381 ECVRF 가 아니라 Sign-to-VRF 구조 → 표준 라이브러리 도입 시 ECVRF 로 교체 권장
- 운영자가 다수 sybil 참가자를 동원하면 시드 편향 가능 → 머클 화이트리스트 + 본인 확인 강화 필요

## 라이선스 / 출처

본 코드의 인증/감사로그/세션 등 기반 인프라는 블라인드 경매 프로젝트의 자산을 그대로 재사용합니다.
"ZeroTrust Draw"의 핵심 보안 프리미티브 (`internal/security/vrf.go`, `internal/security/merkle.go`,
`internal/auction/draw.go`, `internal/auction/repository_lottery.go`, `internal/bid/service_lottery.go`,
`internal/bid/repository_lottery.go`, `internal/handler/lottery_handler.go`) 가 본 프로젝트 추가 부분입니다.
