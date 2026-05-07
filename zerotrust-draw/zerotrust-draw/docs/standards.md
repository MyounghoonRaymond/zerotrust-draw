# 협업 표준 및 규약

## 1. 세션 형식 (JWT → 세션 전환)

> ⚠️ JWT에서 서버 세션으로 전환되었습니다. JWT 관련 내용은 더 이상 유효하지 않습니다.

### 세션 발급 (A팀 담당)
- 로그인 성공 시 `crypto/rand` 16바이트 이상으로 `session_id`를 생성합니다.
- `sessions` 테이블에 `session_id`, `user_id`, `expires_at`을 저장합니다.
- 클라이언트에는 `session_id`만 쿠키(`HttpOnly; Secure; SameSite=Strict`)로 전달합니다.
- `user_id`, `role` 등 내부 정보는 절대 클라이언트에 노출하지 않습니다.

### 세션 검증 (`pkg/auth/interface.go` — C팀 인터페이스)
```go
ValidateSession(sessionID string) (*UserClaims, error)
```
- 세션 없음 / 만료 / 변조 모두 동일하게 `ErrSessionInvalid`를 반환합니다.
- 공격자가 세션 존재 여부를 유추할 수 없도록 에러를 구분하지 않습니다.

### `UserClaims` 구조체 매핑
- `UserID`   ← DB `sessions.user_id`
- `Username` ← DB `users.username`
- `Role`     ← DB `users.role` (`BIDDER` | `AUCTIONEER` | `ADMIN` | `GUEST`)

---

## 2. API 요청·응답 형식

### 성공 응답
```json
{
  "success": true,
  "data": { },
  "error": null,
  "meta": {
    "timestamp": "2024-07-04T12:00:00Z",
    "requestId": "req-uuid-v4"
  }
}
```

### 실패 응답
```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ERR_BID_001",
    "message": "요청을 처리할 수 없습니다."
  },
  "meta": {
    "timestamp": "...",
    "requestId": "..."
  }
}
```

> ⚠️ `error.detail` 필드는 제거되었습니다. 내부 원인은 서버 로그에만 기록합니다.

---

## 3. DB 컬럼명 규칙

### users 테이블 (A·B팀 소유)
- `id`, `username`, `password`, `salt`, `role`, `created_at`
- `last_login_at` (nullable) — A팀 로그인 성공 시 갱신
- `last_failed_at` (nullable) — A팀 로그인 실패 시 갱신

### sessions 테이블 (A팀 소유)
- `session_id`, `user_id`, `expires_at`, `created_at`

### auctions 테이블 (C팀 소유)
- `id`, `item_name`, `created_by`, `status`, `start_at`, `end_at`, `created_at`

### bids 테이블 (C·D팀 소유)
- `id`, `auction_id`, `user_id`, `commit_hash`, `revealed_price`, `revealed_salt`
- `is_valid`, `committed_at`, `revealed_at`, `created_at`

---

## 4. Role 권한 정의

| Role | 경매 생성 | 입찰 Commit/Reveal | 경매 조회 |
|------|-----------|-------------------|-----------|
| BIDDER | ✗ | ✓ | ✓ |
| AUCTIONEER | ✓ | ✗ | ✓ |
| ADMIN | ✓ | ✓ | ✓ |
| GUEST | ✗ | ✗ | ✓ |

> ⚠️ GUEST는 `HasRole(RoleBidder)` / `HasRole(RoleAuctioneer)` 체크에서 자동 차단됩니다.
> C팀 서비스 레이어에서 별도 GUEST 차단 로직을 추가할 필요가 없습니다.

---

## 5. 에러 코드

| 코드 | HTTP | 의미 | 클라이언트 노출 메시지 |
|------|------|------|----------------------|
| ERR_AUTH_001 | 401 | 세션 없음 또는 유효하지 않음 | 인증이 필요합니다. |
| ERR_AUTH_002 | 403 | 권한 부족 | 요청을 처리할 수 없습니다. |
| ERR_AUTH_003 | 401 | 세션 만료 또는 변조 | 인증이 필요합니다. |
| ERR_BID_001 | 400 | 입찰 기간 종료 | 요청을 처리할 수 없습니다. |
| ERR_BID_002 | 400 | 경매 종료 전 Reveal | 요청을 처리할 수 없습니다. |
| ERR_BID_003 | 409 | 이미 입찰함 | 요청을 처리할 수 없습니다. |
| ERR_BID_004 | 400 | 해시 형식 오류 | 요청을 처리할 수 없습니다. |
| ERR_VER_001 | 400 | 해시 불일치 | 요청을 처리할 수 없습니다. |
| ERR_VER_002 | 400 | 가격 형식 오류 | 요청을 처리할 수 없습니다. |
| ERR_RATE_001 | 429 | 요청 횟수 초과 | 잠시 후 다시 시도하세요. |
| ERR_SYS_001 | 500 | 내부 오류 | 요청을 처리할 수 없습니다. |

> ⚠️ 실패 원인의 상세 내용은 서버 로그에만 기록합니다.

---

## 6. 로그 이벤트

### 감사(AUDIT) 로그
| 이벤트 | 담당 | 설명 |
|--------|------|------|
| `SESSION_CREATED` | A팀 | 로그인 성공, 세션 발급 |
| `SESSION_DELETED` | A팀 | 로그아웃, 세션 삭제 |
| `AUCTION_CREATED` | C팀 | 경매 생성 완료 |
| `AUCTION_CLOSED`  | C팀 | 경매 마감 완료 |
| `BID_COMMITTED`   | C팀 | 입찰 커밋 성공 |
| `HASH_VERIFIED`   | C·D팀 | 해시 검증 성공 |
| `WINNER_SELECTED` | C팀 | 낙찰자 선정 완료 |

### 경고(WARN) 로그
| 이벤트 | 담당 | 설명 |
|--------|------|------|
| `SESSION_INVALID`  | A·C팀 | 세션 없음·만료·변조 (구분 없이 동일 이벤트) |
| `LOGIN_FAILED`     | A팀   | 로그인 실패 (`last_failed_at` 갱신 트리거) |
| `HASH_MISMATCH`    | C·D팀 | Reveal 해시 불일치 |
| `RATE_LIMIT_HIT`   | D팀   | 요청 횟수 초과 |

---

## 7. 협업 체크포인트

### Day 1 필수
- [x] 세션 방식 전환 합의 (JWT 폐기)
- [ ] `users` 테이블 `last_login_at`, `last_failed_at` 컬럼 확인 (A팀)
- [ ] `role` CHECK에 `GUEST` 추가 확인 (A팀 → D팀 스키마 반영)
- [ ] 에러 코드 목록 확정
- [ ] DB 스키마 커밋

### Day 2 필수
- [ ] `pkg/auth/interface.go` 커밋 (A·B팀에게 공유)
- [ ] `sessions` 테이블 생성 쿼리 확인 (D팀)
- [ ] MockAuthenticator (`NewMockGuest` 포함) 테스트

### 구현 완료 전
- [ ] `go test -race ./...` (Race Condition 없음)
- [ ] `go vet ./...` (경고 없음)
- [ ] `go fmt ./...` (포맷 통일)
- [ ] 모든 DB 쿼리 Prepared Statement 사용
- [ ] 에러 메시지에 내부 정보 노출 없음
- [ ] GUEST 역할 접근 차단 테스트

### 통합 테스트 (Day 8~10)
- [ ] MockAuthenticator → 실구현체 교체
- [ ] E2E 시나리오 테스트 (BIDDER / AUCTIONEER / GUEST 각각)
- [ ] OWASP 체크리스트 검토
