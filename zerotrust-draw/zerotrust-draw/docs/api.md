# API 명세서

## 기본 정보
- Base URL: `http://localhost:8080/api`
- 인증: HTTP `Authorization: Bearer <token>` 헤더
- 응답 형식: JSON

## 엔드포인트

### 1. 경매 생성
```
POST /auctions
```

**요청**
```json
{
  "itemName": "노트북",
  "startAt": "2024-07-04T12:00:00Z",
  "endAt": "2024-07-04T14:00:00Z"
}
```

**응답 (201)**
```json
{
  "success": true,
  "data": {
    "id": "auction-uuid",
    "itemName": "노트북",
    "status": "OPEN",
    "startAt": "2024-07-04T12:00:00Z",
    "endAt": "2024-07-04T14:00:00Z"
  },
  "meta": { "timestamp": "...", "requestId": "..." }
}
```

**에러 (403)**
- ERR_AUTH_002: AUCTIONEER 권한 없음

---

### 2. 입찰 (Commit)
```
POST /auctions/:auctionId/bids
```

**요청**
```json
{
  "commitHash": "a1b2c3...d4e5f6" // 64자리 hex (SHA-256)
}
```

**응답 (201)**
```json
{
  "success": true,
  "data": {
    "bidId": "bid-uuid",
    "auctionId": "auction-uuid",
    "committedAt": "2024-07-04T12:30:00Z"
  },
  "meta": { "timestamp": "...", "requestId": "..." }
}
```

**에러**
- 400 ERR_BID_001: 입찰 기간 종료
- 400 ERR_BID_003: 이미 입찰함
- 400 ERR_BID_004: 해시 형식 오류
- 429 ERR_RATE_001: 요청 횟수 초과

---

### 3. 입찰 공개 (Reveal)
```
POST /auctions/:auctionId/reveal
```

**요청**
```json
{
  "price": 50000,
  "salt": "b2c3d4...e5f6a7" // 32자리 이상 hex
}
```

**응답 (200)**
```json
{
  "success": true,
  "data": {
    "bidId": "bid-uuid",
    "isValid": true,
    "revealedAt": "2024-07-04T13:45:00Z"
  },
  "meta": { "timestamp": "...", "requestId": "..." }
}
```

**에러**
- 400 ERR_BID_002: 경매 미마감
- 400 ERR_VER_001: 해시 불일치
- 400 ERR_VER_002: 가격 형식 오류

---

### 4. 낙찰 결과 조회
```
GET /auctions/:auctionId/result
```

**응답 (200)**
```json
{
  "success": true,
  "data": {
    "auctionId": "auction-uuid",
    "status": "VERIFIED",
    "winnerId": "user-uuid",
    "winnerUsername": "홍길동",
    "winnerPrice": 50000,
    "bids": [
      {
        "bidId": "bid-uuid",
        "userId": "user-uuid",
        "isValid": true,
        "price": 50000
      }
    ]
  },
  "meta": { "timestamp": "...", "requestId": "..." }
}
```

---

## 인증 헤더
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 요청 ID
모든 응답에는 `meta.requestId`가 포함되어 로그 추적을 위해 사용합니다.
