-- ============================================================
-- ZeroTrust Draw
-- 통합 스키마 - 새 레포지토리용
--
-- 의미 매핑:
--   auctions  = 추첨 라운드
--   bids      = 참가자 nonce commit/reveal 기록
--   상태:      OPEN(commit 단계) → CLOSED(reveal 단계) → VERIFIED(추첨 완료)
-- ============================================================

-- 사용자
CREATE TABLE IF NOT EXISTS users (
    id              TEXT     PRIMARY KEY,
    username        TEXT     NOT NULL UNIQUE,
    password        TEXT     NOT NULL,             -- Argon2id 해시 hex
    salt            BLOB     NOT NULL,             -- crypto/rand 16바이트 이상
    role            TEXT     NOT NULL CHECK(role IN ('BIDDER', 'AUCTIONEER', 'ADMIN', 'GUEST')),
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME,
    last_failed_at  DATETIME
);

-- 세션 (HttpOnly 쿠키)
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT     PRIMARY KEY,
    user_id      TEXT     NOT NULL,
    expires_at   DATETIME NOT NULL,
    last_seen_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 추첨 라운드 (legacy 명칭: auctions)
-- VRF pubkey/privkey, 결합 시드, VRF output/proof, 화이트리스트 머클 root 까지 포함.
CREATE TABLE IF NOT EXISTS auctions (
    id               TEXT     PRIMARY KEY,
    item_name        TEXT     NOT NULL,
    created_by       TEXT     NOT NULL,
    status           TEXT     NOT NULL CHECK(status IN ('OPEN', 'CLOSED', 'VERIFIED')) DEFAULT 'OPEN',
    start_at         DATETIME NOT NULL,
    end_at           DATETIME NOT NULL,
    reveal_deadline  DATETIME,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- 검증 가능한 공정 추첨 컬럼 (라운드 생성 시 commit / 추첨 시 채워짐)
    vrf_pubkey       BLOB,                          -- 32B Ed25519 pubkey  (라운드 생성 시점 commit)
    vrf_privkey      BLOB,                          -- 64B Ed25519 privkey (⚠ v1: 평문, v2: KEK 봉투 암호화 권장)
    combined_seed    TEXT,                          -- hex(SHA-256(sorted nonces))
    vrf_output       TEXT,                          -- hex(SHA-512(proof || pubkey || seed))
    vrf_proof        TEXT,                          -- hex(Ed25519.Sign(privkey, seed))
    winner_user_id   TEXT,
    drawn_at         DATETIME,
    whitelist_root   TEXT,                          -- hex(SHA-256 머클 루트)

    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- 참가자 commit/reveal 기록
CREATE TABLE IF NOT EXISTS bids (
    id              TEXT     PRIMARY KEY,
    auction_id      TEXT     NOT NULL,
    user_id         TEXT     NOT NULL,
    commit_hash     TEXT     NOT NULL,             -- nonce commit: SHA-256(userID:nonce:salt)
    revealed_price  INTEGER,                        -- legacy 가격 (사용 안 함)
    revealed_salt   TEXT,                           -- reveal 단계의 salt
    is_valid        INTEGER,                        -- legacy: 1/0/NULL
    nonce_value     TEXT,                           -- reveal 단계의 평문 nonce (hex)
    committed_at    DATETIME NOT NULL,
    revealed_at     DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (auction_id) REFERENCES auctions(id),
    FOREIGN KEY (user_id)    REFERENCES users(id),
    UNIQUE(auction_id, user_id)
);

-- 화이트리스트 (등록된 username만 BIDDER/AUCTIONEER로 가입 가능)
CREATE TABLE IF NOT EXISTS whitelist (
    username   TEXT PRIMARY KEY,
    role       TEXT NOT NULL CHECK(role IN ('BIDDER', 'AUCTIONEER')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 라운드별 화이트리스트 머클 스냅샷 (사후 멤버십 증명용)
CREATE TABLE IF NOT EXISTS whitelist_commitments (
    auction_id  TEXT     NOT NULL,
    username    TEXT     NOT NULL,
    role        TEXT     NOT NULL,
    leaf_index  INTEGER  NOT NULL,                  -- 정렬된 리프 위치
    PRIMARY KEY (auction_id, username),
    FOREIGN KEY (auction_id) REFERENCES auctions(id)
);

-- 감사 로그 (DB 영구 보관 + JSON Lines stdout)
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL,
    level       TEXT     NOT NULL CHECK(level IN ('AUDIT', 'WARN', 'ERROR')),
    event       TEXT     NOT NULL,
    auction_id  TEXT,
    user_id     TEXT,
    request_id  TEXT,
    message     TEXT,
    error_code  TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_sessions_user_id        ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at     ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auctions_created_by     ON auctions(created_by);
CREATE INDEX IF NOT EXISTS idx_auctions_status         ON auctions(status);
CREATE INDEX IF NOT EXISTS idx_auctions_winner         ON auctions(winner_user_id);
CREATE INDEX IF NOT EXISTS idx_bids_auction_id         ON bids(auction_id);
CREATE INDEX IF NOT EXISTS idx_bids_user_id            ON bids(user_id);
CREATE INDEX IF NOT EXISTS idx_bids_committed_at       ON bids(committed_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event        ON audit_logs(event);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id      ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp    ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_wl_commit_round         ON whitelist_commitments(auction_id);
