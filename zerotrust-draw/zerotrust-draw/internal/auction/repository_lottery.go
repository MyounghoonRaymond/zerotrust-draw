// Package auction - 검증 가능한 공정 추첨용 Repository 메서드.
// 기존 repository.go는 변경하지 않고 본 파일에서만 신규 컬럼/테이블 SQL을 다룹니다.
package auction

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"zerotrust-draw/internal/security"
	appErrors "zerotrust-draw/pkg/errors"
)

// LotteryDrawSnapshot은 공개 검증 페이지가 사용하는 라운드 스냅샷입니다.
type LotteryDrawSnapshot struct {
	AuctionID      string
	Status         string
	VrfPubkey      []byte
	CombinedSeed   string // hex
	VrfOutput      string // hex
	VrfProof       string // hex
	WinnerUserID   string
	DrawnAt        *time.Time
	WhitelistRoot  string // hex (머클 화이트리스트 root)
}

// ─────────────────────────────────────────────
//  VRF 키쌍 / 추첨 결과
// ─────────────────────────────────────────────

// SetVRFKeys는 라운드 생성 직후 VRF 키쌍을 라운드에 바인딩합니다.
// 라운드 ID와 함께 pubkey가 commit 되므로 운영자의 사후 키 grinding 차단.
func (r *Repository) SetVRFKeys(auctionID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	res, err := r.db.Exec(
		`UPDATE auctions SET vrf_pubkey = ?, vrf_privkey = ? WHERE id = ?`,
		[]byte(pub), []byte(priv), auctionID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 라운드입니다."}
	}
	return nil
}

// GetVRFKeys는 추첨 시점에 라운드의 VRF 키쌍을 가져옵니다.
// ⚠ v1: privkey 평문 저장. v2 권장: KEK 봉투 암호화 후 메모리 복호화만.
func (r *Repository) GetVRFKeys(auctionID string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var pub, priv []byte
	err := r.db.QueryRow(
		`SELECT vrf_pubkey, vrf_privkey FROM auctions WHERE id = ?`, auctionID,
	).Scan(&pub, &priv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 라운드입니다."}
	}
	if err != nil {
		return nil, nil, err
	}
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("vrf keys not initialized for this round")
	}
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

// SaveDrawResult는 추첨 결과(seed, vrf output/proof, winner)를 트랜잭션으로 저장하고
// status='VERIFIED' 로 전환합니다.
func (r *Repository) SaveDrawResult(auctionID, combinedSeedHex, vrfOutputHex, vrfProofHex, winnerUserID string, drawnAt time.Time) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`
		UPDATE auctions
		   SET combined_seed = ?, vrf_output = ?, vrf_proof = ?, winner_user_id = ?, drawn_at = ?
		 WHERE id = ?`,
		combinedSeedHex, vrfOutputHex, vrfProofHex, winnerUserID,
		drawnAt.UTC().Format(time.RFC3339), auctionID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE auctions SET status = 'VERIFIED' WHERE id = ?`, auctionID); err != nil {
		return err
	}
	return tx.Commit()
}

// GetLotteryDrawSnapshot은 검증 페이지 응답을 위한 라운드 스냅샷을 조회합니다.
func (r *Repository) GetLotteryDrawSnapshot(auctionID string) (*LotteryDrawSnapshot, error) {
	const q = `
		SELECT id, status, vrf_pubkey, combined_seed, vrf_output, vrf_proof,
		       winner_user_id, drawn_at, whitelist_root
		  FROM auctions
		 WHERE id = ?`
	var snap LotteryDrawSnapshot
	var pub []byte
	var seed, output, proof, winner, root sql.NullString
	var drawnAt sql.NullString
	err := r.db.QueryRow(q, auctionID).Scan(
		&snap.AuctionID, &snap.Status, &pub, &seed, &output, &proof, &winner, &drawnAt, &root,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 라운드입니다."}
	}
	if err != nil {
		return nil, err
	}
	snap.VrfPubkey = pub
	if seed.Valid {
		snap.CombinedSeed = seed.String
	}
	if output.Valid {
		snap.VrfOutput = output.String
	}
	if proof.Valid {
		snap.VrfProof = proof.String
	}
	if winner.Valid {
		snap.WinnerUserID = winner.String
	}
	if drawnAt.Valid {
		t, _ := time.Parse(time.RFC3339, drawnAt.String)
		snap.DrawnAt = &t
	}
	if root.Valid {
		snap.WhitelistRoot = root.String
	}
	return &snap, nil
}

// ─────────────────────────────────────────────
//  머클 화이트리스트 스냅샷 / 증명
// ─────────────────────────────────────────────

// FetchWhitelistEntries는 현재 whitelist 테이블 전체를 username 오름차순으로 가져옵니다.
// 라운드 생성 시점의 스냅샷을 만드는 입력으로 사용합니다.
func (r *Repository) FetchWhitelistEntries() ([]security.MerkleLeaf, error) {
	rows, err := r.db.Query(`SELECT username, role FROM whitelist ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []security.MerkleLeaf
	for rows.Next() {
		var u, role string
		if err := rows.Scan(&u, &role); err != nil {
			return nil, err
		}
		out = append(out, security.MerkleLeaf{Username: u, Role: role})
	}
	return out, rows.Err()
}

// CommitWhitelistSnapshot은 라운드의 whitelist_root 갱신과 whitelist_commitments 적재를
// 한 트랜잭션으로 묶어 부분 저장을 차단합니다.
func (r *Repository) CommitWhitelistSnapshot(auctionID, rootHex string, sortedLeaves []security.MerkleLeaf) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`UPDATE auctions SET whitelist_root = ? WHERE id = ?`, rootHex, auctionID); err != nil {
		return err
	}
	const ins = `
		INSERT INTO whitelist_commitments (auction_id, username, role, leaf_index)
		VALUES (?, ?, ?, ?)`
	for i, leaf := range sortedLeaves {
		if _, err := tx.Exec(ins, auctionID, leaf.Username, leaf.Role, i); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadWhitelistSnapshot은 라운드 시점에 봉인된 화이트리스트를 leaf_index 순으로 반환합니다.
// 증명 생성 / 검증 페이지 모두 이 결정적 순서를 그대로 사용해야 합니다.
func (r *Repository) LoadWhitelistSnapshot(auctionID string) ([]security.MerkleLeaf, error) {
	rows, err := r.db.Query(`
		SELECT username, role
		  FROM whitelist_commitments
		 WHERE auction_id = ?
		 ORDER BY leaf_index ASC`, auctionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []security.MerkleLeaf
	for rows.Next() {
		var u, role string
		if err := rows.Scan(&u, &role); err != nil {
			return nil, err
		}
		out = append(out, security.MerkleLeaf{Username: u, Role: role})
	}
	return out, rows.Err()
}

// FindWhitelistLeafIndex는 username 의 leaf_index 를 반환합니다(없으면 -1).
func (r *Repository) FindWhitelistLeafIndex(auctionID, username string) (int, error) {
	var idx int
	err := r.db.QueryRow(`
		SELECT leaf_index FROM whitelist_commitments
		 WHERE auction_id = ? AND username = ?`, auctionID, username,
	).Scan(&idx)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	return idx, nil
}
