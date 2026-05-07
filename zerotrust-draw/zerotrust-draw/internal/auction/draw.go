// Package auction - 검증 가능한 공정 추첨(Verifiable Fair Lottery) 핵심 흐름.
//
// LotteryDrawer는 다음 4축을 결합한 단일 진입점입니다.
//
//	1) 라운드 생성 시 VRF pubkey commit  → 운영자의 키 grinding 차단
//	2) 라운드 생성 시 화이트리스트 머클 봉인 → 명단 사후 변조 차단
//	3) 다자간 베이컨(commit-reveal nonce)   → 단일 참가자 시드 조작 차단
//	4) Sign-to-VRF (Ed25519 결정적 서명)    → 운영자도 결과 사후 조작 차단
package auction

import (
	"encoding/hex"
	"sort"
	"time"

	"zerotrust-draw/internal/bid"
	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/internal/security"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"
)

// LotteryDrawer는 라운드 생성 / 추첨 / 검증을 담당합니다.
type LotteryDrawer struct {
	auctionRepo *Repository
	bidRepo     *bid.Repository
}

// NewLotteryDrawer는 LotteryDrawer를 생성합니다.
func NewLotteryDrawer(auctionRepo *Repository, bidRepo *bid.Repository) *LotteryDrawer {
	return &LotteryDrawer{auctionRepo: auctionRepo, bidRepo: bidRepo}
}

// ─────────────────────────────────────────────
//  1. 라운드 생성 (VRF pubkey + 화이트리스트 머클 commit)
// ─────────────────────────────────────────────

// CreateLotteryRound는 라운드를 생성하고 VRF pubkey + 화이트리스트 머클 root를
// 라운드 ID에 함께 묶습니다. 두 commit이 라운드 시작 시점에 박히므로
// 운영자의 사후 조작(키 갈아끼우기, 명단 변조)은 모두 root/pubkey 불일치로 발각됩니다.
//
// AUCTIONEER 권한만 호출 가능합니다(svc.CreateAuction 권한 검증을 그대로 위임).
func (d *LotteryDrawer) CreateLotteryRound(svc *Service, claims *auth.UserClaims, input CreateAuctionInput) (*models.Auction, error) {
	ac, err := svc.CreateAuction(claims, input)
	if err != nil {
		return nil, err
	}

	// 1) VRF 키쌍 생성 + pubkey commit
	kp, err := security.GenerateVRFKey()
	if err != nil {
		applog.Error("VRF_KEYGEN_FAIL", ac.ID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	if err := d.auctionRepo.SetVRFKeys(ac.ID, kp.Public, kp.Private); err != nil {
		applog.Error("VRF_KEY_BIND_FAIL", ac.ID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	applog.Audit("LOTTERY_VRF_PUBKEY_COMMITTED", ac.ID, claims.UserID, "", "VRF pubkey commit 완료")

	// 2) 화이트리스트 스냅샷 + 머클 root commit
	leaves, err := d.auctionRepo.FetchWhitelistEntries()
	if err != nil {
		applog.Error("WHITELIST_FETCH_FAIL", ac.ID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	rootHex, _, sortedLeaves := security.BuildMerkleRoot(leaves)
	if err := d.auctionRepo.CommitWhitelistSnapshot(ac.ID, rootHex, sortedLeaves); err != nil {
		applog.Error("WHITELIST_COMMIT_FAIL", ac.ID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	applog.Audit("LOTTERY_WHITELIST_COMMITTED", ac.ID, claims.UserID, "", "화이트리스트 머클 root commit 완료")

	return ac, nil
}

// ─────────────────────────────────────────────
//  2. 다자간 베이컨 + VRF 추첨 실행
// ─────────────────────────────────────────────

// WinnerInfo는 추첨 결과 요약입니다.
type WinnerInfo struct {
	BidID            string    `json:"bidId"`
	UserID           string    `json:"userId"`
	CombinedSeedHex  string    `json:"combinedSeedHex"`
	VRFOutputHex     string    `json:"vrfOutputHex"`
	VRFProofHex      string    `json:"vrfProofHex"`
	ParticipantsHash string    `json:"participantsHash"`
	WhitelistRoot    string    `json:"whitelistRoot"`
	DrawnAt          time.Time `json:"drawnAt"`
}

// DrawLottery는 status=CLOSED 라운드의 reveal된 nonce들을 결합하여
// VRF로 결정적·검증 가능한 추첨 결과를 산출합니다.
//
//	- reveal 안 한 참가자는 추첨 풀에서 자동 제외(last-revealer attack 무력화)
//	- 결과는 트랜잭션으로 한 번에 저장 + status='VERIFIED' 전환
func (d *LotteryDrawer) DrawLottery(auctionID string) (*WinnerInfo, error) {
	status, err := d.bidRepo.FindAuctionStatus(auctionID)
	if err != nil {
		return nil, err
	}
	if status != "CLOSED" {
		applog.Warn("DRAW_INVALID_STATUS", auctionID, "", "", "CLOSED 아닌 라운드 추첨 시도", "ERR_BID_001")
		return nil, appErrors.ErrBidPeriodClosed
	}

	reveals, err := d.bidRepo.FindRevealedNonces(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if len(reveals) == 0 {
		applog.Audit("NO_PARTICIPANTS", auctionID, "", "", "reveal된 참가자 없음")
		_ = d.auctionRepo.SaveDrawResult(auctionID, "", "", "", "", time.Now().UTC())
		return nil, nil
	}

	contribs := make([]security.NonceContribution, 0, len(reveals))
	for _, r := range reveals {
		contribs = append(contribs, security.NonceContribution{UserID: r.UserID, Nonce: r.NonceValue})
	}
	seed := security.CombineNonces(contribs)

	pub, priv, err := d.auctionRepo.GetVRFKeys(auctionID)
	if err != nil {
		applog.Error("DRAW_VRF_KEY_LOAD_FAIL", auctionID, "", "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	output, proof, err := security.VRFEvaluate(priv, seed)
	if err != nil {
		applog.Error("DRAW_VRF_EVAL_FAIL", auctionID, "", "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	if rebuilt, ok := security.VRFVerify(pub, seed, proof); !ok || hex.EncodeToString(rebuilt) != hex.EncodeToString(output) {
		applog.Error("DRAW_VRF_SELF_VERIFY_FAIL", auctionID, "", "", "VRF self-verify mismatch", "ERR_VER_001")
		return nil, appErrors.ErrSystemError
	}

	sortedParticipants := make([]string, 0, len(reveals))
	for _, r := range reveals {
		sortedParticipants = append(sortedParticipants, r.UserID)
	}
	sort.Strings(sortedParticipants)
	idx := security.SelectWinnerIndex(output, len(sortedParticipants))
	winnerUserID := sortedParticipants[idx]

	now := time.Now().UTC()
	seedHex := hex.EncodeToString(seed)
	outputHex := hex.EncodeToString(output)
	proofHex := hex.EncodeToString(proof)
	if err := d.auctionRepo.SaveDrawResult(auctionID, seedHex, outputHex, proofHex, winnerUserID, now); err != nil {
		applog.Error("DRAW_SAVE_FAIL", auctionID, winnerUserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	pHash := participantsHash(sortedParticipants)
	var winnerBidID string
	for _, r := range reveals {
		if r.UserID == winnerUserID {
			winnerBidID = r.BidID
			break
		}
	}

	// 라운드의 화이트리스트 root 도 같이 응답에 포함 (정직성 비교용)
	snap, _ := d.auctionRepo.GetLotteryDrawSnapshot(auctionID)
	whitelistRoot := ""
	if snap != nil {
		whitelistRoot = snap.WhitelistRoot
	}

	applog.Audit("LOTTERY_DRAWN", auctionID, winnerUserID, "", "VRF 추첨 완료")
	return &WinnerInfo{
		BidID:            winnerBidID,
		UserID:           winnerUserID,
		CombinedSeedHex:  seedHex,
		VRFOutputHex:     outputHex,
		VRFProofHex:      proofHex,
		ParticipantsHash: pHash,
		WhitelistRoot:    whitelistRoot,
		DrawnAt:          now,
	}, nil
}

// ─────────────────────────────────────────────
//  3. 공개 검증 (누구나 호출 가능)
// ─────────────────────────────────────────────

// VerificationResult는 검증 페이지가 반환하는 결과입니다.
// 클라이언트는 이 값들로 추첨을 100% 재현 가능하며, *Match 필드들이 모두 true여야 정직.
type VerificationResult struct {
	AuctionID          string   `json:"auctionId"`
	Status             string   `json:"status"`
	VRFPubkeyHex       string   `json:"vrfPubkeyHex"`
	WhitelistRoot      string   `json:"whitelistRoot"`
	Participants       []string `json:"participants"`
	ParticipantNonces  []string `json:"participantNonces"`
	CombinedSeedHex    string   `json:"combinedSeedHex"`
	VRFProofHex        string   `json:"vrfProofHex"`
	VRFOutputHex       string   `json:"vrfOutputHex"`
	ServerWinnerUserID string   `json:"serverWinnerUserId"`
	RecomputedWinnerID string   `json:"recomputedWinnerId"`
	WinnerMatch        bool     `json:"winnerMatch"`
	VRFProofValid      bool     `json:"vrfProofValid"`
	SeedRecomputeMatch bool     `json:"seedRecomputeMatch"`
}

// VerifyLottery는 저장된 결과 + 모든 입력값을 노출하고 서버측에서도 동일 재계산하여
// 일치 여부를 함께 반환합니다.
func (d *LotteryDrawer) VerifyLottery(auctionID string) (*VerificationResult, error) {
	snap, err := d.auctionRepo.GetLotteryDrawSnapshot(auctionID)
	if err != nil {
		return nil, err
	}
	res := &VerificationResult{
		AuctionID:          auctionID,
		Status:             snap.Status,
		VRFPubkeyHex:       hex.EncodeToString(snap.VrfPubkey),
		WhitelistRoot:      snap.WhitelistRoot,
		CombinedSeedHex:    snap.CombinedSeed,
		VRFProofHex:        snap.VrfProof,
		VRFOutputHex:       snap.VrfOutput,
		ServerWinnerUserID: snap.WinnerUserID,
	}

	reveals, err := d.bidRepo.FindRevealedNonces(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	contribs := make([]security.NonceContribution, 0, len(reveals))
	users := make([]string, 0, len(reveals))
	nonces := make([]string, 0, len(reveals))
	for _, r := range reveals {
		contribs = append(contribs, security.NonceContribution{UserID: r.UserID, Nonce: r.NonceValue})
		users = append(users, r.UserID)
		nonces = append(nonces, r.NonceValue)
	}
	sort.Strings(users)
	res.Participants = users
	res.ParticipantNonces = nonces

	if snap.Status != "VERIFIED" || len(snap.VrfPubkey) == 0 {
		return res, nil
	}

	rebuiltSeed := security.CombineNonces(contribs)
	res.SeedRecomputeMatch = hex.EncodeToString(rebuiltSeed) == snap.CombinedSeed

	proofBytes, err1 := hex.DecodeString(snap.VrfProof)
	expectedOutput, err2 := hex.DecodeString(snap.VrfOutput)
	if err1 == nil && err2 == nil {
		if rebuiltOutput, ok := security.VRFVerify(snap.VrfPubkey, rebuiltSeed, proofBytes); ok {
			res.VRFProofValid = true
			sortedParticipants := append([]string(nil), users...)
			sort.Strings(sortedParticipants)
			if len(sortedParticipants) > 0 {
				idx := security.SelectWinnerIndex(rebuiltOutput, len(sortedParticipants))
				res.RecomputedWinnerID = sortedParticipants[idx]
			}
			res.WinnerMatch = res.RecomputedWinnerID == snap.WinnerUserID &&
				hex.EncodeToString(rebuiltOutput) == hex.EncodeToString(expectedOutput)
		}
	}
	return res, nil
}

// ─────────────────────────────────────────────
//  4. 머클 화이트리스트 멤버십 증명
// ─────────────────────────────────────────────

// WhitelistProofResult는 화이트리스트 멤버십 증명입니다.
// 클라이언트는 (LeafHashHex, Proof, Root) 만으로 자신의 멤버십을 검증 가능합니다.
type WhitelistProofResult struct {
	AuctionID    string                    `json:"auctionId"`
	Username     string                    `json:"username"`
	Role         string                    `json:"role"`
	LeafIndex    int                       `json:"leafIndex"`
	LeafHashHex  string                    `json:"leafHashHex"`
	Proof        []security.MerkleProofStep `json:"proof"`
	Root         string                    `json:"root"`
	Verified     bool                      `json:"verified"`
}

// WhitelistProof는 라운드의 봉인된 화이트리스트에서 username의 멤버십 증명을 생성합니다.
// 인증 불필요. 명단 변조가 일어났다면 root 가 변경되어 클라이언트 측 검증이 자연 실패.
func (d *LotteryDrawer) WhitelistProof(auctionID, username string) (*WhitelistProofResult, error) {
	snap, err := d.auctionRepo.GetLotteryDrawSnapshot(auctionID)
	if err != nil {
		return nil, err
	}
	if snap.WhitelistRoot == "" {
		return nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "화이트리스트 봉인이 없는 라운드입니다."}
	}

	idx, err := d.auctionRepo.FindWhitelistLeafIndex(auctionID, username)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if idx < 0 {
		return &WhitelistProofResult{
			AuctionID: auctionID, Username: username, LeafIndex: -1,
			Root: snap.WhitelistRoot, Verified: false,
		}, nil
	}

	leaves, err := d.auctionRepo.LoadWhitelistSnapshot(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	leafHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = security.MerkleLeafHash(l.Username, l.Role)
	}
	proof, err := security.BuildMerkleProof(leafHashes, idx)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}

	leafHashHex := hex.EncodeToString(leafHashes[idx])
	verified := security.VerifyMerkleProof(leafHashHex, proof, snap.WhitelistRoot)

	return &WhitelistProofResult{
		AuctionID:   auctionID,
		Username:    leaves[idx].Username,
		Role:        leaves[idx].Role,
		LeafIndex:   idx,
		LeafHashHex: leafHashHex,
		Proof:       proof,
		Root:        snap.WhitelistRoot,
		Verified:    verified,
	}, nil
}

// ─────────────────────────────────────────────
//  내부 헬퍼
// ─────────────────────────────────────────────

// participantsHash는 정렬된 참가자 목록의 SHA-256 hex 를 반환합니다.
// 외부 게시판 등에 공개해두면 사후 명단 변조를 곧바로 발각시킬 수 있습니다.
func participantsHash(sortedUsers []string) string {
	return security.BeaconCommit("__participants__", joinUsers(sortedUsers), "v1")
}

func joinUsers(users []string) string {
	out := ""
	for i, u := range users {
		if i > 0 {
			out += ","
		}
		out += u
	}
	return out
}
