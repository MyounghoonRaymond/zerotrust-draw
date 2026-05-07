// Package security: 머클 화이트리스트 (Merkle Whitelist Commitment).
//
// 라운드 생성 시점에 화이트리스트(참여 가능 사용자 목록) 스냅샷을
// 머클 트리로 봉인합니다. 라운드의 root 해시가 auctions 테이블에 박히면
// 운영자도 사후에 명단을 변조할 수 없습니다(변조하면 root 불일치).
//
// 보안 속성:
//   - 무결성:   참가자 누구나 자신의 (username, role) 리프 + proof 로 root 재계산 가능
//   - 비귀속성: root만 공개해도 멤버십 증명 가능 (전체 명단 비공개로 운영해도 OK)
//   - 사후 검증성: 라운드 종료 후에도 누구나 "내가 명단에 있었다" 증명 가능
//
// 리프 포맷: SHA-256(username + ":" + role)
// 내부노드: SHA-256(left || right)
// 홀수 노드: 마지막 노드를 복제하여 짝 맞춤 (Bitcoin 스타일)
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
)

// MerkleLeaf는 화이트리스트 한 항목입니다.
type MerkleLeaf struct {
	Username string
	Role     string
}

// MerkleProofStep은 root까지 거슬러 올라가는 한 단계의 형제 해시입니다.
type MerkleProofStep struct {
	Hash   string `json:"hash"`   // hex of sibling hash
	IsLeft bool   `json:"isLeft"` // 형제가 왼쪽이면 true (이 경우 H = SHA(sibling || cur))
}

// MerkleLeafHash는 리프 해시를 계산합니다: SHA-256(username + ":" + role).
func MerkleLeafHash(username, role string) []byte {
	h := sha256.Sum256([]byte(username + ":" + role))
	return h[:]
}

// merkleParentHash는 내부노드 해시를 계산합니다: SHA-256(left || right).
func merkleParentHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// BuildMerkleRoot는 화이트리스트로부터 머클 루트를 만듭니다.
// 입력은 username 오름차순으로 정렬되어 결정적 root를 보장합니다.
// 반환:
//   - rootHex: 32바이트 SHA-256 root의 hex
//   - leafHashes: 정렬된 리프 해시 배열 (proof 생성 입력으로 재사용)
//   - sortedLeaves: 정렬 결과 (snapshot 저장용)
func BuildMerkleRoot(leaves []MerkleLeaf) (rootHex string, leafHashes [][]byte, sortedLeaves []MerkleLeaf) {
	sortedLeaves = append([]MerkleLeaf(nil), leaves...)
	sort.Slice(sortedLeaves, func(i, j int) bool { return sortedLeaves[i].Username < sortedLeaves[j].Username })

	leafHashes = make([][]byte, len(sortedLeaves))
	for i, l := range sortedLeaves {
		leafHashes[i] = MerkleLeafHash(l.Username, l.Role)
	}

	if len(leafHashes) == 0 {
		empty := sha256.Sum256(nil)
		return hex.EncodeToString(empty[:]), leafHashes, sortedLeaves
	}

	level := make([][]byte, len(leafHashes))
	copy(level, leafHashes)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, merkleParentHash(level[i], level[i+1]))
		}
		level = next
	}
	return hex.EncodeToString(level[0]), leafHashes, sortedLeaves
}

// BuildMerkleProof는 인덱스 idx 리프에 대한 형제 경로를 반환합니다.
// leafHashes 는 BuildMerkleRoot 가 반환한 정렬된 리프 해시 배열을 그대로 넘겨야 합니다.
func BuildMerkleProof(leafHashes [][]byte, idx int) ([]MerkleProofStep, error) {
	if idx < 0 || idx >= len(leafHashes) {
		return nil, errors.New("merkle proof: index out of range")
	}
	if len(leafHashes) == 0 {
		return nil, errors.New("merkle proof: empty tree")
	}

	var proof []MerkleProofStep
	level := make([][]byte, len(leafHashes))
	copy(level, leafHashes)
	cur := idx

	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		var sibIdx int
		var isLeft bool
		if cur%2 == 0 {
			sibIdx = cur + 1
			isLeft = false
		} else {
			sibIdx = cur - 1
			isLeft = true
		}
		proof = append(proof, MerkleProofStep{
			Hash:   hex.EncodeToString(level[sibIdx]),
			IsLeft: isLeft,
		})
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, merkleParentHash(level[i], level[i+1]))
		}
		level = next
		cur /= 2
	}
	return proof, nil
}

// VerifyMerkleProof는 (leaf, proof, root) 만으로 root 재계산을 검증합니다.
// 클라이언트(검증 페이지)도 동일 함수를 자바스크립트 등으로 재구현 가능합니다.
func VerifyMerkleProof(leafHashHex string, proof []MerkleProofStep, expectedRootHex string) bool {
	cur, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return false
	}
	for _, step := range proof {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false
		}
		if step.IsLeft {
			cur = merkleParentHash(sib, cur)
		} else {
			cur = merkleParentHash(cur, sib)
		}
	}
	return hex.EncodeToString(cur) == expectedRootHex
}
