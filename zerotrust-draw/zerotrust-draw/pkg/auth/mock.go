package auth

// MockAuthenticator는 A·B팀 실구현체가 완성되기 전에
// C팀이 독립 개발·테스트할 때 사용하는 가짜 구현체입니다.
//
// ⚠️ 이 파일은 테스트·개발 전용입니다. 프로덕션 코드에서 절대 사용 금지.
type MockAuthenticator struct {
	Claims *UserClaims
	Err    error
}

// ValidateSession은 미리 주입된 Claims 또는 Err를 그대로 반환합니다.
// 실제 세션 DB 조회 없이 동작하므로 테스트 전용입니다.
func (m *MockAuthenticator) ValidateSession(_ string) (*UserClaims, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Claims, nil
}

// NewMockBidder는 BIDDER 역할의 MockAuthenticator를 반환합니다.
func NewMockBidder(userID, username string) *MockAuthenticator {
	return &MockAuthenticator{
		Claims: &UserClaims{UserID: userID, Username: username, Role: "BIDDER"},
	}
}

// NewMockAuctioneer는 AUCTIONEER 역할의 MockAuthenticator를 반환합니다.
func NewMockAuctioneer(userID, username string) *MockAuthenticator {
	return &MockAuthenticator{
		Claims: &UserClaims{UserID: userID, Username: username, Role: "AUCTIONEER"},
	}
}

// NewMockAdmin은 ADMIN 역할의 MockAuthenticator를 반환합니다.
func NewMockAdmin(userID, username string) *MockAuthenticator {
	return &MockAuthenticator{
		Claims: &UserClaims{UserID: userID, Username: username, Role: "ADMIN"},
	}
}

// NewMockGuest는 GUEST 역할의 MockAuthenticator를 반환합니다.
// GUEST는 경매 조회(GET)만 가능하며 Commit/Reveal/CreateAuction은 차단됩니다.
func NewMockGuest(userID, username string) *MockAuthenticator {
	return &MockAuthenticator{
		Claims: &UserClaims{UserID: userID, Username: username, Role: "GUEST"},
	}
}

// NewMockExpired는 세션 무효 에러를 반환하는 MockAuthenticator를 반환합니다.
// 만료·변조·미존재를 구분하지 않고 동일한 ErrSessionInvalid를 반환합니다.
func NewMockExpired() *MockAuthenticator {
	return &MockAuthenticator{Err: ErrSessionInvalid}
}

// ClaimsOf는 MockAuthenticator에서 UserClaims를 직접 꺼냅니다.
// service_test.go에서 claims를 직접 주입할 때 사용합니다.
func ClaimsOf(m *MockAuthenticator) *UserClaims {
	return m.Claims
}
