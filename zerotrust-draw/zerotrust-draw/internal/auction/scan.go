package auction

import (
	"database/sql"
	"time"

	"zerotrust-draw/pkg/models"
)

// scanAuction은 sql.Row를 models.Auction으로 변환합니다.
// repository.go와 service_test.go에서 공유합니다.
func scanAuction(row *sql.Row) (*models.Auction, error) {
	var a models.Auction
	var startAt, endAt, createdAt string
	var revealDeadline sql.NullString
	err := row.Scan(&a.ID, &a.ItemName, &a.CreatedBy, &a.Status,
		&startAt, &endAt, &revealDeadline, &createdAt)
	if err != nil {
		return nil, err
	}
	a.StartAt, _ = time.Parse(time.RFC3339, startAt)
	a.EndAt, _ = time.Parse(time.RFC3339, endAt)
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if revealDeadline.Valid {
		t, _ := time.Parse(time.RFC3339, revealDeadline.String)
		a.RevealDeadline = &t
	}
	return &a, nil
}
