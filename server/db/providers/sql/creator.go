package sql

import (
	"context"

	"github.com/authorizerdev/authorizer/server/db/models"
)

// GetCreatorByEmail to get creator by email
func (p *provider) GetCreatorByEmail(ctx context.Context, emailAddress string) (models.Creator, error) {
	var creator models.Creator

	result := p.db.Where("email = ?", emailAddress).First(&creator)
	if result.Error != nil {
		return creator, result.Error
	}
	return creator, nil
}
