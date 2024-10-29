package mongodb

import (
	"context"

	"github.com/authorizerdev/authorizer/server/db/models"
)

// GetCreatorByEmail to get creator by email
// TODO: implement this
func (p *provider) GetCreatorByEmail(ctx context.Context, email string) (models.Creator, error) {
	var creator models.Creator
	return creator, nil
}
