package models

// Note: any change here should be reflected in providers/casandra/provider.go as it does not have model support in collection creation

// Creator model for db
type Creator struct {
	ID int64 `gorm:"primaryKey" json:"_id" bson:"_id" cql:"id" dynamo:"id,hash"`

	Name  *string `json:"name" bson:"name" cql:"name" dynamo:"name"`
	Email *string `json:"email" bson:"email" cql:"email" dynamo:"email"`
}

func (c *Creator) TableName() string {
	return "creators"
}
