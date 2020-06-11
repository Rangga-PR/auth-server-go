package model

import "go.mongodb.org/mongo-driver/bson/primitive"

//AccessToken : Define Access Token Document
type AccessToken struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id,omitempty"`
	AccessToken string             `json:"access_token" bson:"access_token"`
	LoggedOut   bool               `json:"logged_out" bson:"logged_out"`
	Revoked     bool               `json:"revoked" bson:"revoked"`
	UpdatedAt   primitive.DateTime `json:"updated_at" bson:"updated_at,omitempty"`
	CreatedAt   primitive.DateTime `json:"created_at" bson:"created_at,omitempty"`
	DeletedAt   primitive.DateTime `json:"deleted_at" bson:"deleted_at,omitempty"`
}
