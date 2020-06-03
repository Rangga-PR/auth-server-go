package model

import "go.mongodb.org/mongo-driver/bson/primitive"

//User : Define User Document
type User struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"username"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"password" bson:"password"`
	UpdatedAt primitive.DateTime `json:"updated_at" bson:"updated_at,omitempty"`
	CreatedAt primitive.DateTime `json:"created_at" bson:"created_at,omitempty"`
	DeletedAt primitive.DateTime `json:"deleted_at" bson:"deleted_at,omitempty"`
}
