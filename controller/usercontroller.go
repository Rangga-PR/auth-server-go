package controller

import (
	"auth-server-go/model"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

//Controller : constructor
type Controller struct {
	Collection *mongo.Collection
}

func sendFailedResponse(c *gin.Context, statusCode int, msg string) {
	c.JSON(statusCode, gin.H{
		"success": 0,
		"error":   msg,
	})
}

func sendSuccessResponse(c *gin.Context, statusCode int, data gin.H) {
	c.JSON(statusCode, gin.H{
		"success": 1,
		"result":  data,
	})
}

//RegisterHandler : handle user registeration logic
func (con *Controller) RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var u model.User

		if err := c.ShouldBindJSON(&u); err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		userData := model.User{
			Username:  u.Username,
			Email:     u.Email,
			Password:  string(hashedPassword),
			CreatedAt: primitive.NewDateTimeFromTime(time.Now().UTC()),
			UpdatedAt: primitive.NewDateTimeFromTime(time.Now().UTC()),
		}

		newUser, err := con.Collection.InsertOne(c, userData)
		if err != nil {
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong")
			log.Println(err.Error())
			return
		}

		sendSuccessResponse(c, http.StatusCreated, gin.H{
			"new_user_id": newUser.InsertedID,
		})
	}
}