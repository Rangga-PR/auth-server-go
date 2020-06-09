package controller

import (
	"auth-server-go/model"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

//Controller : constructor
type Controller struct {
	Collection *mongo.Collection
	Redis      *redis.Client
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

//LoginHandler : handle user login logic
func (con *Controller) LoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		email := c.Query("email")
		password := c.Query("password")

		if email == "" || password == "" {
			sendFailedResponse(c, http.StatusBadRequest, "please fill email and password")
			return
		}

		accessToken, err := con.Redis.Get(c, email).Result()
		if err != nil || accessToken != "" {
			sendSuccessResponse(c, http.StatusOK, gin.H{
				"access_token": accessToken,
			})
			return
		}

		var loginUser model.User
		err = con.Collection.FindOne(c, bson.M{"email": email}).Decode(&loginUser)
		if err != nil {
			sendFailedResponse(c, http.StatusNotFound, "user not found")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(loginUser.Password), []byte(password))
		if err != nil {
			sendFailedResponse(c, http.StatusNotFound, "incorrect password")
			return
		}

		claims := jwt.MapClaims{
			"authorized": true,
			"username":   loginUser.Username,
			"email":      loginUser.Email,
			"id":         loginUser.ID,
			"expired":    time.Now().Add(6 * time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		accessToken, err = token.SignedString([]byte(os.Getenv("SECRET_KEY")))
		if err != nil {
			log.Println("jwt-error: ", err.Error())
			sendFailedResponse(c, http.StatusInternalServerError, "something went wrong, please try again")
			return
		}

		err = con.Redis.Set(c, loginUser.Email, accessToken, 6*time.Hour).Err()
		if err != nil {
			log.Println("redis error: ", err.Error())
		}

		sendSuccessResponse(c, http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	}
}
