package main

import (
	"auth/authenticate"
	mdw "auth/delivery/middleware"
	"auth/model"
	"auth/util"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func main() {
	r := gin.Default()
	tokenConf := authenticate.TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "Password",
		AccessTokenLifeTime: time.Duration(30) * time.Second,
	}
	tokenService := authenticate.NewTokenService(tokenConf)
	tokenValidator := mdw.NewTokenValidator(tokenService)
	r.Use(tokenValidator.RequireToken())
	publicRoute := r.Group("/enigma")
	publicRoute.POST("/login", func(c *gin.Context) {
		user := model.Credentials{}
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"Message":    "Invalid input",
				"StatusCode": 400,
			})
			return
		}
		if user.Username == "user" && user.Password == "pass" {
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatusJSON(500, gin.H{
					"Message":    "Internal Server Error",
					"ErrMessage": err.Error(),
					"StatusCode": 401,
				})
				return
			}
			authenticate.TOKEN_DUMP = append(authenticate.TOKEN_DUMP, "Bearer "+token)
			c.JSON(200, gin.H{
				"Message":    "Success",
				"StatusCode": 200,
				"Data":       token,
			})
			return
		}
		c.AbortWithStatusJSON(401, gin.H{
			"Message":    "Invalid credentials",
			"StatusCode": 401,
		})
	})

	publicRoute.POST("/logout", func(c *gin.Context) {
		var isChanged bool
		authValue := c.GetHeader("Authorization")
		authenticate.TOKEN_DUMP, isChanged = util.SearchDelete(authenticate.TOKEN_DUMP, authValue)
		if isChanged {
			c.JSON(200, gin.H{
				"Message":    "Success Log out",
				"StatusCode": 200,
			})
			return
		}
		c.JSON(500, gin.H{
			"Message":    "Internal Error. No Change Found!",
			"StatusCode": 500,
		})

	})

	publicRoute.GET("/customer", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"Message":    "Success",
			"StatusCode": 200,
			"Data":       c.GetHeader("Authorization"),
		})
	})
	err := r.Run()
	if err != nil {
		log.Fatalln("Failed running", err)
	}
}
