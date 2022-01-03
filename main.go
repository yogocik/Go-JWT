package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

type UserCredential struct {
	Username string `json:"user_name" binding:"required"`
	Password string `json:"user_password" binding:"required"`
}

type authHeader struct {
	AuthorizationHeader string `header:"authorization" binding:"required"`
}

func main() {
	r := gin.Default()
	r.Use(authMiddle())
	r.POST("/login", func(c *gin.Context) {
		user := UserCredential{}
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"Message":    "Invalid input",
				"StatusCode": 400,
			})
			return
		}
		if user.Username == "user" && user.Password == "pass" {
			c.JSON(200, gin.H{
				"Message":    "Success",
				"StatusCode": 200,
			})
			return
		}
		c.AbortWithStatusJSON(401, gin.H{
			"Message":    "Invalid credentials",
			"StatusCode": 401,
		})
	})

	r.GET("/customer", func(c *gin.Context) {
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

func authMiddle() gin.HandlerFunc {
	authFunc := func(c *gin.Context) {
		if c.Request.URL.Path == "/login" {
			c.Next()
			return
		}
		var h authHeader
		if err := c.ShouldBindHeader(&h); err != nil || h.AuthorizationHeader == "" {
			c.AbortWithStatusJSON(400, gin.H{
				"Message":    "No valid header provided",
				"StatusCode": 400,
			})
		} else if h.AuthorizationHeader != "123" {
			c.AbortWithStatusJSON(401, gin.H{
				"Message":    "Invalid header value",
				"StatusCode": 401,
			})
		}
	}
	return authFunc
}
