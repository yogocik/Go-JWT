package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	type authHeader struct {
		AuthorizationHeader string `header:"Authorization"`
	}

	r.GET("/customer", func(c *gin.Context) {
		h := authHeader{}
		if err := c.BindHeader(&h); err != nil || h.AuthorizationHeader == "" {
			c.JSON(401, gin.H{
				"Message":    "No Valid Header Provided.",
				"StatusCode": 401,
				"Data":       h,
			})
			return
		}
		if h.AuthorizationHeader == "123" {
			c.JSON(200, gin.H{
				"Message":    "Success",
				"StatusCode": 200,
				"Data":       h,
			})
			return
		}
		c.JSON(401, gin.H{
			"Message":    "Invalid Authorization",
			"StatusCode": 401,
			"Data":       h,
		})
	})
	err := r.Run()
	if err != nil {
		log.Fatalln("Failed running", err)
	}
}
