package delivery

import (
	"auth/authenticate"
	"auth/util"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"authorization" binding:"required"`
}

type AuthTokenMiddleware struct {
	acctToken authenticate.Token
}

func NewTokenValidator(acctToken authenticate.Token) *AuthTokenMiddleware {
	return &AuthTokenMiddleware{
		acctToken: acctToken,
	}
}

func (a *AuthTokenMiddleware) RequireToken() gin.HandlerFunc {
	authFunc := func(c *gin.Context) {
		if c.Request.URL.Path == "/enigma/login" {
			c.Next()
			return
		}
		var h AuthHeader
		if err := c.ShouldBindHeader(&h); err != nil || h.AuthorizationHeader == "" {
			c.AbortWithStatusJSON(400, gin.H{
				"Message":    "No valid header provided",
				"StatusCode": 400,
			})
		} else if !util.SearchElement(authenticate.TOKEN_DUMP, h.AuthorizationHeader) {
			c.AbortWithStatusJSON(401, gin.H{
				"Message":    "Invalid Token Header",
				"StatusCode": 401,
			})
			return
		}
		tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
		token, err := a.acctToken.VerifyAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{
				"Message":    "Unauthorized",
				"StatusCode": 401,
				"ErrMsg":     err.Error(),
			})
			return
		}
		if token == nil {
			c.AbortWithStatusJSON(401,
				gin.H{
					"Message":    "Unauthorized. Unknown Credentials",
					"StatusCode": 401,
				})
			return
		} else {
			c.Next()
		}
	}
	return authFunc
}
