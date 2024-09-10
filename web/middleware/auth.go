package middleware

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

var (
	urls = []string{
		"http://dev-api.agi7.ai:10000",
		"http://test-api.agi7.ai:10000",
		"http://api.agi7.ai:10000",
	}
)

// parse token from request header
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		err, ret := ParseHSToken(token, "be3aae4fa5a14f52a194f82fa3cc606e")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		url, ok := ret["url"].(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("parsed url %s", url)

		if !contains(urls, url) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ParseHSToken(token string, secret string) (error, jwt.MapClaims) {
	return ParseToken(token, map[string]string{jwt.SigningMethodHS256.Alg(): secret})
}

// ParseToken verifies and parses JWT token and returns its claims.
func ParseToken(token string, methodKey map[string]string) (error, jwt.MapClaims) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		key, ok := methodKey[t.Method.Alg()]
		if !ok {
			return nil, fmt.Errorf("method %s is not supported", t.Method)
		}
		return []byte(key), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Printf("token %s is expired", token)
			return err, nil
		}
		log.Printf("parse token %s err %s", token, err)
		return err, nil
	}
	if !parsedToken.Valid {
		log.Printf("token %s is invalid", token)
		return err, nil
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("claims %v is invalid", parsedToken.Claims)
		return err, nil
	}

	return err, claims
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
