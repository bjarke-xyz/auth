package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var keyRetreiver = NewGoogleKeyRetreiver()

var ErrValidation = errors.New("validation error")

func ValidateToken(ctx context.Context, request ValidateTokenRequest) (AuthToken, error) {
	keys, err := keyRetreiver.GetKeys(ctx)
	if err != nil {
		return AuthToken{}, fmt.Errorf("error getting keys: %w", err)
	}
	token, err := jwt.Parse(request.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: unexpected signing method: %v", ErrValidation, token.Header["alg"])
		}
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("%w: kid not found in token header", ErrValidation)
		}
		kidStr, ok := kid.(string)
		if !ok {
			return nil, fmt.Errorf("%w: kid was not a string", ErrValidation)
		}
		key, ok := keys[kidStr]
		if !ok {
			return nil, fmt.Errorf("%w: key not found for kid %v", ErrValidation, kidStr)
		}
		block, _ := pem.Decode([]byte(key))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse certificate", ErrValidation)
		}
		publicKey := cert.PublicKey.(*rsa.PublicKey)
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(request.Audience), jwt.WithIssuer("https://securetoken.google.com/"+request.Audience))
	if err != nil {
		return AuthToken{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if !token.Valid {
		return AuthToken{}, fmt.Errorf("%w: token not valid", ErrValidation)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return AuthToken{}, fmt.Errorf("%w: failed to get token map claims", ErrValidation)
	}
	authTimeIface, ok := claims["auth_time"]
	if !ok {
		return AuthToken{}, fmt.Errorf("%w: claim auth_time not found", ErrValidation)
	}
	authTime, ok := authTimeIface.(float64)
	if !ok {
		return AuthToken{}, fmt.Errorf("%w: claim auth_time has invalid type", ErrValidation)
	}
	// auth_time must be in the past
	now := float64(time.Now().UTC().Unix())
	if authTime > now {
		return AuthToken{}, fmt.Errorf("%w: auth_time must be in the past. auth_time=%f now=%f", ErrValidation, authTime, now)
	}
	authToken := AuthToken{
		Claims: make(map[string]any),
	}
	for k, v := range claims {
		switch k {
		case "auth_time":
			authToken.AuthTime = v.(float64)
		case "iss":
			authToken.Issuer = v.(string)
		case "aud":
			authToken.Audience = v.(string)
		case "exp":
			authToken.Expires = v.(float64)
		case "iat":
			authToken.IssuedAt = v.(float64)
		case "sub":
			authToken.Subject = v.(string)
		case "user_id":
			authToken.UID = v.(string)
		case "role":
			authToken.Role = v.(string)
		case "products":
			authToken.Products = convertToArrayString(v)
		case "groups":
			authToken.Groups = convertToArrayString(v)
		default:
			authToken.Claims[k] = v
		}
	}
	return authToken, nil
}

func convertToArrayString(val any) []string {
	ifaceList, ok := val.([]any)
	if !ok {
		return []string{}
	}
	strList := make([]string, len(ifaceList))
	for i, ifaceVal := range ifaceList {
		strVal, ok := ifaceVal.(string)
		if ok {
			strList[i] = strVal
		} else {
			strList[i] = ""
		}
	}
	return strList
}

type AuthToken struct {
	AuthTime float64
	Issuer   string
	Audience string
	Expires  float64
	IssuedAt float64
	Subject  string
	UID      string
	Claims   map[string]any
	Products []string
	Role     string
	Groups   []string
}

type ValidateTokenRequest struct {
	Token    string
	Audience string
}
