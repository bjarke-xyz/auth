package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	pany "github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var keyRetreiver = NewGoogleKeyRetreiver()

var ErrValidation = errors.New("validation error")

func WarmCache(ctx context.Context) {
	keyRetreiver.GetKeys(ctx)
}

func ValidateToken(ctx context.Context, audience string, tokenStr string) (*AuthToken, error) {
	keys, err := keyRetreiver.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting keys: %w", err)
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
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
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(audience), jwt.WithIssuer("https://securetoken.google.com/"+audience))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("%w: token not valid", ErrValidation)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: failed to get token map claims", ErrValidation)
	}
	authTimeIface, ok := claims["auth_time"]
	if !ok {
		return nil, fmt.Errorf("%w: claim auth_time not found", ErrValidation)
	}
	authTime, ok := authTimeIface.(float64)
	if !ok {
		return nil, fmt.Errorf("%w: claim auth_time has invalid type", ErrValidation)
	}
	// auth_time must be in the past
	now := float64(time.Now().UTC().Unix())
	if authTime > now {
		return nil, fmt.Errorf("%w: auth_time must be in the past. auth_time=%f now=%f", ErrValidation, authTime, now)
	}
	authToken := &AuthToken{
		Claims: make(map[string]*anypb.Any),
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
			anyVal, err := ConvertInterfaceToAny(v)
			if err != nil {
				return nil, fmt.Errorf("error converting interface to anypb")
			}
			authToken.Claims[k] = anyVal
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

func ConvertInterfaceToAny(v interface{}) (*pany.Any, error) {
	anyValue := &pany.Any{}
	bytes, _ := json.Marshal(v)
	bytesValue := &wrappers.BytesValue{
		Value: bytes,
	}
	err := anypb.MarshalFrom(anyValue, bytesValue, proto.MarshalOptions{})
	return anyValue, err
}

func ConvertAnyToInterface(anyValue *pany.Any) (interface{}, error) {
	var value interface{}
	bytesValue := &wrappers.BytesValue{}
	err := anypb.UnmarshalTo(anyValue, bytesValue, proto.UnmarshalOptions{})
	if err != nil {
		return value, err
	}
	uErr := json.Unmarshal(bytesValue.Value, &value)
	if err != nil {
		return value, uErr
	}
	return value, nil
}
