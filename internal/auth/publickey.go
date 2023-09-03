package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type KeyRetreiver interface {
	GetKeys(context.Context) (map[string]string, error)
}

type GoogleKeyRetreiver struct {
	cache          map[string]string
	cacheExpiresAt time.Time
	sync.RWMutex
}

func NewGoogleKeyRetreiver() KeyRetreiver {
	return &GoogleKeyRetreiver{
		cache:          make(map[string]string),
		cacheExpiresAt: time.Now(),
	}
}

func (kr *GoogleKeyRetreiver) GetKeys(ctx context.Context) (map[string]string, error) {
	now := time.Now().UTC()
	if len(kr.cache) > 0 && now.Before(kr.cacheExpiresAt) {
		return kr.cache, nil
	}
	kr.Lock()
	defer kr.Unlock()
	resp, err := http.Get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got non success code from google key: %v", resp.StatusCode)
	}
	defer resp.Body.Close()
	result := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&result)
	maxAge, err := getMaxAge(resp)
	if err != nil {
		return nil, fmt.Errorf("error getting max age: %w", err)
	}
	age, err := getAge(resp)
	if err != nil {
		return nil, fmt.Errorf("error getting age: %w", err)
	}
	cacheExpiresAfterSeconds := maxAge - age
	kr.cacheExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(cacheExpiresAfterSeconds))
	kr.cache = result
	return kr.cache, nil
}

func getMaxAge(resp *http.Response) (int, error) {
	cacheControlHeader := resp.Header.Get("Cache-Control")
	parts := strings.Split(cacheControlHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, "max-age") {
			maxAgeParts := strings.Split(part, "=")
			if len(maxAgeParts) >= 2 {
				maxAgeStr := strings.TrimSpace(maxAgeParts[1])
				maxAge, err := strconv.Atoi(maxAgeStr)
				return maxAge, err
			}
		}
	}
	return 0, fmt.Errorf("maxAge int value not found")
}

func getAge(resp *http.Response) (int, error) {
	ageHeader := resp.Header.Get("Age")
	if ageHeader == "" {
		return 0, nil
	}
	return strconv.Atoi(ageHeader)
}
