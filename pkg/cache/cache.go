package cache

import (
	"time"

	gocache "github.com/patrickmn/go-cache"
)

var cache = gocache.New(10*time.Second, 10*time.Second)

func NotExists(key string) bool {

	// 检查缓存中是否存在
	if _, found := cache.Get(key); found {
		return false // 1分钟内已记录
	}

	// 添加到缓存，1分钟后自动过期
	cache.Set(key, struct{}{}, gocache.DefaultExpiration)
	return true
}

