package control

import (
	"time"

	gocache "github.com/patrickmn/go-cache"
)

var dnsLogCache = gocache.New(3*time.Minute, 5*time.Minute)

func checkCache(questionName string) bool {

	// 检查缓存中是否存在
	if _, found := dnsLogCache.Get(questionName); found {
		return false // 3分钟内已记录
	}

	// 添加到缓存，3分钟后自动过期
	dnsLogCache.Set(questionName, struct{}{}, gocache.DefaultExpiration)
	return true
}
