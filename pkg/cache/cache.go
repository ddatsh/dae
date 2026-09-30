package cache

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	gocache "github.com/patrickmn/go-cache"
)

var cache = gocache.New(10*time.Second, 10*time.Second)
var ipNameMap sync.Map

func init() {
	DoInit()
}

func DoInit() {
	if runtime.GOOS == "windows" {
		return
	}
	ipNameMap.Clear()
	// 1. 先解析 dhcp 配置，拿到 mac -> name
	macToName, err := parseDHCPConfig("/etc/config/dhcp")
	if err != nil {
		fmt.Printf("解析 /etc/config/dhcp 失败: %v\n", err)
		return
	}

	// 2. 执行 ip neigh，直接存 ip -> name
	cmd := exec.Command("ip", "neigh", "show", "dev", "br-lan")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("执行命令失败: %v\n", err)
		return
	}

	lines := strings.SplitSeq(strings.TrimSpace(string(output)), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		ip := fields[0]
		state := fields[1]
		mac := fields[2]

		// 第二列必须是 lladdr
		if state != "lladdr" {
			continue
		}

		// 用 MAC 去查 name，查不到就保留 MAC
		name, ok := macToName[strings.ToLower(mac)]
		if !ok {
			name = mac
		}

		// KEY = IP，VALUE = name
		ipNameMap.Store(ip, name)
	}

	// 本机ip
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ipNameMap.Store(ipnet.IP.String(), "local")
		}
	}
}
func NotExists(key string) bool {

	if _, found := cache.Get(key); found {
		return false
	}

	cache.Set(key, struct{}{}, gocache.DefaultExpiration)
	return true
}

func Name(key string) string {
	if v, found := ipNameMap.Load(key); found {
		return v.(string)
	}
	return key
}

// parseDHCPConfig 解析 /etc/config/dhcp，返回 mac -> name 的映射
func parseDHCPConfig(path string) (map[string]string, error) {
	macToName := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		curName string
		curMacs []string
		inHost  bool
	)

	flush := func() {
		if !inHost {
			return
		}
		if curName != "" {
			for _, m := range curMacs {
				macToName[strings.ToLower(m)] = curName
			}
		}
		curName = ""
		curMacs = nil
		inHost = false
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "config ") {
			flush()
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "host" {
				inHost = true
			}
			continue
		}

		if !inHost {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := fields[0]
		switch key {
		case "option":
			if len(fields) < 3 {
				continue
			}
			optName := fields[1]
			optVal := strings.Trim(fields[2], "'\"")
			if optName == "name" {
				curName = optVal
			}
		case "list":
			if len(fields) < 3 {
				continue
			}
			optName := fields[1]
			optVal := strings.Trim(fields[2], "'\"")
			if optName == "mac" {
				curMacs = append(curMacs, optVal)
			}
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return macToName, nil
}
