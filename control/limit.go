package control

import (
    "io"
    "net/http"
    "sync"
    "time"
)
// RateLimiter 限流器（1分钟内最多触发一次告警）
type RateLimiter struct {
    mu            sync.Mutex
    calls         []time.Time
    threshold     int
    windowSize    time.Duration
    lastAlertTime time.Time
    alertCooldown time.Duration
    callback      func()
}

// NewRateLimiter 创建限流器
func NewRateLimiter(threshold int, windowSize, cooldown time.Duration, callback func()) *RateLimiter {
    return &RateLimiter{
        calls:         make([]time.Time, 0),
        threshold:     threshold,
        windowSize:    windowSize,
        lastAlertTime: time.Time{},
        alertCooldown: cooldown,
        callback:      callback,
    }
}

// Record 记录调用
func (r *RateLimiter) Record() {
    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-r.windowSize)

    // 清理过期调用
    valid := make([]time.Time, 0)
    for _, t := range r.calls {
        if t.After(cutoff) {
            valid = append(valid, t)
        }
    }
    r.calls = valid

    // 检查是否超过阈值
    if len(r.calls) >= r.threshold {
        // 检查是否在冷却期
        if now.Sub(r.lastAlertTime) >= r.alertCooldown {
            // 触发告警
            if r.callback != nil {
                go r.callback()
            }
            r.lastAlertTime = now
            // 清空调用记录
            r.calls = make([]time.Time, 0)
        }
        return
    }

    // 记录本次调用
    r.calls = append(r.calls, now)
}

// sendAlert 发送告警
func sendAlert() {
    client := &http.Client{
        Timeout: 3 * time.Second,
    }

    req, err := http.NewRequest("GET", "http://localhost:8080/api/jms/restartAll", nil)
    if err != nil {
        return
    }

    resp, err := client.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()

    _, _ = io.Copy(io.Discard, resp.Body)
}

var limiter = NewRateLimiter(50, time.Minute, time.Minute, sendAlert)
