package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/componentcatalog"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
)

// 家用测速端反向 WS:测速端(部署在用户家里)主动连入主控,凭配对 token 认证;
// 主控通过该连接派发测速任务、收回结果(解决家庭无公网 IP 无法被主控主动访问的问题)。
// 协议:JSON 文本帧。master→tester {type:run,...};tester→master {type:result,...} / {type:hello} / {type:pong}。

// stWSMsg 测速端 WS 消息(双向复用)。
type stWSMsg struct {
	Type        string   `json:"type"`
	JobID       string   `json:"job_id,omitempty"`
	ClashConfig string   `json:"clash_config,omitempty"`
	Bytes       int64    `json:"bytes,omitempty"`
	URL         string   `json:"url,omitempty"`
	Threads     int      `json:"threads,omitempty"`      // 并发下载线程数(默认 1)
	LatencyOnly bool     `json:"latency_only,omitempty"` // true 仅测真连接延迟(Cloudflare 204)
	DownMbps    float64  `json:"down_mbps,omitempty"`
	LatencyMs   int64    `json:"latency_ms,omitempty"`
	EgressIP    string   `json:"egress_ip,omitempty"`
	Status      string   `json:"status,omitempty"`
	Error       string   `json:"error,omitempty"`
	Name        string   `json:"name,omitempty"`
	Version     string   `json:"version,omitempty"`
	Caps        []string `json:"caps,omitempty"`
	GOOS        string   `json:"goos,omitempty"`
	GOARCH      string   `json:"goarch,omitempty"`

	// update is sent only to clients that explicitly advertise self_update_v1.
	// The three fields point at an immutable, backend-approved Release asset and
	// its checksum manifest rather than a moving "latest" URL.
	AssetName    string `json:"asset_name,omitempty"`
	DownloadURL  string `json:"download_url,omitempty"`
	ChecksumsURL string `json:"checksums_url,omitempty"`
}

const speedtesterSelfUpdateCapability = "self_update_v1"

func speedtesterUpdateMessage(currentVersion string, caps []string, goos, goarch string) (stWSMsg, bool) {
	if !hasSpeedtesterCapability(caps, speedtesterSelfUpdateCapability) {
		return stWSMsg{}, false
	}
	asset, checksumsURL, supported := componentcatalog.Speedtester(goos, goarch)
	if !supported || currentVersion == "" || componentcatalog.VersionCompare(currentVersion, asset.Version) >= 0 {
		return stWSMsg{}, false
	}
	return stWSMsg{
		Type:         "update",
		Version:      asset.Version,
		AssetName:    asset.Name,
		DownloadURL:  asset.URL,
		ChecksumsURL: checksumsURL,
	}, true
}

func hasSpeedtesterCapability(caps []string, wanted string) bool {
	for _, capability := range caps {
		if capability == wanted {
			return true
		}
	}
	return false
}

type testerConn struct {
	id      int64
	conn    *websocket.Conn
	writeMu sync.Mutex
	pending sync.Map // jobID(string) -> chan stWSMsg
}

func (tc *testerConn) send(m stWSMsg) error {
	data, _ := json.Marshal(m)
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()
	return tc.conn.WriteMessage(websocket.TextMessage, data)
}

// SpeedTesterWSHandler 管理家用测速端连接。
type SpeedTesterWSHandler struct {
	repo              *storage.TrafficRepository
	upgrader          websocket.Upgrader
	conns             sync.Map // testerID(int64) -> *testerConn
	capabilityManager *capabilities.Manager
}

func NewSpeedTesterWSHandler(repo *storage.TrafficRepository) *SpeedTesterWSHandler {
	return &SpeedTesterWSHandler{
		repo:     repo,
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
	}
}

func (h *SpeedTesterWSHandler) SetCapabilityManager(manager *capabilities.Manager) {
	h.capabilityManager = manager
}

// Online 测速端当前是否在线。
func (h *SpeedTesterWSHandler) Online(testerID int64) bool {
	_, ok := h.conns.Load(testerID)
	return ok
}

func (h *SpeedTesterWSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	tester, err := h.repo.GetSpeedTesterByTokenHash(r.Context(), hashShareToken(token))
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	tc := &testerConn{id: tester.ID, conn: conn}
	// 同一测速端重连:踢掉旧连接
	if old, ok := h.conns.Load(tester.ID); ok {
		old.(*testerConn).conn.Close()
	}
	h.conns.Store(tester.ID, tc)
	log.Printf("[SpeedTester] tester %d (%s) connected", tester.ID, tester.Name)
	h.repo.TouchSpeedTester(context.Background(), tester.ID)

	defer func() {
		conn.Close()
		// 仅当当前注册的就是自己时才删除(避免误删新连接)
		if cur, ok := h.conns.Load(tester.ID); ok && cur.(*testerConn) == tc {
			h.conns.Delete(tester.ID)
		}
		log.Printf("[SpeedTester] tester %d disconnected", tester.ID)
	}()

	conn.SetReadLimit(64 * 1024)
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg stWSMsg
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "result":
			if ch, ok := tc.pending.Load(msg.JobID); ok {
				select {
				case ch.(chan stWSMsg) <- msg:
				default:
				}
			}
		case "hello":
			h.repo.TouchSpeedTester(context.Background(), tester.ID)
			_ = tc.send(stWSMsg{Type: "pong"})
			if update, available := speedtesterUpdateMessage(msg.Version, msg.Caps, msg.GOOS, msg.GOARCH); available {
				if err := tc.send(update); err != nil {
					log.Printf("[SpeedTester] tester %d update dispatch failed: %v", tester.ID, err)
				}
			}
		case "ping":
			h.repo.TouchSpeedTester(context.Background(), tester.ID)
			_ = tc.send(stWSMsg{Type: "pong"})
		case "update_result":
			if msg.Status != "ok" {
				log.Printf("[SpeedTester] tester %d update failed: %s", tester.ID, msg.Error)
			}
		}
	}
}

// Dispatch 把测速任务派给指定在线测速端,阻塞等结果(带超时)。
// threads >= 2 时启用多线程下载;latencyOnly=true 时跳过下载只测 Cloudflare 204 真延迟。
func (h *SpeedTesterWSHandler) Dispatch(ctx context.Context, testerID int64, clashConfig string, bytes int64, url string, threads int, latencyOnly bool) (speedtest.Result, error) {
	if h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureSpeedTest) {
		return speedtest.Result{}, errors.New("测速端不在线")
	}
	v, ok := h.conns.Load(testerID)
	if !ok {
		return speedtest.Result{}, errors.New("测速端不在线")
	}
	tc := v.(*testerConn)
	jobID := uuid.New().String()
	ch := make(chan stWSMsg, 1)
	tc.pending.Store(jobID, ch)
	defer tc.pending.Delete(jobID)

	if err := tc.send(stWSMsg{
		Type: "run", JobID: jobID, ClashConfig: clashConfig,
		Bytes: bytes, URL: url, Threads: threads, LatencyOnly: latencyOnly,
	}); err != nil {
		return speedtest.Result{}, errors.New("下发任务失败: " + err.Error())
	}

	select {
	case res := <-ch:
		if res.Status != "ok" {
			return speedtest.Result{LatencyMs: res.LatencyMs, EgressIP: res.EgressIP}, errors.New(res.Error)
		}
		return speedtest.Result{DownMbps: res.DownMbps, LatencyMs: res.LatencyMs, Bytes: bytes, EgressIP: res.EgressIP}, nil
	case <-time.After(120 * time.Second):
		return speedtest.Result{}, errors.New("测速端响应超时")
	case <-ctx.Done():
		return speedtest.Result{}, ctx.Err()
	}
}
