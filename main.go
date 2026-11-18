package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHTML []byte

// ==================== قاعدة البيانات ====================

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    code_hash TEXT NOT NULL,
    failed_count INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT,
    direct_key TEXT UNIQUE,
    created_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_members (
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_mem_user ON chat_members(user_id);
`

var db *sql.DB

func openDB(path string) error {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	var err error
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(schema)
	return err
}

// ==================== الأمان ====================

const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*?"

func genCode() string {
	b := make([]byte, 6)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, _ := rand.Int(rand.Reader, max)
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func hashCode(code string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(code), salt, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" +
		base64.RawStdEncoding.EncodeToString(h)
}

func verifyCode(code, stored string) bool {
	p := strings.SplitN(stored, ":", 2)
	if len(p) != 2 {
		return false
	}
	salt, _ := base64.RawStdEncoding.DecodeString(p[0])
	expected, _ := base64.RawStdEncoding.DecodeString(p[1])
	actual := argon2.IDKey([]byte(code), salt, 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func newToken() (string, []byte) {
	raw := make([]byte, 32)
	rand.Read(raw)
	t := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(t))
	return t, h[:]
}

func tokHash(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

type limiter struct {
	mu   sync.Mutex
	data map[string]*entry
}
type entry struct {
	n     int
	reset time.Time
}

func newLimiter() *limiter { return &limiter{data: map[string]*entry{}} }

func (l *limiter) allow(key string, max int, win time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.data[key]
	if !ok || now.After(e.reset) {
		l.data[key] = &entry{1, now.Add(win)}
		return true
	}
	if e.n >= max {
		return false
	}
	e.n++
	return true
}

var (
	loginLimit = newLimiter()
	regLimit   = newLimiter()
	msgLimit   = newLimiter()
)

// ==================== WebSocket Hub ====================

type hub struct {
	mu      sync.RWMutex
	clients map[int64]map[*websocket.Conn]chan []byte
}

var h = &hub{clients: map[int64]map[*websocket.Conn]chan []byte{}}

func (h *hub) add(uid int64, c *websocket.Conn) chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	if h.clients[uid] == nil {
		h.clients[uid] = map[*websocket.Conn]chan []byte{}
	}
	h.clients[uid][c] = ch
	h.mu.Unlock()
	return ch
}

func (h *hub) remove(uid int64, c *websocket.Conn) {
	h.mu.Lock()
	if set := h.clients[uid]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(h.clients, uid)
		}
	}
	h.mu.Unlock()
}

func (h *hub) send(uid int64, data []byte) {
	h.mu.RLock()
	targets := make([]chan []byte, 0)
	for _, ch := range h.clients[uid] {
		targets = append(targets, ch)
	}
	h.mu.RUnlock()
	for _, ch := range targets {
		select {
		case ch <- data:
		default:
		}
	}
}

// ==================== Helpers ====================

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errMsg(w http.ResponseWriter, status int, m string) {
	writeJSON(w, status, map[string]string{"error": m})
}

func ip(r *http.Request) string {
	if x := r.Header.Get("X-Real-IP"); x != "" {
		return x
	}
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.Split(x, ",")[0]
	}
	return r.RemoteAddr
}

func authUser(r *http.Request) int64 {
	var tok string
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = h[7:]
	} else {
		tok = r.URL.Query().Get("token")
	}
	if tok == "" {
		return 0
	}
	var uid int64
	db.QueryRow(`SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?`,
		tokHash(tok), time.Now().Unix()).Scan(&uid)
	return uid
}

func isMember(uid, cid int64) bool {
	var x int
	return db.QueryRow(`SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?`, cid, uid).Scan(&x) == nil
}

func chatMembers(cid int64) []int64 {
	rows, _ := db.Query(`SELECT user_id FROM chat_members WHERE chat_id=?`, cid)
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var u int64
		rows.Scan(&u)
		out = append(out, u)
	}
	return out
}

// ==================== HTTP Handlers ====================

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(indexHTML)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if !regLimit.allow(ip(r), 5, time.Hour) {
		errMsg(w, 429, "too many")
		return
	}
	var req struct{ Username string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		errMsg(w, 400, "bad request")
		return
	}
	u := strings.TrimSpace(req.Username)
	if len(u) < 3 || len(u) > 24 {
		errMsg(w, 400, "اسم المستخدم 3-24 حرفاً")
		return
	}
	for _, c := range u {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.'
		if !ok {
			errMsg(w, 400, "أحرف غير مسموحة")
			return
		}
	}
	code := genCode()
	_, err := db.Exec(`INSERT INTO users(username,code_hash,created_at) VALUES(?,?,?)`,
		u, hashCode(code), time.Now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			errMsg(w, 409, "اسم المستخدم محجوز")
			return
		}
		errMsg(w, 500, "خطأ")
		return
	}
	writeJSON(w, 201, map[string]string{"username": u, "code": code})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !loginLimit.allow(ip(r), 10, 15*time.Minute) {
		errMsg(w, 429, "محاولات كثيرة")
		return
	}
	var req struct{ Username, Code string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		errMsg(w, 400, "bad request")
		return
	}
	var id, failed, locked int64
	var ch string
	err := db.QueryRow(`SELECT id,code_hash,failed_count,locked_until FROM users WHERE username=?`,
		strings.TrimSpace(req.Username)).Scan(&id, &ch, &failed, &locked)
	if err != nil {
		errMsg(w, 401, "بيانات غير صحيحة")
		return
	}
	now := time.Now().Unix()
	if locked > now {
		errMsg(w, 429, "الحساب مقفل مؤقتاً")
		return
	}
	if !verifyCode(req.Code, ch) {
		failed++
		var lock2 int64
		if failed >= 5 {
			lock2 = now + 900
			failed = 0
		}
		db.Exec(`UPDATE users SET failed_count=?,locked_until=? WHERE id=?`, failed, lock2, id)
		errMsg(w, 401, "بيانات غير صحيحة")
		return
	}
	db.Exec(`UPDATE users SET failed_count=0,locked_until=0 WHERE id=?`, id)
	tok, th := newToken()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	db.Exec(`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)`, th, id, exp)
	writeJSON(w, 200, map[string]any{
		"token": tok, "user_id": id, "username": req.Username, "expires_at": exp,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokHash(t))
	w.WriteHeader(204)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	var name string
	db.QueryRow(`SELECT username FROM users WHERE id=?`, uid).Scan(&name)
	writeJSON(w, 200, map[string]any{"user_id": uid, "username": name})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	q := r.URL.Query().Get("q")
	rows, _ := db.Query(`SELECT id,username FROM users WHERE username LIKE ? AND id<>? ORDER BY username LIMIT 20`,
		q+"%", uid)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var n string
		rows.Scan(&id, &n)
		out = append(out, map[string]any{"id": id, "username": n})
	}
	writeJSON(w, 200, out)
}

func handleChats(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	rows, _ := db.Query(`
		SELECT c.id, c.type, COALESCE(c.name,''),
		       COALESCE((SELECT m.content FROM messages m WHERE m.chat_id=c.id ORDER BY m.id DESC LIMIT 1),''),
		       COALESCE((SELECT m.created_at FROM messages m WHERE m.chat_id=c.id ORDER BY m.id DESC LIMIT 1),0)
		FROM chats c JOIN chat_members cm ON cm.chat_id=c.id
		WHERE cm.user_id=? ORDER BY 5 DESC, c.id DESC`, uid)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, ts int64
		var typ, name, last string
		rows.Scan(&id, &typ, &name, &last, &ts)
		display := name
		if typ == "direct" {
			db.QueryRow(`SELECT u.username FROM users u JOIN chat_members cm ON cm.user_id=u.id
				WHERE cm.chat_id=? AND u.id<>? LIMIT 1`, id, uid).Scan(&display)
		}
		out = append(out, map[string]any{
			"id": id, "type": typ, "name": display,
			"last_message": last, "last_at": ts,
		})
	}
	writeJSON(w, 200, out)
}

func handleDirect(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	var req struct{ Username string }
	json.NewDecoder(r.Body).Decode(&req)
	var other int64
	if db.QueryRow(`SELECT id FROM users WHERE username=?`, req.Username).Scan(&other) != nil {
		errMsg(w, 404, "المستخدم غير موجود")
		return
	}
	if other == uid {
		errMsg(w, 400, "لا يمكنك محادثة نفسك")
		return
	}
	a, b := uid, other
	if a > b {
		a, b = b, a
	}
	key := strconv.FormatInt(a, 10) + ":" + strconv.FormatInt(b, 10)
	var id int64
	if db.QueryRow(`SELECT id FROM chats WHERE direct_key=?`, key).Scan(&id) == nil {
		writeJSON(w, 200, map[string]int64{"id": id})
		return
	}
	now := time.Now().Unix()
	res, err := db.Exec(`INSERT INTO chats(type,direct_key,created_by,created_at) VALUES('direct',?,?,?)`,
		key, uid, now)
	if err != nil {
		errMsg(w, 500, "خطأ")
		return
	}
	id, _ = res.LastInsertId()
	db.Exec(`INSERT INTO chat_members VALUES(?,?)`, id, uid)
	db.Exec(`INSERT INTO chat_members VALUES(?,?)`, id, other)
	writeJSON(w, 201, map[string]int64{"id": id})
}

func handleGroup(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	var req struct {
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if len(req.Name) < 1 || len(req.Name) > 40 {
		errMsg(w, 400, "اسم المجموعة غير صالح")
		return
	}
	ids := map[int64]bool{uid: true}
	for _, un := range req.Members {
		var mid int64
		if db.QueryRow(`SELECT id FROM users WHERE username=?`, un).Scan(&mid) == nil {
			ids[mid] = true
		}
	}
	if len(ids) < 2 {
		errMsg(w, 400, "أضف مشاركاً واحداً على الأقل")
		return
	}
	now := time.Now().Unix()
	res, _ := db.Exec(`INSERT INTO chats(type,name,created_by,created_at) VALUES('group',?,?,?)`,
		req.Name, uid, now)
	id, _ := res.LastInsertId()
	for m := range ids {
		db.Exec(`INSERT INTO chat_members VALUES(?,?)`, id, m)
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		errMsg(w, 401, "unauthorized")
		return
	}
	cid, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/chats/"), 10, 64)
	if !isMember(uid, cid) {
		errMsg(w, 403, "forbidden")
		return
	}
	rows, _ := db.Query(`SELECT id,sender_id,content,created_at FROM messages
		WHERE chat_id=? ORDER BY id DESC LIMIT 50`, cid)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, sid, ts int64
		var c string
		rows.Scan(&id, &sid, &c, &ts)
		out = append(out, map[string]any{
			"id": id, "chat_id": cid, "sender_id": sid, "content": c, "created_at": ts,
		})
	}
	writeJSON(w, 200, out)
}

// ==================== WebSocket ====================

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	uid := authUser(r)
	if uid == 0 {
		http.Error(w, "unauthorized", 401)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ch := h.add(uid, conn)
	go func() {
		for msg := range ch {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if conn.WriteMessage(websocket.TextMessage, msg) != nil {
				return
			}
		}
	}()
	defer func() {
		h.remove(uid, conn)
		conn.Close()
	}()
	conn.SetReadLimit(8 << 10)
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var m struct {
			Type    string `json:"type"`
			ChatID  int64  `json:"chat_id"`
			Content string `json:"content"`
		}
		if json.Unmarshal(data, &m) != nil || m.Type != "send" {
			continue
		}
		if m.ChatID == 0 || m.Content == "" || len(m.Content) > 2000 {
			continue
		}
		if !msgLimit.allow(strconv.FormatInt(uid, 10), 30, time.Minute) {
			continue
		}
		if !isMember(uid, m.ChatID) {
			continue
		}
		now := time.Now().UnixMilli()
		res, err := db.Exec(`INSERT INTO messages(chat_id,sender_id,content,created_at) VALUES(?,?,?,?)`,
			m.ChatID, uid, m.Content, now)
		if err != nil {
			continue
		}
		mid, _ := res.LastInsertId()
		payload, _ := json.Marshal(map[string]any{
			"type": "message",
			"message": map[string]any{
				"id": mid, "chat_id": m.ChatID, "sender_id": uid,
				"content": m.Content, "created_at": now,
			},
		})
		for _, member := range chatMembers(m.ChatID) {
			h.send(member, payload)
		}
	}
}

// ==================== Main ====================

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "chat.db"
	}
	if err := openDB(dbPath); err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/me", handleMe)
	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/chats", handleChats)
	mux.HandleFunc("/api/chats/direct", handleDirect)
	mux.HandleFunc("/api/chats/group", handleGroup)
	mux.HandleFunc("/api/chats/", handleMessages)
	mux.HandleFunc("/ws", handleWS)

	log.Println("listening on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
