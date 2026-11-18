package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrUsernameExists = errors.New("用户名已存在")
	ErrDeviceExists   = errors.New("设备 ID 已存在")
	ErrDeviceNotFound = errors.New("设备不存在")
	ErrUserNotFound   = errors.New("用户不存在")
)

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// validateDeviceID 限制设备 ID 为安全的文件名字符，防止路径穿越。
func validateDeviceID(id string) bool {
	return deviceIDPattern.MatchString(id) && !strings.Contains(id, "..")
}

type metaData struct {
	Users   []*User   `json:"users"`
	Devices []*Device `json:"devices"`
}

// Store 基于文件的持久化存储：
//   - meta.json 保存用户与设备（低频写，原子替换）
//   - messages/<deviceID>.jsonl 每个设备一个 append-only 文件（高频写，同步落盘）
//
// 明文短信、明文 token、明文密码哈希、明文用户名/邮箱/设备 ID 与名称均不落盘：
// 短信落盘密文与 nonce；token 落盘哈希 + 内置密钥密文；
// 登录凭证、用户名、邮箱、设备 ID、设备名称均落盘为内置密钥密文（按所属实体绑定），
// 另存不可逆 HMAC 索引用于查找与消息文件命名。
// 加密密钥编译在二进制中，攻击者仅拿到 data 目录无法解密或伪造凭证。
type Store struct {
	mu              sync.RWMutex
	dataDir         string
	msgDir          string
	legacyMasterKey []byte // 旧版主密钥，仅用于一次性迁移 token_enc
	users           map[string]*User
	usersByName     map[string]*User
	usersByEmail    map[string]*User // key 为 EmailHash（HMAC），避免按邮箱全表扫描
	usersByTok      map[string]*User // key 为 tokenHash，而非明文 token
	devices         map[string]*Device
	messages        map[string][]Message
}

// NewStore 打开存储。legacyKey 为旧版 config.ini 主密钥，可为 nil，仅用于迁移旧数据。
func NewStore(dataDir string, legacyKey []byte) (*Store, error) {
	msgDir := filepath.Join(dataDir, "messages")
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	s := &Store{
		dataDir:         dataDir,
		msgDir:          msgDir,
		legacyMasterKey: legacyKey,
		users:           make(map[string]*User),
		usersByName:     make(map[string]*User),
		usersByEmail:    make(map[string]*User),
		usersByTok:      make(map[string]*User),
		devices:         make(map[string]*Device),
		messages:        make(map[string][]Message),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	metaPath := filepath.Join(s.dataDir, "meta.json")
	b, err := os.ReadFile(metaPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("读取 meta.json 失败: %w", err)
	}
	var meta metaData
	if len(b) > 0 {
		if err := json.Unmarshal(b, &meta); err != nil {
			return fmt.Errorf("解析 meta.json 失败: %w", err)
		}
	}
	needSave := false
	for _, u := range meta.Users {
		// 兼容旧版 meta.json：明文 token -> SHA-256 哈希 + 内置密钥密文。
		if u.Token != "" {
			plain := u.Token
			u.TokenHash = tokenHash(plain)
			enc, err := encryptToken(plain)
			if err != nil {
				return fmt.Errorf("迁移用户 %s 的 token 失败: %w", u.ID, err)
			}
			u.TokenEnc = enc
			u.Token = ""
			needSave = true
		} else if u.TokenEnc != "" {
			// 旧版用 config.ini [security] key 加密的 token_enc：内置密钥解不开时，
			// 用遗留密钥解出明文再用内置密钥重加密，一次迁移后不再依赖文件 key。
			if _, err := decryptToken(u.TokenEnc); err != nil && len(s.legacyMasterKey) > 0 {
				plain, lerr := decryptTokenWithKey(s.legacyMasterKey, u.TokenEnc)
				if lerr == nil {
					enc, rerr := encryptToken(plain)
					if rerr != nil {
						return fmt.Errorf("重加密用户 %s 的 token 失败: %w", u.ID, rerr)
					}
					u.TokenEnc = enc
					if u.TokenHash == "" {
						u.TokenHash = tokenHash(plain)
					}
					needSave = true
				}
			}
		}
		// 用户名：密文还原为运行时明文；旧明文迁移为密文。
		if u.Username == "" && u.UsernameEnc != "" {
			if name, err := decryptField("username", u.ID, u.UsernameEnc); err == nil {
				u.Username = name
			}
		}
		if u.Username == "" && u.LegacyUsername != "" {
			u.Username = u.LegacyUsername
		}
		if u.Username != "" {
			if u.UsernameEnc == "" {
				enc, err := encryptField("username", u.ID, u.Username)
				if err != nil {
					return fmt.Errorf("加密用户 %s 名失败: %w", u.ID, err)
				}
				u.UsernameEnc = enc
				needSave = true
			}
			u.UsernameHash = fieldIndex(u.Username)
			if u.LegacyUsername != "" {
				u.LegacyUsername = ""
				needSave = true
			}
		}
		// 兼容旧版 meta.json：明文 password_hash + salt -> 内置密钥加密的 cred_enc。
		if u.CredEnc == "" && (u.PasswordHash != "" || u.Salt != "") {
			enc, err := encryptCredential(u.ID, u.Username, u.PasswordHash, u.Salt)
			if err != nil {
				return fmt.Errorf("迁移用户 %s 的登录凭证失败: %w", u.ID, err)
			}
			u.CredEnc = enc
			needSave = true
		}
		if u.PasswordHash != "" || u.Salt != "" {
			u.PasswordHash, u.Salt = "", ""
			needSave = true
		}
		// 邮箱：密文还原为运行时明文；旧明文迁移为密文。
		if u.Email == "" && u.EmailEnc != "" {
			if em, err := decryptField("email", u.ID, u.EmailEnc); err == nil {
				u.Email = em
			}
		}
		if u.Email == "" && u.LegacyEmail != "" {
			u.Email = u.LegacyEmail
		}
		if u.Email != "" {
			if u.EmailEnc == "" {
				enc, err := encryptField("email", u.ID, u.Email)
				if err != nil {
					return fmt.Errorf("加密用户 %s 邮箱失败: %w", u.ID, err)
				}
				u.EmailEnc = enc
				needSave = true
			}
			u.EmailHash = fieldIndex(strings.ToLower(u.Email))
			s.usersByEmail[u.EmailHash] = u
			if u.LegacyEmail != "" {
				u.LegacyEmail = ""
				needSave = true
			}
		}
		s.users[u.ID] = u
		if u.Username != "" {
			s.usersByName[u.Username] = u
		}
		if u.TokenHash != "" {
			s.usersByTok[u.TokenHash] = u
		}
	}

	for _, d := range meta.Devices {
		if d.ID == "" && d.IDEnc != "" {
			if id, err := decryptField("device", d.UserID, d.IDEnc); err == nil {
				d.ID = id
			}
		}
		if d.ID == "" && d.LegacyID != "" {
			d.ID = d.LegacyID
		}
		if d.ID == "" {
			continue
		}
		if d.IDEnc == "" {
			enc, err := encryptField("device", d.UserID, d.ID)
			if err != nil {
				return fmt.Errorf("加密设备 %s ID 失败: %w", d.ID, err)
			}
			d.IDEnc = enc
			needSave = true
		}
		d.IDHash = fieldIndex(d.ID)
		if d.LegacyID != "" {
			d.LegacyID = ""
			needSave = true
		}
		if d.Name == "" && d.NameEnc != "" {
			if name, err := decryptField("devicename", d.ID, d.NameEnc); err == nil {
				d.Name = name
			}
		}
		if d.Name == "" && d.LegacyName != "" {
			d.Name = d.LegacyName
		}
		if d.Name != "" {
			if d.NameEnc == "" {
				enc, err := encryptField("devicename", d.ID, d.Name)
				if err != nil {
					return fmt.Errorf("加密设备 %s 名称失败: %w", d.ID, err)
				}
				d.NameEnc = enc
				needSave = true
			}
			if d.LegacyName != "" {
				d.LegacyName = ""
				needSave = true
			}
		}
		s.devices[d.ID] = d
	}

	// 消息文件名：旧版为明文设备 ID，迁移为 ID 的 HMAC 哈希，避免泄露设备 ID。
	byHash := make(map[string]string, len(s.devices))
	for id := range s.devices {
		byHash[fieldIndex(id)] = id
	}
	entries, err := os.ReadDir(s.msgDir)
	if err != nil {
		return fmt.Errorf("读取消息目录失败: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".jsonl")
		readPath := filepath.Join(s.msgDir, e.Name())
		devID, ok := byHash[base]
		if !ok {
			// 旧版明文文件名：按设备 ID 匹配并迁移文件名
			if _, exists := s.devices[base]; !exists {
				continue
			}
			devID = base
			newPath := s.msgPath(devID)
			if newPath != readPath {
				if err := os.Rename(readPath, newPath); err != nil {
					return fmt.Errorf("迁移设备 %s 消息文件失败: %w", devID, err)
				}
				readPath = newPath
			}
		}
		raw, err := os.ReadFile(readPath)
		if err != nil {
			return fmt.Errorf("读取设备 %s 消息失败: %w", devID, err)
		}
		var msgs []Message
		msgMigrated := false
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var m Message
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				return fmt.Errorf("解析设备 %s 消息失败: %w", devID, err)
			}
			m.DeviceID = devID // 运行时明文，不落盘
			// 发送方号码：密文还原为运行时明文；旧明文迁移为密文。
			if m.Sender == "" && m.SenderEnc != "" {
				if s, err := decryptField("msgsender", devID, m.SenderEnc); err == nil {
					m.Sender = s
				}
			}
			if m.Sender == "" && m.LegacySender != "" {
				m.Sender = m.LegacySender
			}
			if m.Sender != "" {
				if m.SenderEnc == "" {
					enc, err := encryptField("msgsender", devID, m.Sender)
					if err != nil {
						return fmt.Errorf("加密设备 %s 发送方号码失败: %w", devID, err)
					}
					m.SenderEnc = enc
					msgMigrated = true
				}
				if m.LegacySender != "" {
					m.LegacySender = ""
					msgMigrated = true
				}
			}
			msgs = append(msgs, m)
		}
		if msgMigrated {
			var buf strings.Builder
			for _, m := range msgs {
				line, err := json.Marshal(m)
				if err != nil {
					return fmt.Errorf("序列化设备 %s 消息失败: %w", devID, err)
				}
				buf.Write(line)
				buf.WriteByte('\n')
			}
			if err := os.WriteFile(readPath, []byte(buf.String()), 0600); err != nil {
				return fmt.Errorf("迁移设备 %s 消息失败: %w", devID, err)
			}
		}
		s.messages[devID] = msgs
	}
	if needSave {
		if err := s.saveMetaLocked(); err != nil {
			return fmt.Errorf("迁移数据后保存 meta.json 失败: %w", err)
		}
	}
	return nil
}

func (s *Store) saveMetaLocked() error {
	// 落盘前把运行时明文字段统一加密，并生成不可逆索引；明文永不写入文件。
	for _, u := range s.users {
		if u.Username != "" {
			enc, err := encryptField("username", u.ID, u.Username)
			if err != nil {
				return err
			}
			u.UsernameEnc = enc
			u.UsernameHash = fieldIndex(u.Username)
		}
		if u.Email != "" {
			enc, err := encryptField("email", u.ID, u.Email)
			if err != nil {
				return err
			}
			u.EmailEnc = enc
			u.EmailHash = fieldIndex(strings.ToLower(u.Email))
		}
	}
	for _, d := range s.devices {
		if d.ID != "" {
			enc, err := encryptField("device", d.UserID, d.ID)
			if err != nil {
				return err
			}
			d.IDEnc = enc
			d.IDHash = fieldIndex(d.ID)
		}
		if d.Name != "" {
			enc, err := encryptField("devicename", d.ID, d.Name)
			if err != nil {
				return err
			}
			d.NameEnc = enc
		}
	}
	meta := metaData{
		Users:   make([]*User, 0, len(s.users)),
		Devices: make([]*Device, 0, len(s.devices)),
	}
	for _, u := range s.users {
		meta.Users = append(meta.Users, u)
	}
	for _, d := range s.devices {
		meta.Devices = append(meta.Devices, d)
	}
	sort.Slice(meta.Users, func(i, j int) bool { return meta.Users[i].ID < meta.Users[j].ID })
	sort.Slice(meta.Devices, func(i, j int) bool { return meta.Devices[i].ID < meta.Devices[j].ID })

	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dataDir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return fmt.Errorf("写入 meta 临时文件失败: %w", err)
	}
	return os.Rename(tmp, filepath.Join(s.dataDir, "meta.json"))
}

// msgPath 用设备 ID 的 HMAC 哈希作为文件名，避免明文设备 ID 出现在文件系统中。
func (s *Store) msgPath(deviceID string) string {
	return filepath.Join(s.msgDir, fieldIndex(deviceID)+".jsonl")
}

// ---- 用户 ----

func (s *Store) CreateUser(username, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByName[username]; ok {
		return nil, ErrUsernameExists
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	token, err := randomID()
	if err != nil {
		return nil, err
	}
	th := tokenHash(token)
	enc, err := encryptToken(token)
	if err != nil {
		return nil, err
	}
	hash, salt, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	cred, err := encryptCredential(id, username, hash, salt)
	if err != nil {
		return nil, err
	}
	u := &User{
		ID: id, Username: username, CredEnc: cred,
		TokenHash: th, TokenEnc: enc, TokenPlain: token,
		CreatedAt: time.Now().UTC(),
	}
	s.users[id] = u
	s.usersByName[username] = u
	s.usersByTok[th] = u
	if err := s.saveMetaLocked(); err != nil {
		delete(s.users, id)
		delete(s.usersByName, username)
		delete(s.usersByTok, th)
		return nil, err
	}
	return u, nil
}

// CreateUserWithToken 供初始化超级管理员时使用（可指定 token）。
func (s *Store) CreateUserWithToken(username, password, token string) (*User, error) {
	if token == "" {
		var err error
		token, err = randomID()
		if err != nil {
			return nil, err
		}
	}
	th := tokenHash(token)
	enc, err := encryptToken(token)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByName[username]; ok {
		return nil, ErrUsernameExists
	}
	if _, ok := s.usersByTok[th]; ok {
		return nil, errors.New("token 已存在")
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	hash, salt, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	cred, err := encryptCredential(id, username, hash, salt)
	if err != nil {
		return nil, err
	}
	u := &User{
		ID: id, Username: username, CredEnc: cred,
		TokenHash: th, TokenEnc: enc, TokenPlain: token,
		CreatedAt: time.Now().UTC(),
	}
	s.users[id] = u
	s.usersByName[username] = u
	s.usersByTok[th] = u
	if err := s.saveMetaLocked(); err != nil {
		delete(s.users, id)
		delete(s.usersByName, username)
		delete(s.usersByTok, th)
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

func (s *Store) GetUserByToken(token string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByTok[tokenHash(token)]
}

// DecryptToken 还原用户 token，仅供服务端解密短信使用，绝不返回给前端。
func (s *Store) DecryptToken(u *User) (string, error) {
	if u.TokenPlain != "" {
		return u.TokenPlain, nil
	}
	if u.TokenEnc != "" {
		return decryptToken(u.TokenEnc)
	}
	if u.Token != "" {
		return u.Token, nil
	}
	return "", errors.New("用户 token 不存在")
}

func (s *Store) Authenticate(username, password string) *User {
	s.mu.RLock()
	u := s.usersByName[username]
	if u == nil || u.CredEnc == "" {
		s.mu.RUnlock()
		return nil
	}
	// 在锁内取字段快照，避免与 UpdatePassword 并发读写 CredEnc 产生 data race。
	id, uname, cred := u.ID, u.Username, u.CredEnc
	s.mu.RUnlock()
	hash, salt, err := decryptCredential(id, uname, cred)
	if err != nil || !verifyPassword(password, hash, salt) {
		return nil
	}
	return u
}

// UserEmail 在锁内读取用户邮箱，避免与 UpdateEmail 并发读写产生 data race。
func (s *Store) UserEmail(userID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u := s.users[userID]; u != nil {
		return u.Email
	}
	return ""
}

func (s *Store) FindUserByEmail(email string) *User {
	if email == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByEmail[fieldIndex(strings.ToLower(email))]
}

func (s *Store) UpdatePassword(userID, hash, salt string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	enc, err := encryptCredential(u.ID, u.Username, hash, salt)
	if err != nil {
		return err
	}
	old := u.CredEnc
	u.CredEnc = enc
	if err := s.saveMetaLocked(); err != nil {
		u.CredEnc = old
		return err
	}
	return nil
}

func (s *Store) UpdateEmail(userID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	oldEmail, oldHash := u.Email, u.EmailHash
	newHash := ""
	if email != "" {
		newHash = fieldIndex(strings.ToLower(email))
	}
	u.Email, u.EmailHash = email, newHash
	if oldHash != "" {
		delete(s.usersByEmail, oldHash)
	}
	if newHash != "" {
		s.usersByEmail[newHash] = u
	}
	if err := s.saveMetaLocked(); err != nil {
		u.Email, u.EmailHash = oldEmail, oldHash
		if oldHash != "" {
			s.usersByEmail[oldHash] = u
		}
		if newHash != "" {
			delete(s.usersByEmail, newHash)
		}
		return err
	}
	return nil
}

// ---- 设备 ----

func (s *Store) CreateDevice(userID, id, name string) (*Device, error) {
	if !validateDeviceID(id) {
		return nil, errors.New("设备 ID 只能包含字母、数字、下划线、点和连字符，且以字母或数字开头，长度 1-64")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; ok {
		return nil, ErrDeviceExists
	}
	d := &Device{ID: id, UserID: userID, Name: name, CreatedAt: time.Now().UTC()}
	s.devices[id] = d
	if err := s.saveMetaLocked(); err != nil {
		delete(s.devices, id)
		return nil, err
	}
	return d, nil
}

func (s *Store) GetDevice(id string) *Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devices[id]
}

// deviceDTO 包含设备信息及派生的最后活跃时间。
type deviceDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
	Preview   string    `json:"preview"` // 最后一条短信明文（由 handler 解密填充）
	Online    bool      `json:"online"`  // 20 秒内有心跳即在线
}

func (s *Store) ListDevices(userID string) []deviceDTO {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]deviceDTO, 0)
	for _, d := range s.devices {
		if d.UserID != userID {
			continue
		}
		msgs := s.messages[d.ID]
		dto := deviceDTO{ID: d.ID, Name: d.Name, CreatedAt: d.CreatedAt, LastSeen: d.CreatedAt, Count: len(msgs)}
		if len(msgs) > 0 {
			dto.LastSeen = msgs[len(msgs)-1].CreatedAt
		}
		out = append(out, dto)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// LastMessage 返回设备最后一条短信（仍为密文）。
func (s *Store) LastMessage(deviceID string) (Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	msgs := s.messages[deviceID]
	if len(msgs) == 0 {
		return Message{}, false
	}
	return msgs[len(msgs)-1], true
}

func (s *Store) DeleteDevice(userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok || d.UserID != userID {
		return ErrDeviceNotFound
	}
	if err := os.Remove(s.msgPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.devices, id)
	delete(s.messages, id)
	if err := s.saveMetaLocked(); err != nil {
		s.devices[id] = d
		return err
	}
	return nil
}

// ---- 短信 ----

func (s *Store) AddMessage(m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[m.DeviceID]; !ok {
		return ErrDeviceNotFound
	}
	// 发送方号码加密落盘，绑定设备 ID，明文只保留在运行时。
	if m.Sender != "" {
		enc, err := encryptField("msgsender", m.DeviceID, m.Sender)
		if err != nil {
			return fmt.Errorf("加密发送方号码失败: %w", err)
		}
		m.SenderEnc = enc
	}
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.msgPath(m.DeviceID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("打开消息文件失败: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("写入消息失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("同步消息失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.messages[m.DeviceID] = append(s.messages[m.DeviceID], m)
	return nil
}

// ListMessages 返回按时间倒序分页的短信。
func (s *Store) ListMessages(deviceID string, page, size int) ([]Message, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.messages[deviceID]
	total := len(all)
	start := (page - 1) * size
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	res := make([]Message, 0, end-start)
	for i := end - 1; i >= start; i-- {
		res = append(res, all[i])
	}
	return res, total
}

func (s *Store) ClearMessages(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(s.msgPath(deviceID), nil, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.messages[deviceID] = nil
	return nil
}
