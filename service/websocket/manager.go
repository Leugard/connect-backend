package websocket

import (
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type Manager struct {
	Clients map[uuid.UUID][]*websocket.Conn
	mu      sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		Clients: make(map[uuid.UUID][]*websocket.Conn),
	}
}

func (m *Manager) Add(userID uuid.UUID, conn *websocket.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Clients[userID] = append(m.Clients[userID], conn)
}

func (m *Manager) Remove(userID uuid.UUID, conn *websocket.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	conns := m.Clients[userID]
	for i, c := range conns {
		if c == conn {
			m.Clients[userID] = append(conns[:i], conns[i+1:]...)
			break
		}
	}

	if len(m.Clients[userID]) == 0 {
		delete(m.Clients, userID)
	}
}

func (m *Manager) Send(userID uuid.UUID, data any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, conn := range m.Clients[userID] {
		_ = conn.WriteJSON(data)
	}
}

func (m *Manager) IsOnline(userID uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.Clients[userID]
	return ok
}
