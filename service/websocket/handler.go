package websocket

import (
	"log"
	"net/http"
	"time"

	"github.com/Leugard/connect-backend/middleware"
	"github.com/Leugard/connect-backend/types"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type Handler struct {
	Store   types.UserStore
	Manager *Manager
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("websocket upgrade error:", err.Error())
		return
	}

	userID := r.Context().Value(middleware.UserIDKey).(string)
	user, _ := uuid.Parse(userID)
	h.Manager.Add(user, conn)
	defer h.Manager.Remove(user, conn)
	defer conn.Close()

	for {
		var payload struct {
			ReceiverID string `json:"receiverId"`
			Content    string `json:"content"`
			ImageURL   string `json:"imageUrl"`
		}
		err := conn.ReadJSON(&payload)
		if err != nil {
			log.Println("read error:", err.Error())
			break
		}

		receiverID, err := uuid.Parse(payload.ReceiverID)
		if err != nil {
			continue
		}

		isFriend, err := h.Store.AreFriends(user, receiverID)
		if err != nil || !isFriend {
			continue
		}

		convoID, err := h.Store.GetOrCreateConversation(user, receiverID)
		if err != nil {
			continue
		}

		err = h.Store.SendMessage(convoID, user, payload.Content, payload.ImageURL)
		if err != nil {
			continue
		}

		message := map[string]any{
			"from":           user.String(),
			"content":        payload.Content,
			"imageUrl":       payload.ImageURL,
			"createdAt":      time.Now(),
			"conversationId": convoID.String(),
		}

		h.Manager.Send(receiverID, message)
		h.Manager.Send(user, message)
	}
}
