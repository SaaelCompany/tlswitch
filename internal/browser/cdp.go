package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/coder/websocket"
)

type cdpConn struct {
	conn    *websocket.Conn
	mu      sync.Mutex
	writeMu sync.Mutex
	next    int
	pending map[int]chan cdpMessage
	onEvent func(method string, params json.RawMessage)
	done    chan struct{}
}

type cdpMessage struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func dialCDP(ctx context.Context, wsURL string) (*cdpConn, error) {
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(32 << 20)
	c := &cdpConn{
		conn:    conn,
		pending: map[int]chan cdpMessage{},
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

func (c *cdpConn) readLoop() {
	defer close(c.done)
	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			c.failAll(err)
			return
		}
		var msg cdpMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method != "" && c.onEvent != nil {
			method, params := msg.Method, msg.Params
			go c.onEvent(method, params)
		}
	}
}

func (c *cdpConn) failAll(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		ch <- cdpMessage{ID: id, Error: &struct {
			Message string `json:"message"`
		}{Message: err.Error()}}
		delete(c.pending, id)
	}
}

func (c *cdpConn) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	msg, err := c.send(ctx, method, params, true)
	if err != nil {
		return nil, err
	}
	if msg.Error != nil {
		return nil, errors.New(msg.Error.Message)
	}
	return msg.Result, nil
}

func (c *cdpConn) Notify(method string, params any) {
	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	_, _ = c.send(ctx, method, params, false)
}

func (c *cdpConn) send(ctx context.Context, method string, params any, wait bool) (cdpMessage, error) {
	c.mu.Lock()
	c.next++
	id := c.next
	var ch chan cdpMessage
	if wait {
		ch = make(chan cdpMessage, 1)
		c.pending[id] = ch
	}
	c.mu.Unlock()
	body, err := json.Marshal(struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params"`
	}{id, method, params})
	if err != nil {
		return cdpMessage{}, err
	}
	c.writeMu.Lock()
	err = c.conn.Write(ctx, websocket.MessageText, body)
	c.writeMu.Unlock()
	if err != nil {
		return cdpMessage{}, err
	}
	if !wait {
		return cdpMessage{}, nil
	}
	select {
	case <-ctx.Done():
		return cdpMessage{}, ctx.Err()
	case <-c.done:
		return cdpMessage{}, errors.New("соединение с браузером закрыто")
	case msg := <-ch:
		return msg, nil
	}
}

func (c *cdpConn) Close() {
	c.writeMu.Lock()
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	c.writeMu.Unlock()
}

func paramsJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func unmarshal[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 {
		return v, fmt.Errorf("пустой ответ")
	}
	err := json.Unmarshal(raw, &v)
	return v, err
}
