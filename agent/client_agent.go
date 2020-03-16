package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

type rpcFunc func(LdapMsg) LdapResp
type mapRPCFunc map[string]rpcFunc

type agentClient struct {
	closed bool
	rpcOps chan func(mapRPCFunc)
	conn   *websocket.Conn
}

func newAgentClient(rpc mapRPCFunc, conn *websocket.Conn) *agentClient {
	a := &agentClient{
		conn:   conn,
		rpcOps: make(chan func(mapRPCFunc), 1),
	}
	go a.serveRPC(rpc)
	return a
}

func (a *agentClient) Listen(ctx context.Context) error {
	defer a.conn.Close()
	defer a.close()
	conn := a.conn
	pongWait := agentPongWait
	pingPeriod := agentPingPeriod
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(pongWait)) })

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-time.After(pingPeriod):
				_ = conn.SetWriteDeadline(time.Now().Add(agentWriteWait))
				er := conn.WriteMessage(websocket.PingMessage, []byte{})
				if er != nil {
					log.Println("ping", er)
				}
			case <-done:
				return
			case <-ctx.Done():
				a.close()
				return
			}
		}
	}()

	var err error
LOOP:
	for {
		mt, msg, e := conn.ReadMessage()
		if e != nil {
			if _, ok := e.(*websocket.CloseError); ok {
				break LOOP
			}
			err = e
			break LOOP
		}
		switch mt {
		case websocket.CloseMessage:
			break LOOP
		case websocket.TextMessage:
			msg = bytes.TrimSpace(bytes.Replace(msg, []byte{'\n'}, []byte{' '}, -1))
			resp := a.doRPC(msg)
			err = a.write(resp)
			if err != nil {
				break LOOP
			}
		}
	}
	return err
}

func (a *agentClient) write(resp LdapResp) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return errors.Wrapf(err, "resp json encode: %+v", resp)
	}
	_ = a.conn.SetWriteDeadline(time.Now().Add(agentWriteWait))
	return a.conn.WriteMessage(websocket.TextMessage, payload)
}

func (a *agentClient) doRPC(msg []byte) (resp LdapResp) {
	req := LdapMsg{}
	defer func() {
		resp.GUID = req.GUID
	}()
	if e := json.Unmarshal(msg, &req); e != nil {
		resp.Err = errors.Wrapf(e, "wrong msg format; msg: %s", string(msg)).Error()
		return
	}
	done := make(chan struct{})
	a.rpcOps <- func(rpc mapRPCFunc) {
		defer close(done)
		f, ok := rpc[req.Method]
		if !ok {
			resp.Err = errors.New("wrong ldap rpc method : " + req.Method).Error()
			return
		}
		resp = f(req)
	}
	<-done
	return
}

func (a *agentClient) serveRPC(rs mapRPCFunc) {
	for op := range a.rpcOps {
		op(rs)
	}
	for id := range rs {
		delete(rs, id)
	}
}

func (a *agentClient) close() {
	if a.closed {
		return
	}
	log.Println("agent close")
	a.closed = true
	close(a.rpcOps)
	timeout := 3 * time.Second
	_ = a.conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(timeout))
}
