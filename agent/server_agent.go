package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/shubinmi/util/errs"
	"github.com/shubinmi/util/exec"
	"golang.org/x/exp/rand"
)

const (
	identifyHeader = "X-LDAP-URI"
	maxMsgSize     = 1024
	maxRand        = 100
)

// noinspection GoUnusedConst
const (
	ErrUnknown uint8 = iota
	ErrNoAgent
	ErrTimeout
)

type mapWsConn map[string]map[string]*websocket.Conn
type mapRPC map[string]chan<- LdapResp

type agentServer struct {
	connOps chan func(mapWsConn)
	rpcOps  chan func(mapRPC)
}

func newAgentServer() *agentServer {
	a := &agentServer{
		connOps: make(chan func(conn mapWsConn), 1),
		rpcOps:  make(chan func(conn mapRPC), 1),
	}
	go a.serveRPC()
	go a.serveConnOps()
	return a
}

func (a *agentServer) Send(id string, msg LdapMsg, response chan<- LdapResp) (err error) {
	if msg.GUID == "" {
		msg.GUID = uuid.NewV4().String()
	}
	done := make(chan struct{})
	a.connOps <- func(cs mapWsConn) {
		defer close(done)
		wss, ok := cs[id]
		if !ok {
			err = errs.WithState(ErrNoAgent, "cannot find conn with id: "+id)
			return
		}
		t, e := json.Marshal(msg)
		if e != nil {
			err = errs.Merge(e, errors.Errorf("msg to json: %+v", msg))
			return
		}
		if response != nil {
			err = a.withRPCRespond(msg.GUID, response)
			if err != nil {
				return
			}
		}
		fs := make([]func() bool, 0, len(wss))
		for _, c := range wss {
			cn := c
			fs = append(fs, func() bool {
				_ = cn.SetWriteDeadline(time.Now().Add(agentWriteWait))
				err = cn.WriteMessage(websocket.TextMessage, t)
				return err == nil
			})
		}
		exec.UntilSuccess(fs...)
		if err == nil {
			return
		}
		// if err we should clean rpc map
		if response != nil {
			a.rpcResponded(msg.GUID)
		}
	}
	<-done
	return err
}

func (a *agentServer) Handler(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(identifyHeader)
	if id == "" {
		http.Error(w, "empty identify header", http.StatusBadRequest)
		return
	}
	wsUp := websocket.Upgrader{
		ReadBufferSize:  maxMsgSize,
		WriteBufferSize: maxMsgSize,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	conn, err := wsUp.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			log.Println("LdapServer agent recover", r)
		}
	}()

	seed := a.addConn(id, conn)
	defer a.removeConn(id, seed)
	err = a.serveConn(conn)
	if err != nil {
		log.Println("serve conn", err)
		return
	}
}

func (a *agentServer) removeConn(id, seed string) {
	done := make(chan struct{})
	a.connOps <- func(cs mapWsConn) {
		defer close(done)
		_, ok := cs[id]
		if !ok {
			return
		}
		_, ok = cs[id][seed]
		if !ok {
			return
		}
		delete(cs[id], seed)
		if len(cs[id]) > 0 {
			return
		}
		delete(cs, id)
	}
	<-done
}

func (a *agentServer) addConn(id string, conn *websocket.Conn) (seed string) {
	done := make(chan struct{})
	seed = fmt.Sprint(time.Now()) + fmt.Sprint(rand.Intn(maxRand))
	a.connOps <- func(cs mapWsConn) {
		defer close(done)
		_, ok := cs[id]
		if !ok {
			cs[id] = map[string]*websocket.Conn{seed: conn}
			return
		}
		cs[id][seed] = conn
	}
	<-done
	return
}

func (a *agentServer) serveConn(conn *websocket.Conn) error {
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
			if e = a.deliverRPCRespond(msg); e != nil {
				log.Println("deliver rpc", e)
			}
		}
	}
	return err
}

func (a *agentServer) deliverRPCRespond(msg []byte) (err error) {
	res := LdapResp{}
	if e := json.Unmarshal(msg, &res); e != nil {
		return errors.Wrapf(e, "wrong response format; msg: %s", string(msg))
	}
	done := make(chan struct{})
	a.rpcOps <- func(rpc mapRPC) {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				err = errors.Errorf(fmt.Sprint("recovered in deliverRPCRespond", r)+"; msg: %s", string(msg))
			}
		}()
		sender, ok := rpc[res.GUID]
		if !ok {
			err = errors.New("wrong guid to respond: " + res.GUID)
			return
		}
		sender <- res
	}
	<-done
	a.rpcResponded(res.GUID)
	return
}

func (a *agentServer) rpcResponded(guid string) {
	done := make(chan struct{})
	a.rpcOps <- func(rpc mapRPC) {
		defer close(done)
		if _, ok := rpc[guid]; !ok {
			return
		}
		delete(rpc, guid)
	}
	<-done
}

func (a *agentServer) withRPCRespond(guid string, response chan<- LdapResp) (err error) {
	done := make(chan struct{})
	a.rpcOps <- func(rpc mapRPC) {
		defer close(done)
		if _, ok := rpc[guid]; ok {
			err = errors.New("guid rpc already exist: " + guid)
			return
		}
		rpc[guid] = response
	}
	<-done
	return
}

func (a *agentServer) serveRPC() {
	rs := make(mapRPC)
	for op := range a.rpcOps {
		op(rs)
	}
	for id := range rs {
		delete(rs, id)
	}
}

func (a *agentServer) serveConnOps() {
	cs := make(mapWsConn)
	for op := range a.connOps {
		op(cs)
	}
	for id := range cs {
		for seed, c := range cs[id] {
			if c != nil {
				_ = c.WriteMessage(websocket.CloseMessage, []byte{})
				_ = c.Close()
			}
			delete(cs[id], seed)
		}
		delete(cs, id)
	}
}

func (a *agentServer) Close() {
	log.Println("agent close")
	close(a.rpcOps)
	close(a.connOps)
}
