package agent

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

type RPCFunc func(params string) (data string, err error)

type LdapClient struct {
	agent *agentClient
}

func Client(agentID, addr, path string, rpc map[string]RPCFunc) (*LdapClient, error) {
	u := url.URL{Scheme: "ws", Host: addr, Path: path}
	log.Printf("connecting to %s with id = %s", u.String(), agentID)
	header := http.Header{}
	header.Set(identifyHeader, agentID)
	conn, rb, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return nil, err
	}
	_ = rb.Body.Close()
	return &LdapClient{
		agent: newAgentClient(convert(rpc), conn),
	}, nil
}

func (c *LdapClient) Serve(ctx context.Context) error {
	return c.agent.Listen(ctx)
}

func convert(rpc map[string]RPCFunc) mapRPCFunc {
	res := make(mapRPCFunc, len(rpc))
	for n, f := range rpc {
		name, fun := n, f
		res[name] = func(msg LdapMsg) (lr LdapResp) {
			data, err := fun(msg.Params)
			if err != nil {
				lr.Err = err.Error()
			}
			lr.Data = data
			lr.GUID = msg.GUID
			return
		}
	}
	return res
}
