package agent

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/shubinmi/util/errs"
)

type LdapRPC func(agentId string, msg LdapMsg) (LdapResp, error)

type LdapServer struct {
	agent   *agentServer
	timeout time.Duration
}

func Server(timeout time.Duration) *LdapServer {
	return &LdapServer{
		agent:   newAgentServer(),
		timeout: timeout,
	}
}

func (s *LdapServer) Run(ctx context.Context, addr, path string) error {
	mux := http.NewServeMux()
	s.ReachMux(mux, path)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		log.Println("trying to stop ldap ws LdapServer")
		ctx1, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		if e := srv.Shutdown(ctx1); e != nil {
			log.Println("ldap ws LdapServer shutdown", e)
		}
		log.Println("ldap ws LdapServer done")
	}()
	log.Println("start ldap ws LdapServer")
	return srv.ListenAndServe()
}

func (s *LdapServer) ReachMux(mux *http.ServeMux, path string) {
	mux.Handle(path, http.HandlerFunc(s.agent.Handler))
}

func (s *LdapServer) RPC(agentID string, msg LdapMsg) (LdapResp, error) {
	var r LdapResp
	res := make(chan LdapResp)
	defer close(res)
	err := s.agent.Send(agentID, msg, res)
	if err != nil {
		return r, err
	}
	select {
	case <-time.After(s.timeout):
		err = errs.WithState(ErrTimeout, "ldap rpc timeout")
	case r = <-res:
	}
	return r, err
}

func (s *LdapServer) Close() {
	s.agent.Close()
}
