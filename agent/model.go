package agent

import "time"

type LdapMsg struct {
	GUID   string
	Method string
	Params string
}

type LdapResp struct {
	GUID string
	Data string
	Err  string
}

type RPCAuth struct {
	Login string
	Pass  string
}

type RPCPag struct {
	PerPage uint32
	PageNum uint32
}

type RPCPagGql struct {
	PerPage int
	PageNum int
}

func (p RPCPagGql) ToPag() RPCPag {
	return RPCPag{
		PerPage: uint32(p.PerPage),
		PageNum: uint32(p.PageNum),
	}
}

type RPCNodeUsers struct {
	ID     string
	Pag    RPCPag
	PagGql RPCPagGql
}

func (nu *RPCNodeUsers) LoadPag() {
	nu.Pag = nu.PagGql.ToPag()
}

const (
	agentPongWait   = 60 * time.Second
	agentPingPeriod = (agentPongWait * 8) / 10
	agentWriteWait  = 10 * time.Second
)
