package agent

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/shubinmi/ldap"
)

type rpcClient struct {
	client *ldap.Client
	funcs  map[string]RPCFunc
}

const (
	RPCAuthMethod       = "auth"
	RPCGroupsMethod     = "groups"
	RPCUnitsMethod      = "units"
	RPCSearchMethod     = "search"
	RPCGroupUsersMethod = "groupUsers"
	RPCUnitUsersMethod  = "unitUsers"
)

type rpcOpt func(r *rpcClient)

func WithAuth() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCAuthMethod] = r.auth
	}
}
func WithGroups() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCGroupsMethod] = r.groups
	}
}
func WithOrganizationalUnits() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCUnitsMethod] = r.units
	}
}
func WithGroupUsers() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCGroupUsersMethod] = r.groupUsers
	}
}
func WithUnitUsers() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCUnitUsersMethod] = r.unitUsers
	}
}
func WithSearch() func(r *rpcClient) {
	return func(r *rpcClient) {
		r.funcs[RPCSearchMethod] = r.search
	}
}

func DefaultRPCFuncs(client *ldap.Client, ops ...rpcOpt) map[string]RPCFunc {
	res := make(map[string]RPCFunc)
	rcl := &rpcClient{
		client: client,
		funcs:  res,
	}
	for _, f := range ops {
		f(rcl)
	}
	return rcl.funcs
}

func (r *rpcClient) auth(params string) (data string, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "rpc auth")
		}
	}()
	auth := RPCAuth{}
	err = json.Unmarshal([]byte(params), &auth)
	if err != nil {
		return
	}
	u, err := r.client.Auth(auth.Login, auth.Pass)
	if err != nil {
		return
	}
	d, err := json.Marshal(u)
	if err != nil {
		return
	}
	data = string(d)
	return
}

func (r *rpcClient) nodes(params string,
	retriever func(pageSize uint32) (ldap.ResultsScanner, error),
	result func(scanner func(setter func(res interface{}))) interface{}) (data string, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "rpc nodes")
		}
	}()
	pag := RPCPag{}
	err = json.Unmarshal([]byte(params), &pag)
	if err != nil {
		return
	}
	sc, err := retriever(pag.PerPage)
	if err != nil {
		return
	}
	var res interface{}
	var i uint32 = 0
	for sc.Next() {
		i++
		if i < pag.PageNum {
			continue
		}
		res = result(sc.Scan)
		if sc.LastErr() != nil {
			err = sc.LastErr()
			return
		}
		break
	}

	d, err := json.Marshal(res)
	if err != nil {
		return
	}
	data = string(d)
	return
}

func (r *rpcClient) groups(params string) (data string, err error) {
	return r.nodes(params,
		r.client.Groups,
		func(scanner func(setter func(res interface{}))) interface{} {
			res := make([]ldap.Group, 0)
			scanner(ldap.GroupsSetter(&res))
			return res
		})
}

func (r *rpcClient) units(params string) (data string, err error) {
	return r.nodes(params,
		r.client.OrganizationalUnits,
		func(scanner func(setter func(res interface{}))) interface{} {
			res := make([]ldap.Unit, 0)
			scanner(ldap.UnitsSetter(&res))
			return res
		})
}

func (r *rpcClient) search(query string) (data string, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "rpc search")
		}
	}()
	res, err := r.client.Search(query)
	if err != nil {
		return
	}
	d, err := json.Marshal(res)
	if err != nil {
		return
	}
	data = string(d)
	return
}

func (r *rpcClient) groupUsers(params string) (data string, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "rpc groupUsers")
		}
	}()
	rUsers := RPCNodeUsers{}
	err = json.Unmarshal([]byte(params), &rUsers)
	if err != nil {
		return
	}
	sc, err := r.client.GroupUsers(rUsers.ID, rUsers.Pag.PerPage)
	if err != nil {
		return
	}
	res := make([]ldap.User, 0, rUsers.Pag.PerPage)
	var i uint32 = 0
	for sc.Next() {
		i++
		if i < rUsers.Pag.PageNum {
			continue
		}
		sc.Scan(ldap.UsersSetter(&res))
		if sc.LastErr() != nil {
			err = sc.LastErr()
			return
		}
		break
	}

	d, err := json.Marshal(res)
	if err != nil {
		return
	}
	data = string(d)
	return
}

func (r *rpcClient) unitUsers(params string) (data string, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "rpc groupUsers")
		}
	}()
	rUsers := RPCNodeUsers{}
	err = json.Unmarshal([]byte(params), &rUsers)
	if err != nil {
		return
	}
	sc, err := r.client.OUUsers(rUsers.ID, rUsers.Pag.PerPage)
	if err != nil {
		return
	}
	res := make([]ldap.User, 0, rUsers.Pag.PerPage)
	var i uint32 = 0
	for sc.Next() {
		i++
		if i < rUsers.Pag.PageNum {
			continue
		}
		sc.Scan(ldap.UsersSetter(&res))
		if sc.LastErr() != nil {
			err = sc.LastErr()
			return
		}
		break
	}

	d, err := json.Marshal(res)
	if err != nil {
		return
	}
	data = string(d)
	return data, err
}
