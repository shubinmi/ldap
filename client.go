package ldap

// noinspection GoRedundantImportAlias
import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	"github.com/shubinmi/util/errs"
)

const (
	sleepTimeout = 20 * time.Millisecond
)

type Client struct {
	closed bool
	con    *ldap.Conn
	opt    *opt
	comCh  chan concurrentFunc
}

func New(ctx context.Context, fs ...optF) (*Client, error) {
	opt, e := newOpt(fs...)
	if e != nil {
		return nil, errors.Wrap(e, "wrong ldap Client options")
	}
	done := make(chan struct{})
	var (
		l   *ldap.Conn
		err error
	)
	go func() {
		l, err = ldap.DialURL(opt.url, ldap.DialWithDialer(&net.Dialer{Timeout: opt.timeout}))
		close(done)
	}()
	select {
	case <-time.After(opt.timeout):
		return nil, errors.New("new ldap Client Dial timeout")
	case <-done:
	}
	if err != nil {
		return nil, err
	}
	if opt.debug {
		l.Debug.Enable(true)
	}
	cl := &Client{con: l, opt: opt}
	err = cl.bindAdmin()
	if err != nil {
		return nil, err
	}
	cl.comCh = make(chan concurrentFunc, 1)
	go cl.serveCommands(ctx)
	return cl, nil
}

func (c *Client) Ping() error {
	return c.bindAdmin()
}

func (c *Client) Auth(usr, pass string) (user User, err error) {
	if c.isClosed() {
		err = errors.New("client is closed")
		return
	}
	user, err = c.SearchByLogon(usr)
	if err != nil {
		return
	}
	f := func() chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Bind as the user to verify their password
			err = c.con.Bind(user.DN, pass)
		}()
		return done
	}
	e := c.concurrentDo(f)
	if e != nil {
		err = errs.Merge(err, e)
	}
	return
}

func (c *Client) Close() {
	if c.isClosed() {
		return
	}
	c.closed = true
	c.con.Close()
	close(c.comCh)
}

func (c *Client) GroupUsers(nodeDN string, pageSize uint32) (ResultsScanner, error) {
	if c.isClosed() {
		return nil, errors.New("client is closed")
	}
	mapper := func(ent *ldap.Entry) interface{} { return mapToUser(ent) }
	f := c.retriever(pageSize,
		fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(memberOf=%s))", nodeDN),
		mapper)
	sc := newScanner(f)
	return sc, nil
}

func (c *Client) OUUsers(pageSize uint32, ouNames ...string) (ResultsScanner, error) {
	if c.isClosed() {
		return nil, errors.New("client is closed")
	}
	var allUsersPageSize uint32 = 1000
	mapper := func(ent *ldap.Entry) interface{} { return mapToUser(ent) }
	f := c.retriever(allUsersPageSize,
		"(&(objectCategory=person)(objectClass=user))",
		mapper)
	sc := newScanner(f)
	cashRestResults := make([]User, 0, allUsersPageSize)

	uf := func() (interface{}, error) {
		users := make([]interface{}, 0, pageSize)
		res := make([]User, 0, allUsersPageSize)
	LOOP:
		for len(cashRestResults) > 0 || sc.Next() {
			if len(cashRestResults) > 0 {
				res = append(res, cashRestResults...)
				cashRestResults = []User{}
			} else {
				sc.Scan(UsersSetter(&res))
			}
			for i, u := range res {
				has := false
				for _, ouName := range ouNames {
					ouName = strings.TrimSpace(ouName)
					if strings.Contains(strings.ToLower(u.DN), strings.ToLower("ou="+ouName+",")) {
						has = true
					}
				}
				if !has {
					continue
				}
				users = append(users, u)
				if len(users) == int(pageSize) {
					if i+1 < len(res) {
						cashRestResults = res[i+1:]
					}
					break LOOP
				}
			}
		}
		err := sc.LastErr()
		if err == nil && len(users) < int(pageSize) {
			err = errs.NothingToDo{}
		}
		return users, err
	}
	usc := newScanner(uf)
	return usc, nil
}

func (c *Client) Search(query string) ([]map[string]interface{}, error) {
	if c.isClosed() {
		return nil, errors.New("client is closed")
	}
	searchRequest := c.searchRequest(query)
	var (
		err error
		sr  *ldap.SearchResult
	)
	search := func() (done chan struct{}) {
		done = make(chan struct{})
		go func() {
			defer close(done)
			sr, err = c.con.Search(searchRequest)
		}()
		return
	}
	err = errs.Merge(err, c.concurrentDo(search))
	if err != nil {
		return nil, errors.Wrap(err, "ldap search")
	}

	res := make([]map[string]interface{}, 0, len(sr.Entries))
	for _, e := range sr.Entries {
		item := make(map[string]interface{})
		item["DN"] = e.DN
		for _, attr := range e.Attributes {
			item[attr.Name] = attr.Values
		}
		res = append(res, item)
	}

	return res, nil
}

func (c *Client) OrganizationalUnits(pageSize uint32) (ResultsScanner, error) {
	if c.isClosed() {
		return nil, errors.New("client is closed")
	}
	f := c.retriever(pageSize,
		"(objectCategory=organizationalUnit)",
		func(v *ldap.Entry) interface{} { return mapToUnit(v) })
	sc := newScanner(f)
	return sc, nil
}

func (c *Client) retriever(pageSize uint32, query string,
	mapper func(entry *ldap.Entry) interface{}) func() (interface{}, error) {
	pagingControl := ldap.NewControlPaging(pageSize)
	searchRequest := c.searchRequest(query, pagingControl)
	return func() (interface{}, error) {
		var (
			err error
			sr  *ldap.SearchResult
		)
		search := func() (done chan struct{}) {
			done = make(chan struct{})
			go func() {
				defer close(done)
				sr, err = c.con.Search(searchRequest)
			}()
			return
		}
		err = errs.Merge(err, c.concurrentDo(search))
		if err != nil {
			return nil, errors.Wrap(err, "ldap retriever in search")
		}
		items := make([]interface{}, 0, len(sr.Entries))
		for _, e := range sr.Entries {
			items = append(items, mapper(e))
		}

		var er error
		updatedControl := ldap.FindControl(sr.Controls, ldap.ControlTypePaging)
		if ctrl, ok := updatedControl.(*ldap.ControlPaging); ctrl != nil && ok && len(ctrl.Cookie) != 0 {
			pagingControl.SetCookie(ctrl.Cookie)
		} else {
			er = errs.NothingToDo{}
		}
		return items, er
	}
}

func (c *Client) Groups(pageSize uint32) (ResultsScanner, error) {
	if c.isClosed() {
		return nil, errors.New("client is closed")
	}
	f := c.retriever(pageSize,
		"(|(objectclass=group)(objectclass=groupofnames)(objectclass=groupofuniquenames)(objectCategory=group))",
		func(v *ldap.Entry) interface{} { return mapToGroup(v) })
	sc := newScanner(f)
	return sc, nil
}

func (c *Client) SearchByLogon(loginName string) (user User, err error) {
	if c.isClosed() {
		err = errors.New("client is closed")
		return
	}
	loginName = loginNameNormalize(loginName)
	searchRequest := c.searchRequest(fmt.Sprintf(
		"(&(objectClass=organizationalPerson)(|(sAMAccountName:=%s)(userPrincipalName:=%s)))",
		loginName, loginName))
	var sr *ldap.SearchResult
	search := func() (done chan struct{}) {
		done = make(chan struct{})
		go func() {
			defer close(done)
			sr, err = c.con.Search(searchRequest)
		}()
		return
	}
	err = errs.Merge(err, c.concurrentDo(search))
	if err != nil {
		return
	}
	if len(sr.Entries) == 0 {
		err = errors.New("user does not exist")
		return
	}
	return mapToUser(sr.Entries[0]), nil
}

func (c *Client) concurrentDo(f concurrentFunc) (err error) {
	i := 0
Retry:
	if c.isClosed() {
		return errors.New("client is closed")
	}
	done := make(chan struct{})
	wrap := func() chan struct{} {
		defer func() { err = errs.Merge(err, c.bindAdmin()) }()
		tick := time.NewTicker(c.opt.timeout)
		defer tick.Stop()
		select {
		case <-tick.C:
			err = errors.New("concurrentDo timeout")
		case <-f():
		}
		return done
	}
	c.comCh <- wrap
	<-done
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) && i < 3 {
		err = nil
		i++
		c.con.Start()
		time.Sleep(sleepTimeout)
		goto Retry
	}
	return
}

func (c *Client) isClosed() bool {
	return c.closed
}

func (c *Client) searchRequest(query string, cs ...ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		c.opt.dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(c.opt.timeout), false,
		query,
		[]string{},
		cs,
	)
}

func (c *Client) serveCommands(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.Close()
			return
		case f, ok := <-c.comCh:
			if !ok {
				return
			}
			done := f()
			close(done)
		}
	}
}

func (c *Client) bindAdmin() (err error) {
	if c.isClosed() {
		return errors.New("client is closed")
	}
	done := make(chan struct{})
	go func() {
		err = c.con.Bind(c.opt.usr, c.opt.pass)
		close(done)
	}()
	select {
	case <-time.After(c.opt.timeout):
		err = errors.New("bindAdmin timeout")
	case <-done:
	}
	return
}
