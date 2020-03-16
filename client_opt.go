package ldap

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/shubinmi/util/errs"
)

type concurrentFunc func() (done chan struct{})

type opt struct {
	url     string
	usr     string
	pass    string
	dn      string
	timeout time.Duration
	debug   bool
}

type optF func(*opt)

func newOpt(fs ...optF) (*opt, error) {
	o := &opt{
		timeout: 5 * time.Second,
	}
	for _, f := range fs {
		f(o)
	}
	err := o.valid()
	return o, err
}

func (o *opt) valid() (err error) {
	if o.url == "" {
		err = errs.Merge(err, errors.New("url is required"))
	}
	if o.usr == "" {
		err = errs.Merge(err, errors.New("usr is required"))
	}
	if o.pass == "" {
		err = errs.Merge(err, errors.New("pass is required"))
	}
	if o.dn == "" {
		err = errs.Merge(err, errors.New("dn is required"))
	}
	return
}

func WithURL(url string) func(*opt) {
	return func(o *opt) {
		o.url = url
	}
}

func WithTimeout(t time.Duration) func(*opt) {
	return func(o *opt) {
		o.timeout = t
	}
}

func WithBaseDN(dn string) func(*opt) {
	return func(o *opt) {
		o.dn = dn
	}
}

func WithDebug() func(*opt) {
	return func(o *opt) {
		o.debug = true
	}
}

func WithAdmin(usr, pass string) func(*opt) {
	return func(o *opt) {
		o.usr = usr
		o.pass = pass
	}
}

func loginNameNormalize(loginName string) string {
	logon := strings.Split(loginName, `\`)
	loginName = logon[len(logon)-1]
	logon = strings.Split(loginName, `@`)
	loginName = logon[0]
	return loginName
}
