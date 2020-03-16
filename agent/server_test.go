package agent

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/shubinmi/ldap"
	"github.com/spf13/viper"
)

func TestMain(m *testing.M) {
	viper.SetConfigFile("../tests_conf.json")
	if e := viper.ReadInConfig(); e != nil {
		panic(e)
	}
	os.Exit(m.Run())
}

func TestLdapServer_RPC(t *testing.T) {
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())

	server := Server(5 * time.Second)
	defer server.Close()
	wg.Add(1)
	go func() {
		err := server.Run(ctx, ":8888", "/ws")
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("unexpected server err = %v", err)
		}
		wg.Done()
	}()

	ldapCl, err := ldap.New(context.Background(),
		ldap.WithTimeout(5*time.Second),
		ldap.WithURL(viper.GetString("ldap.url")),
		ldap.WithBaseDN(viper.GetString("ldap.dn")),
		ldap.WithAdmin(viper.GetString("ldap.user"), viper.GetString("ldap.pass")))
	if err != nil {
		t.Fatal("unexpected ldap connect", err)
	}
	defer ldapCl.Close()
	rpc := DefaultRPCFuncs(ldapCl,
		WithAuth(), WithGroups(), WithSearch(),
		WithOrganizationalUnits(), WithGroupUsers(), WithUnitUsers())
	client, err := Client(viper.GetString("ldap.url"),
		":8888", "/ws", rpc)
	if err != nil {
		t.Fatal("unexpected ldap agent connect", err)
	}
	wg.Add(1)
	go func() {
		err := client.Serve(ctx)
		if err != nil {
			t.Error("unexpected ldap agent", err)
		}
		wg.Done()
	}()

	type args struct {
		agentID string
		msg     LdapMsg
	}
	tests := []struct {
		name    string
		rpc     func(agentID string, msg LdapMsg) (LdapResp, error)
		args    args
		want    LdapResp
		wantErr bool
	}{
		{
			name: "auth success",
			rpc:  server.RPC,
			args: args{
				agentID: viper.GetString("ldap.url"),
				msg: LdapMsg{
					GUID:   "123",
					Method: RPCAuthMethod,
					Params: viper.GetString("tests.server.auth.params"),
				},
			},
			want: LdapResp{
				GUID: "123",
				Data: viper.GetString("tests.server.auth.data"),
				Err:  "",
			},
			wantErr: false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rpc(tt.args.agentID, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("RPC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RPC() got = %+v, want %+v", got, tt.want)
			}
		})
	}
	cancel()
	wg.Wait()
}
