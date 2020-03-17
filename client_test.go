package ldap

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func client(t *testing.T) *Client {
	client, err := New(context.Background(),
		WithTimeout(5*time.Second),
		WithURL(viper.GetString("ldap.url")),
		WithBaseDN(viper.GetString("ldap.dn")),
		WithAdmin(viper.GetString("ldap.user"), viper.GetString("ldap.pass")))
	if err != nil {
		t.Fatal("ldap connect", err)
	}
	return client
}

func TestMain(m *testing.M) {
	viper.SetConfigFile("./tests_conf.json")
	if e := viper.ReadInConfig(); e != nil {
		panic(e)
	}
	os.Exit(m.Run())
}

func TestClient_Auth(t *testing.T) {
	client := client(t)
	type fields struct {
		cl *Client
	}
	type args struct {
		usr  string
		pass string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantUser User
		wantErr  bool
	}{
		{
			name: "success",
			fields: fields{
				cl: client,
			},
			args: args{usr: viper.GetString("ldap.user"), pass: viper.GetString("ldap.pass")},
			wantUser: User{
				DN: viper.GetString("tests.client.auth.dn"),
			},
			wantErr: false,
		},
		{
			name: "error",
			fields: fields{
				cl: client,
			},
			args:     args{usr: `corp\some.user`, pass: "wrongPass"},
			wantUser: User{},
			wantErr:  true,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cl
			gotUser, err := c.Auth(tt.args.usr, tt.args.pass)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if err != nil {
				t.Errorf("Auth() unexpected error = %v", err)
				return
			}
			if gotUser.DN != tt.wantUser.DN {
				t.Errorf("Auth() gotUser = %+v, want %+v", gotUser, tt.wantUser)
			}
		})
	}
}

func TestClient_Groups(t *testing.T) {
	client := client(t)
	type fields struct {
		cl *Client
	}
	type args struct {
		pageSize uint32
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			fields:  fields{cl: client},
			args:    args{pageSize: 1},
			wantErr: false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cl
			got, err := c.Groups(tt.args.pageSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("Groups() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("Groups() unexpected nil in scanner")
				return
			}
			gs := make([]Group, 0, tt.args.pageSize)
			last := make([]Group, tt.args.pageSize)
			for got.Next() {
				gs = []Group{}
				got.Scan(GroupsSetter(&gs))
				if e := got.LastErr(); e != nil {
					t.Errorf("Groups() unexpected err while scan = %v", e)
					return
				}
				if len(gs) > int(tt.args.pageSize) {
					t.Errorf("Groups() scan wrong lenght = %d, res = %v", len(gs), gs)
					return
				}
				if reflect.DeepEqual(last, gs) {
					t.Errorf("Groups() got same result = %v as previuse = %v", gs, last)
					return
				}
				copy(last, gs)
			}
			gs = []Group{}
			got.Scan(GroupsSetter(&gs))
			if !reflect.DeepEqual(last, gs) {
				t.Errorf("Groups() in the end of scan got wrong result = %v wait = %v", gs, last)
			}
			if e := got.LastErr(); e != nil {
				t.Errorf("Groups() unexpected err after scan = %v", e)
				return
			}
		})
	}
}

func TestClient_OrganizationalUnits(t *testing.T) {
	client := client(t)
	type fields struct {
		cl *Client
	}
	type args struct {
		pageSize uint32
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			fields:  fields{cl: client},
			args:    args{pageSize: 1},
			wantErr: false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cl
			scanR, err := c.OrganizationalUnits(tt.args.pageSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("OrganizationalUnits() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if scanR == nil {
				t.Errorf("OrganizationalUnits() unexpected nil in scanner")
				return
			}
			us := make([]Unit, 0, tt.args.pageSize)
			last := make([]Unit, tt.args.pageSize)
			for scanR.Next() {
				us = []Unit{}
				scanR.Scan(UnitsSetter(&us))
				if e := scanR.LastErr(); e != nil {
					t.Errorf("OrganizationalUnits() unexpected err while scan = %v", e)
					return
				}
				if len(us) > int(tt.args.pageSize) {
					t.Errorf("OrganizationalUnits() scan wrong lenght = %d, res = %v", len(us), us)
					return
				}
				if reflect.DeepEqual(last, us) {
					t.Errorf("OrganizationalUnits() scanR same result = %v as previuse = %v", us, last)
					return
				}
				copy(last, us)
			}
			us = []Unit{}
			scanR.Scan(UnitsSetter(&us))
			if !reflect.DeepEqual(last, us) {
				t.Errorf("OrganizationalUnits() in the end of scan scanR wrong result = %v wait = %v", us, last)
			}
			if e := scanR.LastErr(); e != nil {
				t.Errorf("OrganizationalUnits() unexpected err after scan = %v", e)
				return
			}
		})
	}
}

func TestClient_GroupUsers(t *testing.T) {
	client := client(t)
	type fields struct {
		cl *Client
	}
	type args struct {
		nodeDN   string
		pageSize uint32
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "success",
			fields: fields{cl: client},
			args: args{pageSize: 1,
				nodeDN: viper.GetString("tests.client.groupUsers.nodeDN")},
			wantErr: false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cl
			scanR, err := c.GroupUsers(tt.args.nodeDN, tt.args.pageSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("GroupUsers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if scanR == nil {
				t.Errorf("GroupUsers() unexpected nil in scanner")
				return
			}
			us := make([]User, 0, tt.args.pageSize)
			last := make([]User, tt.args.pageSize)
			for scanR.Next() {
				us = []User{}
				scanR.Scan(UsersSetter(&us))
				if e := scanR.LastErr(); e != nil {
					t.Errorf("GroupUsers() unexpected err while scan = %v", e)
					return
				}
				if len(us) > int(tt.args.pageSize) {
					t.Errorf("GroupUsers() scan wrong lenght = %d, res = %v", len(us), us)
					return
				}
				if reflect.DeepEqual(last, us) {
					t.Errorf("GroupUsers() scanR same result = %v as previuse = %v", us, last)
					return
				}
				copy(last, us)
			}
			us = []User{}
			scanR.Scan(UsersSetter(&us))
			if !reflect.DeepEqual(last, us) {
				t.Errorf("GroupUsers() in the end of scan scanR wrong result = %v wait = %v", us, last)
			}
			if e := scanR.LastErr(); e != nil {
				t.Errorf("GroupUsers() unexpected err after scan = %v", e)
				return
			}
		})
	}
}

func TestClient_OUUsers(t *testing.T) {
	client := client(t)
	type fields struct {
		cl *Client
	}
	type args struct {
		ouName   string
		pageSize uint32
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantNames []string
		wantErr   bool
	}{
		{
			name:      "success",
			fields:    fields{cl: client},
			args:      args{ouName: viper.GetString("tests.client.ouUsers.nodeDN"), pageSize: 1000},
			wantNames: viper.GetStringSlice("tests.client.ouUsers.wantNames"),
			wantErr:   false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cl
			got, err := c.OUUsers(tt.args.pageSize, tt.args.ouName)
			if (err != nil) != tt.wantErr {
				t.Errorf("OUUsers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Error("OUUsers() unexpected nil in result")
				return
			}
			us := make([]User, 0, tt.args.pageSize)
			got.Next()
			got.Scan(UsersSetter(&us))
		LOOP:
			for _, name := range tt.wantNames {
				for _, u := range us {
					if u.Name == name {
						continue LOOP
					}
				}
				t.Errorf("OUUsers() didn't got waited user with name = %s", name)
			}
		})
	}
}
