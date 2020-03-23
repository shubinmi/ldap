package ldap

// noinspection GoRedundantImportAlias
import (
	"encoding/json"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/shubinmi/util/exec"
)

func mapToGroup(ent *ldap.Entry) (g Group) {
	fs := make([]func() bool, 0, 10)
	for _, v := range [4]string{"name", "sAMAccountName", "userPrincipalName", "cn"} {
		pr := v
		fs = append(fs, func() bool {
			g.Name = ent.GetAttributeValue(pr)
			return g.Name != ""
		})
	}
	exec.UntilSuccess(fs...)
	g.DN = ent.DN
	g.CN = ent.GetAttributeValue("cn")
	g.Desc = ent.GetAttributeValue("description")
	g.Member = ent.GetAttributeValue("member")
	return
}

func mapToUnit(ent *ldap.Entry) (u Unit) {
	fs := make([]func() bool, 0, 10)
	for _, v := range [4]string{"ou", "name"} {
		pr := v
		fs = append(fs, func() bool {
			u.Name = ent.GetAttributeValue(pr)
			return u.Name != ""
		})
	}
	exec.UntilSuccess(fs...)
	u.DN = ent.DN
	return
}

func mapToUser(ent *ldap.Entry) (u User) {
	fs := make([]func() bool, 0, 5)
	for _, v := range [5]string{"name", "displayName", "cn", "sAMAccountName", "userPrincipalName"} {
		pr := v
		fs = append(fs, func() bool {
			u.Name = ent.GetAttributeValue(pr)
			return u.Name != ""
		})
	}
	exec.UntilSuccess(fs...)
	fs = fs[:0]
	for _, v := range [2]string{"sAMAccountName", "userPrincipalName"} {
		pr := v
		fs = append(fs, func() bool {
			u.Logon = ent.GetAttributeValue(pr)
			return u.Logon != ""
		})
	}
	exec.UntilSuccess(fs...)
	fs = fs[:0]
	for _, v := range [3]string{"telephoneNumber", "mobile", "phone"} {
		pr := v
		fs = append(fs, func() bool {
			u.Phone = ent.GetAttributeValue(pr)
			return u.Phone != ""
		})
	}
	exec.UntilSuccess(fs...)
	fs = fs[:0]
	for _, v := range [2]string{"mail", "email"} {
		pr := v
		fs = append(fs, func() bool {
			u.Mail = ent.GetAttributeValue(pr)
			return u.Mail != ""
		})
	}
	exec.UntilSuccess(fs...)
	u.DN = ent.DN
	u.CN = ent.GetAttributeValue("cn")
	bt, err := json.Marshal(ent.GetAttributeValues("memberOf"))
	if err == nil {
		u.MemberOf = string(bt)
	}
	return
}
