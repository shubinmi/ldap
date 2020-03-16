package ldap

type Group struct {
	Name   string
	Desc   string
	DN     string
	CN     string
	Member string
}

type Unit struct {
	Name string
	DN   string
}

type User struct {
	Name  string
	DN    string
	CN    string
	Mail  string
	Phone string
	Logon string
}
