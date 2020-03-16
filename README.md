# LDAP / Active Directory
Golang LDAP/Active Directory API wrapper around https://github.com/go-ldap/ldap. WS Agent and Server for LDAP RPC

### Why
- This repo has high level wrapper around some main functions https://github.com/go-ldap/ldap
- Because it allows you to serve LDAP RPC for this function from the box

#### Contribute
- Create tests_conf.json with data 
- `{
  "ldap": {
    "url": "ldap://corp.test.com",
    "dn": "dc=corp,dc=test,dc=com",
    "user": "corp\\test.user",
    "pass": "testPass"
  },
  "tests" : {
    "client": {
      "auth": {
        "dn": "CN=Test User,OU=Users,OU=St-Petersburg,OU=Staff,DC=corp,DC=test,DC=com"
      },
      "groupUsers": {
        "nodeDN": "CN=Clients,OU=Products,OU=Service Accounts,DC=corp,DC=test,DC=com"
      },
      "ouUsers": {
        "nodeDN": "TestGroup",
        "wantNames": ["Test 1", "Test 2"]
      }
    },
    "server": {
      "auth": {
        "data": "{\"Name\":\"Test User\",\"DN\":\"CN=Test User,OU=Users,OU=St-Petersburg,OU=Staff,DC=corp,DC=test,DC=com\",\"CN\":\"Test User\",\"Mail\":\"test.user@test.com\",\"Phone\":\"\",\"Logon\":\"test.user\"}",
        "params": "{\"login\":\"corp\\\\test.user\",\"pass\":\"testPass\"}"
      }
    }
  }
}`
- Run tests in real ldap network