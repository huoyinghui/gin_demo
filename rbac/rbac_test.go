package rbac

import (
	"log"
	"testing"
)

func testEnforce(t *testing.T, sub string, obj string, act string, res bool) {
	t.Helper()
	if ok := check(authEnforcer, sub, obj, act); ok != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, ok, res)
	}
}

func TestSetupRouter(t *testing.T) {
	// setup session store
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, "alice", "data1", "write", false)
	testEnforce(t,"alice", "data2", "write", true)
	testEnforce(t,"bob", "data2", "read", false)
	testEnforce(t,"bob", "data2", "write", true)
	authEnforcer.AddRoleForUser("bob", "data2_admin")
	testEnforce(t, "bob", "data2", "read", true)
	authEnforcer.DeleteRoleForUser("bob", "data2_admin")
	testEnforce(t, "bob", "data2", "read", false)
	authEnforcer.AddPermissionForUser("bob", "data2", "read")
	testEnforce(t, "bob", "data2", "read", true)
	authEnforcer.DeletePermissionForUser("bob", "data2", "read")
	testEnforce(t,"bob", "data2", "read", false)
}