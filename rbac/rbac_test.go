package rbac

import (
	"github.com/casbin/casbin/v2"
	"log"
	"testing"
)

func testEnforce(t *testing.T, e  *casbin.Enforcer, sub string, obj string, act string, res bool) {
	t.Helper()
	if ok := check(e, sub, obj, act); ok != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, ok, res)
	}
}

func testEnforceWithoutUser(t *testing.T, e  *casbin.Enforcer, obj string, act string, res bool) {
	t.Helper()
	if ok := checkWithoutUser(e, obj, act); ok != res {
		t.Errorf("%v, %s: %t, supposed to be %t", obj, act, ok, res)
	}
}

func TestACL(t *testing.T)  {
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/acl_model.conf", "./conf/acl_policy.csv")
	if err != nil {
		t.Error(err)
	}
	testEnforce(t, authEnforcer,"alice", "data1", "read", true)
	testEnforce(t, authEnforcer,"bob", "data2", "write", true)
	testEnforce(t, authEnforcer,"root", "data2", "read", false)
}

func TestACLWithRoot(t *testing.T)  {
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/acl_model_with_root.conf", "./conf/acl_policy.csv")
	if err != nil {
		t.Error(err)
	}
	testEnforce(t, authEnforcer,"alice", "data1", "read", true)
	testEnforce(t, authEnforcer,"bob", "data2", "write", true)
	testEnforce(t, authEnforcer,"root", "data2", "read", true)
}

func TestACLWithoutUser(t *testing.T)  {
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/acl_model_without_user.conf", "./conf/acl_policy_without_user.csv")
	if err != nil {
		t.Error(err)
	}
	testEnforceWithoutUser(t, authEnforcer, "data1", "read", true)
	testEnforceWithoutUser(t, authEnforcer, "data2", "write", true)
}


func TestRBACV1(t *testing.T) {
	// setup session store
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_with_root.conf", "./conf/rbac_policy.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer, "alice", "data1", "write", false)
	testEnforce(t, authEnforcer,"alice", "data2", "write", true)
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
	testEnforce(t, authEnforcer,"bob", "data2", "write", true)
	authEnforcer.AddRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	authEnforcer.DeleteRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", false)
	authEnforcer.AddPermissionForUser("bob", "data2", "read")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	authEnforcer.DeletePermissionForUser("bob", "data2", "read")
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
}

func TestRBACWithRoot(t *testing.T)  {
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_with_root.conf", "./conf/rbac_policy.csv")
	if err != nil {
		t.Error(err)
	}
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
	testEnforce(t, authEnforcer,"root", "data2", "read", true)
}