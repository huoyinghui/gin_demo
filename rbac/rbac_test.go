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

func testEnforceWithDomain(t *testing.T, e  *casbin.Enforcer, sub, domain, obj, act string, res bool) {
	t.Helper()
	if ok := checkWithDomain(e, sub, domain, obj, act); ok != res {
		t.Errorf("%s_%s, %v, %s: %t, supposed to be %t", sub, domain, obj, act, ok, res)
	}
}

func testEnforceABAC(t *testing.T, e  *casbin.Enforcer, sub Subject, obj, act string, res bool) {
	t.Helper()
	if ok := checkABAC(e, sub, obj, act); ok != res {
		t.Errorf("%v, %v, %s: %t, supposed to be %t", sub, obj, act, ok, res)
	}
}

func testEnforceABACV1(t *testing.T, e  *casbin.Enforcer, sub string, obj Object, act string, res bool) {
	t.Helper()
	if ok := checkABACV1(e, sub, obj, act); ok != res {
		t.Errorf("%v, %v, %s: %t, supposed to be %t", sub, obj, act, ok, res)
	}
}

func testEnforceABACV2(t *testing.T, e  *casbin.Enforcer, sub Subject, obj Object, act string, res bool) {
	t.Helper()
	if ok := checkABACV2(e, sub, obj, act); ok != res {
		t.Errorf("%v, %v, %s: %t, supposed to be %t", sub, obj, act, ok, res)
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

func TestRBAC(t *testing.T) {
	// 用户->角色
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model.conf", "./conf/rbac_policy.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer, "alice", "data1", "write", false)
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
	testEnforce(t, authEnforcer,"bob", "data2", "write", true)
	testEnforce(t, authEnforcer,"alice", "data2", "write", true)
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


func TestRBACAndCURD(t *testing.T) {
	// setup session store
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_with_root.conf", "./conf/rbac_policy.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
	authEnforcer.AddRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	authEnforcer.DeleteRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", false)
	authEnforcer.AddPermissionForUser("bob", "data2", "read")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	authEnforcer.DeletePermissionForUser("bob", "data2", "read")
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
}


func TestRBACResourceRoles(t *testing.T) {
	// 用户->角色 g(r.sub, p.sub)
	// 资源->角色 g2(r.obj, p.obj)
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_resource_roles.conf", "./conf/rbac_policy_resource_roles.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"alice", "data2", "read", false)
	testEnforce(t, authEnforcer,"alice", "data2", "write", true)
}

func TestRBACTreeRoles(t *testing.T) {
	// 用户->角色 g(r.sub, p.sub)
	// 资源->角色 g2(r.obj, p.obj)
	// 多层角色
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_resource_roles.conf", "./conf/rbac_policy_resource_roles_v2.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"bob", "dev.data", "read", true)
	testEnforce(t, authEnforcer,"bob", "dev.data", "write", true)
	testEnforce(t, authEnforcer,"bob", "prod.data", "read", true)
	testEnforce(t, authEnforcer,"bob", "prod.data", "write", false)

	testEnforce(t, authEnforcer,"alice", "dev.data", "read", true)
	testEnforce(t, authEnforcer,"alice", "dev.data", "write", true)
	testEnforce(t, authEnforcer,"alice", "prod.data", "read", true)
	testEnforce(t, authEnforcer,"alice", "prod.data", "write", true)
}

func TestRBACDomain(t *testing.T) {
	/*
	在casbin中，角色可以是全局的，也可以是特定domain（领域）或tenant（租户），可以简单理解为组。
	例如dajun在组tenant1中是管理员，拥有比较高的权限，在tenant2可能只是个弟弟。
	*/
	authEnforcer, err := casbin.NewEnforcer(
		"./conf/rbac_model_domain.conf", "./conf/rbac_policy_domain.csv")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	testEnforceWithDomain(t, authEnforcer,"alice", "domain1", "data1", "read", true)
	testEnforceWithDomain(t, authEnforcer,"alice", "domain1", "data2", "read", false)
}

func TestABAC(t *testing.T)  {
	// abac 可以不需要policy
	authEnforcer, err := casbin.NewEnforcer("./conf/abac_model.conf")
	if err != nil {
		t.Error(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
	o := Object{
		Name: "data1",
		Owner: "alice",
	}
	testEnforceABACV1(t, authEnforcer, "alice", o, "read", true)
}