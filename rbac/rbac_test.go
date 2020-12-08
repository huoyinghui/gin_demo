package rbac

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	gormadapter "github.com/casbin/gorm-adapter/v2"
	_ "github.com/go-sql-driver/mysql"
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"bob", "data2", "read", false)
	_, _ = authEnforcer.AddRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	_, _ = authEnforcer.DeleteRoleForUser("bob", "data2_admin")
	testEnforce(t, authEnforcer, "bob", "data2", "read", false)
	_, _ = authEnforcer.AddPermissionForUser("bob", "data2", "read")
	testEnforce(t, authEnforcer, "bob", "data2", "read", true)
	_, _ = authEnforcer.DeletePermissionForUser("bob", "data2", "read")
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
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
	t.Logf("authEnforcer:%v", authEnforcer)
	testEnforceWithDomain(t, authEnforcer,"alice", "domain1", "data1", "read", true)
	testEnforceWithDomain(t, authEnforcer,"alice", "domain1", "data2", "read", false)
}

func TestABAC(t *testing.T)  {
	// abac 可以不需要policy
	authEnforcer, err := casbin.NewEnforcer("./conf/abac_model_hour.conf")
	if err != nil {
		t.Error(err)
	}
	t.Logf("authEnforcer:%v", authEnforcer)
	// 任意请求，在9-18点可以访问.
	sub := Subject{
		Name: "alice",
		Hour: 9,
	}
	subNight := Subject{
		Name: "alice",
		Hour: 19,
	}
	testEnforceABAC(t, authEnforcer, sub, "xxx", "data", true)
	testEnforceABAC(t, authEnforcer, subNight, "xxx", "read", false)
}


func TestABACV1(t *testing.T)  {
	// abac 可以不需要policy
	authEnforcer, err := casbin.NewEnforcer("./conf/abac_model.conf")
	if err != nil {
		t.Error(err)
	}
	t.Logf("authEnforcer:%v", authEnforcer)
	// data只有Owner拥有访问权限
	o := Object{
		Name: "data1",
		Owner: "alice",
	}
	testEnforceABACV1(t, authEnforcer, "alice", o, "read", true)
	testEnforceABACV1(t, authEnforcer, "bob", o, "read", false)
}

func TestABACV2(t *testing.T)  {
	// abac 可以不需要policy
	authEnforcer, err := casbin.NewEnforcer("./conf/abac_model_hour.conf")
	if err != nil {
		t.Error(err)
	}
	t.Logf("authEnforcer:%v", authEnforcer)
	// data只有Owner拥有访问权限
	o := Object{
		Name: "data1",
		Owner: "alice",
	}
	subBob := Subject{
		Name: "bob",
		Hour: 18,
	}
	subBobNight := Subject{
		Name: "bob",
		Hour: 20,
	}
	subAlice := Subject{
		Name: "alice",
		Hour: 20,
	}
	// 任意请求，在9-18点可以访问. 除此之外，只能拥有者访问
	testEnforceABACV2(t, authEnforcer, subBob, o, "read", true)
	testEnforceABACV2(t, authEnforcer, subBobNight, o, "read", false)
	testEnforceABACV2(t, authEnforcer, subAlice, o, "read", true)
}

func TestModelStore(t *testing.T)  {
	// 代码中动态初始化模型
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	a := fileadapter.NewAdapter("./conf/acl_policy.csv")
	authEnforcer, err := casbin.NewEnforcer(m, a)
	if err != nil {
		t.Error(err)
	}
	t.Logf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"alice", "data1", "read", true)
	testEnforce(t, authEnforcer,"bob", "data2", "write", true)
	testEnforce(t, authEnforcer,"root", "data2", "read", false)
}

func TestPolicyStore(t *testing.T)  {
	// 在前面的例子中，我们都是将策略存储在policy.csv文件中。一般在实际应用中，很少使用文件存储
	// casbin以第三方适配器的方式支持多种存储方式包括MySQL/MongoDB/Redis/Etcd等
	// https://casbin.org/docs/en/adapters
	// https://casbin.org/docs/zh-CN/policy-storage
	// 下面我们介绍使用Gorm Adapter
	// 1.import mysql
	// 2.NewAdapter
	Adapter, err := gormadapter.NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
	if err != nil {
		t.Error(err)
	}
	t.Logf("Adapter:%v", Adapter)

	authEnforcer, err := casbin.NewEnforcer("./conf/rbac_model.conf", Adapter)
	if err != nil {
		t.Error(err)
	}
	t.Logf("authEnforcer:%v", authEnforcer)
	testEnforce(t, authEnforcer,"alice", "data1", "read", true)
}