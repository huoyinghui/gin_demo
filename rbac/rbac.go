package rbac

import (
	"github.com/casbin/casbin/v2"
	"log"
)

var authEnforcer *casbin.Enforcer

type Object struct {
	Name  string
	Owner string
}

type Subject struct {
	Name string
	Hour int
}

func init() {
	var err error
	// https://casbin.org/en/editor
	authEnforcer, err = casbin.NewEnforcer("./conf/rbac_model.conf", "./conf/rbac_policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authEnforcer:%v", authEnforcer)
}

func check(e *casbin.Enforcer, sub, obj, act string) bool {
	ok, _ := e.Enforce(sub, obj, act)
	//if ok {
	//	fmt.Printf("%s CAN %s %s\n", sub, act, obj)
	//} else {
	//	fmt.Printf("%s CANNOT %s %s\n", sub, act, obj)
	//}
	return ok
}

func checkWithoutUser(e *casbin.Enforcer, obj, act string) bool {
	ok, _ := e.Enforce(obj, act)
	return ok
}

func checkWithDomain(e *casbin.Enforcer, sub, domain, obj, act string) bool {
	ok, _ := e.Enforce(sub, domain, obj, act)
	return ok
}

func checkABAC(e *casbin.Enforcer, sub Subject, obj, act string)  bool {
	ok, _ := e.Enforce(sub, obj, act)
	return ok
}

func checkABACV1(e *casbin.Enforcer, sub string, obj Object, act string)  bool {
	ok, _ := e.Enforce(sub, obj, act)
	return ok
}

func checkABACV2(e *casbin.Enforcer, sub Subject, obj Object, act string)  bool {
	ok, _ := e.Enforce(sub, obj, act)
	return ok
}
