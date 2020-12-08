package rbac

import (
	"github.com/casbin/casbin/v2"
	"log"
)

var authEnforcer *casbin.Enforcer

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
