package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
)

func check(e *casbin.Enforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", sub, act, obj)
	}
}


func main() {
	// https://casbin.org/en/editor
	authEnforcer, err := casbin.NewEnforcer("conf/rbac_model.conf", "conf/rbac_policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	// setup session store
	log.Printf("authEnforcer:%v", authEnforcer)
	check(authEnforcer, "alice", "data1", "read")
	check(authEnforcer, "alice", "data1", "write")
	check(authEnforcer, "alice", "data2", "write")
	check(authEnforcer, "bob", "data2", "read")
	check(authEnforcer, "bob", "data2", "write")
	authEnforcer.AddRoleForUser("bob", "data2_admin")
	check(authEnforcer, "bob", "data2", "read")
	authEnforcer.DeleteRoleForUser("bob", "data2_admin")
	check(authEnforcer, "bob", "data2", "read")
	authEnforcer.AddPermissionForUser("bob", "data2", "read")
	check(authEnforcer, "bob", "data2", "read")
	authEnforcer.DeletePermissionForUser("bob", "data2", "read")
	check(authEnforcer, "bob", "data2", "read")
}
