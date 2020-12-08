## 参考
[官方在线获取模型](https://casbin.org/en/editor)
[Go 每日一库之casbin](https://juejin.cn/post/6844904191257739277)


## RBAC 模型

在casbin中使用RBAC模型需要在模型文件中添加role_definition模块
```
[role_definition]
g = _, _

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

`g = _,_`
定义了用户——角色，角色——角色的映射关系，

前者是后者的成员，拥有后者的权限。
然后在匹配器中，我们不需要判断r.sub与p.sub完全相等，
只需要使用g(r.sub, p.sub)来判断请求主体r.sub是否属于p.sub这个角色即可

## ABAC

RBAC模型对于实现比较规则的、相对静态的权限管理非常有用。
但是对于特殊的、动态的需求，RBAC就显得有点力不从心了。

例如，我们在不同的时间段对数据data实现不同的权限控制。
正常工作时间9:00-18:00所有人都可以读写data，其他时间只有数据所有者能读写。
~~~~