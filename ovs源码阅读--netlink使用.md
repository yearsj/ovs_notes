博客主页 -- https://segmentfault.com/a/1190000016080251
### netlink

netlink socket是一种用于用户态进程和内核态进程之间的通信机制。它通过为内核模块提供一组特殊的API，并为用户程序提供了一组标准的socket接口的方式，实现了全双工的通讯连接。

**特点：** 

- 双向传输，异步通信
- 用户空间中使用标准socket API
- 内核空间中使用专门的API
- 支持多播
- 可由内核端发起通信
- 支持32种协议类型

netlink仅支持32种协议类型，这在实际应用中可能并不足够，因此产生了generic netlink（以下简称为genl）， 
generic netlink支持1023个子协议号，弥补了netlink协议类型较少的缺陷。

#### 通信架构

![20160417125258374](https://ws4.sinaimg.cn/large/006tNc79ly1fqr78wnntsj30a209r0tp.jpg)

Netlink子系统：所有genl通信的基础，Netlink子系统中收到的所有Generic类型的netlink数据都被送到genl总线上；从内核发出的数据也经由genl总线送至netlink子系统，再打包送至用户空间 

Generic Netlink控制器：作为内核的一部分，负责动态地分配genl通道(即genl family id)，并管理genl任务，genl控制器是一个特殊的genl内核用户，它负责监听genl bus上的通信通道

genl通信建立在一系列的通信通道的基础上，每个genl family对应多个通道，这些通道由genl控制器动态分配 

#### 相关结构体

![netlink](https://ws2.sinaimg.cn/large/006tNc79ly1fqr6z984npj30ud0fbt9z.jpg)

##### **genl family** 

Generic Netlink是基于客户端-服务端模型的通信机制，服务端注册family（family是对genl服务的各项定义的集合），控制器和客户端都通过已注册的信息与服务端通信。 

```
//genl_family主要字段
struct genl_family
{
      unsigned int		id;	//family id
      unsigned int  	hdrsize;  //用户自定议头部长度
      char          	name[GENL_NAMSIZ]; //family名，要求不同的family使用不同的名字
      unsigned int  	version;	//版本
      unsigned int  	maxattr;	//最大attr类型数，使用netlink标准的attr来传输数据
      genl_ops 			*ops;		// 操作集合
};
```

##### genl_ops

定义了netlink family相关的操作

```
// genl_ops主要字段
struct genl_ops
{
      u8                 cmd;	//命令名，用于识别genl_ops
      unsigned int       flags;	//设置属性
      struct nla_policy  *policy; //定义了attr规则，genl在触发事件处理程序之前，会用其进行attr校验
      int                (*doit)(struct sk_buff *skb, struct genl_info *info);
      int                (*dumpit)(struct sk_buff *skb, struct netlink_callback *cb);
};
```

- doit：回调函数，在generic netlink收到数据时触发，运行在进程上下文
- dumpit：回调函数，当genl_ops的flag标志被添加了NLM_F_DUMP以后，每次收到genl消息即会回触发这个函数

> **dumpit与doit的区别是：**dumpit的第一个参数skb不会携带从客户端发来的数据。相反地，开发者应该在skb中填入需要传给客户端的数据，skb中携带的数据会被自动送到客户端。只要dumpit的返回值大于0，dumpit函数就会再次被调用，并被要求在skb中填入数据。当服务端没有数据要传给客户端时，dumpit要返回0。如果函数中出错，要求返回一个负值。

##### nal_policy

定义了attr规则

```
struct nla_policy
{
	u16     type;	//attr中的数据类型
	u16     len;	//如果在type字段配置的是字符串有关的值，要把len设置为字符串的最大长度
};
```

##### genl_info

内核在接收到用户的genetlink消息后，会对消息解析并封装成genl_info结构

```
struct genl_info
{
    u32                     snd_seq;  //发送序号  
    u32                     snd_pid;  //发送客户端的PID
    struct nlmsghdr *       nlhdr;	  //netlink header的指针
    struct genlmsghdr *     genlhdr;  //genl头部的指针（即family头部）
    void *                  userhdr;  //用户自定义头部指针  
    struct nlattr **        attrs;    //如果定义了genl_ops->policy，保存被policy过滤以后的结果
};
```

#### Generic Netlink服务端（内核）初始化

这里以OVS中packet的处理为例：

##### 1. 定义family

```
//定义packet family
static struct genl_family dp_packet_genl_family __ro_after_init = {
	.hdrsize = sizeof(struct ovs_header), 
	.name = OVS_PACKET_FAMILY,  
	.version = OVS_PACKET_VERSION, 
	.maxattr = OVS_PACKET_ATTR_MAX, 
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_packet_genl_ops,      //操作集合
	.n_ops = ARRAY_SIZE(dp_packet_genl_ops),
	.module = THIS_MODULE,
};
```

##### 2. 定义operation

```
// 定义packet family 的操作 --- packet类型的操作只支持OVS_PACKET_CMD_EXECUTE
static struct genl_ops dp_packet_genl_ops[] = {
    { .cmd = OVS_PACKET_CMD_EXECUTE, 
	  .flags = GENL_UNS_ADMIN_PERM, 
	  .policy = packet_policy,  
	  .doit = ovs_packet_cmd_execute    //接受数据包时，调用ovs_packet_cmd_execute进行处理
	}
};
```

```
// 定义packet family 的过滤规则
static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .len = ETH_HLEN },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_PACKET_ATTR_MRU] = { .type = NLA_U16 },
};
```

##### 3. 注册family

```
genl_register_family(&dp_packet_genl_family); 
```

#### **Generic Netlink客户端（用户空间）初始化** 

```
struct sockaddr_nl saddr;	
int                sock;
sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC); //创建一个netlink类型的socket

if (sock < 0) {
	return -1;
}

memset(&saddr, 0, sizeof(saddr));
saddr.nl_family = AF_NETLINK;
saddr.nl_pid = getpid();	//获取family id
if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {	//绑定
    printf("bind fail!\n");
    close(*p_sock);
    return -1;
}
```

#### 内核空间接受发送数据

接受数据：内核端一旦收到generic netlink数据，会触发doit函数运行，通过回调函数进行处理

发送数据：将数据打包好之后，可通过单播（genlmsg_unicast）或多播（）的形式进行发送

#### 用户空间接受发送数据

接受数据：调用recv函数即可完成从内核来的数据的接收

发送数据：调用sendto来发送数据 

#### netlink收发数据—以ovs中packet为例

![netlink收发控制](https://ws2.sinaimg.cn/large/006tKfTcly1fr21zhepi1j31bo0lcdj6.jpg)

### 参考内容
[GenerRic Netlink 详解](https://www.tuicool.com/articles/jE7nim)
