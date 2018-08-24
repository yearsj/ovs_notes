 segmentfault对应博文页面：https://segmentfault.com/a/1190000016113797
 
 
# ovs源码阅读--元组空间搜索算法

关于TTS（元组空间搜索算法）的详细介绍可以参考[OVS+DPDK Datapath 包分类技术](https://www.cnblogs.com/neooelric/p/7160222.html)这篇文章，本文只对该篇博客进行简单的介绍，其中案例和部分图片来自于[OVS+DPDK Datapath 包分类技术](https://www.cnblogs.com/neooelric/p/7160222.html)

### TTS算法主要组成部分

#### **Rule** : 单条的包过滤规则+动作

以下为具体的例子：

```
1 Rule #1: ip_src=192.168.0.0/16 ip_dst=0/0 protocol=0/0 port_src=0/0 port_dst=0/0
2 Rule #2: ip_src=0/0 ip_dst=23.23.233.0/24 protocol=6/8(TCP) port_src=0/0 port_dst=23/16 
3 Rule #3: ip_src=0/0 ip_dst=11.11.233.0/24 protocol=17/8(UDP) port_dst=0/0 port_dst=4789/16
4 Rule #4: ip_src=10.10.0.0/16 ip_dst=0/0 protocol=0/0 port_src=0/0 port_dst=0/0
```

可以看到一个rule中有多个字段，每个字段的形式为 ：**字段值/掩码前缀**



#### Tuple : 使用相同的匹配字段+每个匹配字段都使用相同的掩码长度

以下为具体的例子：

```
1 Tuple #1: ip_src_mask=16 ip_dst_mask=0 protocol_mask=0 port_src_mask=0 port_dst_mask=0
2 Tuple #2: ip_src_mask=0 ip_dst_mask=24 protocol_mask=8 port_src_mask=0 port_dst_mask=16
```

tuple是将有**相同规则**的rule进行合并，例如上述rule #1和rule #4可以看成是同一个tuple #1，因为其每个字段的掩码都相同，所以tuple有如下特点：

1. 使用相同的匹配字段
2. 每个匹配字段都使用相同的掩码长度



#### **Key**：用于hash

以Tuple #2中的Rule #2为例说明一下，首先用tuple的掩码去**与**rule中的各个**字段值**，丢弃tuple不关心的位，得到：

```
ip_src=_ ip_dst=23.23.233 protocol=6 port_src=_ port_dst=23
```

然后把这些位拼接起来，就是哈希表的key，转换为二进制如下：

```
key = 0001 0111(23) 0001 0111(23) 1110 1001(233) 0000 0110(6) 0000 0000 0001 0111(23)
```

最后，用这个key去做散列，即是哈希表的索引



### 匹配过程

- 所有的rule都被分成了多个tuple，并存储在相应tuple下的哈希表中
- 当要对一个包进行匹配时，将遍历这多个tuple下的哈希表，一个一个查过去，查出所有匹配成功的结果，然后按一定策略在匹配结果中选出最优的一个。

下面以ovs中具体的事例进行说明：

1. 首先添加一个rule #1，该rule创建的过程中会创建对应的掩码（mask FF.FF.FF.00），也就是TTS中的Tuple，然后rule与mask进行与操作生成key，通过key进行散列得到一个索引值，最终将该rule #1加入到hash表HT 1对应的索引中

![img](https://ws3.sinaimg.cn/large/006tNbRwly1fuitscx51rj30gy03f0sw.jpg)

> 可以看到，同一个哈希表中的mask都是相同的，也就是说每一个tuple对应一个表

2. 接下来收到一个包packet #1，如下图所示，该包查找的过程中，会与所有的hash表进行匹配，由于目前只有一个表HT 1，所以该包会与HT 1对应的mask进行与运算，对其结果进行散列后查到对应表中的结果

![img](https://ws2.sinaimg.cn/large/006tNbRwly1fuitsbsbnuj30gy03k74g.jpg)

3. 同步骤1，此时又来了一个rule #2，按照同样的步骤，创建一个新的表HT 2

![img](https://ws1.sinaimg.cn/large/006tNbRwly1fuitscfljtj30gy04rjro.jpg)

4. 收到另一个包Packet #2，同步骤2进行查找，首先与HT 1对应的mask进行匹配查找，无法找到结果

![img](https://ws1.sinaimg.cn/large/006tNbRwly1fuitse9rljj30gy04tjrp.jpg)

然后与HT 2对应的mask进行查找，查询到对应的结果

![img](https://ws2.sinaimg.cn/large/006tNbRwly1fuitsdsv9bj30gy04rq39.jpg)

> 通过上述步骤可以看出来，TTS中的时间复杂度与Tuple的数量相关，如果Tuple的数量越多，则耗费的时间越长，当Tuple的数量==表项的数量，此时等同于挨个遍历所有的表项



### OVS与TTS

在[上一篇博文中](https://segmentfault.com/a/1190000016112493)，其中Megaflow Cache的实现就是采用了TTS，在如下图中，每个megaflow cache的表项对应TTS中的rule![2401853394-5b7d444466240_articlex](https://ws3.sinaimg.cn/large/006tNbRwly1fuitwsie0uj30m80c2af0.jpg)



具体的实现结构如下图，在最新的ovs中采用的是Mircroflow cache和Megaflow Cache结合的方式，其中可以看到Megaflow Cache是通过链表的形式进行组合的，sw_flow_mask结构体相当于是mask（TTS中的tuple），sw_flow结构体相当于是rule，其中Microflow cache中存放的是上次访问的sw_flow_mask索引，具体的流程会在接下来的博客进行详细的介绍。

![流表查询_gaitubao_com_watermark](https://ws3.sinaimg.cn/large/006tNbRwly1fuitr3wr6oj31ia0w4tcs.jpg) 



## 参考资料

[OVS+DPDK Datapath 包分类技术](https://www.cnblogs.com/neooelric/p/7160222.html)
