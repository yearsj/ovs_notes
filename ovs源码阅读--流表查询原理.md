segmentfault对应博文：https://segmentfault.com/a/1190000016112493
# ovs源码阅读--流表查询原理
## 背景

在ovs交换机中，报文的处理流程可以划分为一下三个步骤：协议解析，表项查找和动作执行，其中最耗时的步骤在于表项查找，往往一个流表中有数目巨大的表项，如何根据数据报文的信息快速的查找到对应的流表项是ovs交换机的一个重要的功能。

在openflow协议中，支持多级流表的形式，可以类比于将一个复杂的功能进行打散，分解成过个小的功能，实现一个流水线的功能，具体见下图：

![646470776-5b7d4417222f6_articlex](https://ws2.sinaimg.cn/large/006tNbRwly1fuip45umxhj30m807r751.jpg)

上图中可以看到，一个数据报文进入后，会经过多个流表，每个流表负责特定的功能，比如上图中table 1中的流表项只会与数据报文中L2层的信息进行匹配，多个流表的处理使得整个数据报文的查询形成一种流水线的处理方式。

## ovs流cache设计

首先需要明确的是，ovs中的多级流表存放在用户空间，内核态存放的是流表的缓存，数据报文进入ovs的时候，首先会查询内核态的缓存信息，如果命中则直接执行相应的动作，否则通过[netlink](https://segmentfault.com/a/1190000016080251)的方式发送到用户空间，用户空间查找多级流表，如果用户态命中则将对应的信息丢给内核态进行缓存，否则查询不到，用户态还要继续将报文的信息丢给控制器，由控制器下发对应的规则，有关ovs和控制器之间的关系可以参见我的[上一个博客](https://segmentfault.com/a/1190000016112134)。

ovs中关于流表的查询经历了三个过程：

### microflow cache

microflow cache的思想十分简单，具体见下图：

![3921078234-5b7d4424ab398_articlex](https://ws1.sinaimg.cn/large/006tNbRwly1fuip3hxm8hj30m80b4q5s.jpg)

多级流表的查询过程中，会将报文与每个流表的每个流表项进行匹配，这个过程中耗费的时间是很大的，microflow cache的想法就是将多级流表查询之后的结果按照一定的表项格式直接缓存到内核态中，然后下次同样的数据报文到达时，直接通过hash的方法在内核态中命中，第二次的时间复杂度为$O(1)$，

microflow cache的缺点也很明显：

- 实际存在很多short-lived类型的流量，导致命中率低
- 由于Mircroflow Cache 基于Hash的精确匹配查表，数据头中微小的改动都会导致无法命中cache（如TTL）

#### Megaflow Cache

虽然基于microflow cache的流表查询方式，能让数据报文第二次命中的时间复杂度达到$O(1)$，但是其真正的性能瓶颈在于用户空间的查询，如何减少数据报文进入用户态，是一个很重要的问题。

为了解决精确匹配的问题，减少数据报文进入用户态，ovs采用了megaflow cache代替了microflow cache的匹配方式，megaflow cache是一种基于TTS（元组空间搜索算法）的实现方式，采用了模糊匹配取代microflow cache的精确匹配，通过增加在内核态中查询的时间（从1次hash查找到k次，仍然是常数时间内，跟TTS算法中表的数量有关），减少数据报文进入用户态的次数，具体会在TTS算法中解释。

一种朴素的megaflow cache实现方式就是，将所有多级流表的级联结果存放在内核态中，如下图：

![870210584-5b7d4436180d1_articlex](https://ws4.sinaimg.cn/large/006tNbRwly1fuip45c0juj30m80cfwgx.jpg)

内核态中存放着一张所有流表级联之后的大表，显而易见，这种做法简单粗暴，但是内存的开销也是巨大的。

一种好的做法是，采用’Lazy‘的方式，如下图所示，数据报文首先通过模糊匹配的方式检索内核中的表，如果所有的表都无法命中，则查询用户态，然后将用户态的查询出的所有表项合并成一条表项，再插入到内核态的表中。

![2401853394-5b7d444466240_articlex](https://ws1.sinaimg.cn/large/006tNbRwly1fuip46yxu3j30m80c2aco.jpg)

需要注意的是，上图中megaflow cache是一张表，在实际的ovs实现中，因为采用了TTS，所以megaflow cache是多张表形成的链表。

### microflow cache+Megaflow Cache

目前版本的ovs采用的是第三种查询方式，也就是结合microflow cache和Megaflow Cache，其中microflow cache作为一级cache，Megaflow Cache作为二级cache，此时microflow cache中存放的不再是多级流表返回的结果，而是上一次在Megaflow Cache中命中的索引。

数据报文到达时，首先通过对报文信息hash，查询microflow cache中是否存放着对应的hash值，如果存在则查询对应hash值所指向的索引，这个索引用来定位对应的Megaflow链表中的某一个元素表，然后再在这个元素表中进行查找。



整体的解释起来可能有点拗口，本人也是第一次写博客，对ovs了解的也不够深入，其中涉及到很多细节也不是很清楚，希望通过分享的形式同大家交流。




参考资料

[Pfaff B, Pettit J, Koponen T, et al. The Design and Implementation of Open vSwitch[C]//NSDI. 2015, 15: 117-130.](https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-pfaff.pdf)

[Open vSwitch流表查找分析](https://www.sdnlab.com/15713.html)

[The Design and Implementation of Open vSwitch 作者演讲ppt](https://www.usenix.org/sites/default/files/conference/protected-files/nsdi15_slides_pfaff.pdf)
