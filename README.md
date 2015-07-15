# ZABBIX-SFLOW

一个用于配合Zabbix监控工具的sFlow收集器及Zabbix自定义监控脚本，基于sFlow提供了Zabbix的监控脚本及sFlow收集器。目前支持UDP攻击的检查。

使用方法：

启动收集器（交换机上需要配好sFlow agent发送数据包到收集器）：

```
#设置UDP的pps大于1000的时候记录告警
zsflow --udp-threshold 1000
```

Zabbix的自定义监控脚本输出：

```
zsflow_zabbix | tail -n 1
```

脚本输出内容说明：

* 除了最后一行外，其余的行的内容为日志
* 如果最后一行为UDP-GOOD，表明一切正常
* 如果最后一行为UDP-UNKNOWN，表明脚本运行异常，可以查看输出的内容排查问题
* 如果最后一行为UDP-10.3.3.4-53-10.3.3.3-53，表明流量超过了阀值。这里的输出含义为UDP-{src_ip}-{src_port}-{dest_ip}-{dest_port}，src_ip/src_port/dest_ip/dest_port为异常流量中流量最大的流的信息。
