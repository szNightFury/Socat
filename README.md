# Socat

Socat 端口转发管理脚本
版本: v1.0

功能:
- 基于 systemd 和 socat 实现的端口转发规则持久化与管理。
- 支持 TCP/UDP，IPv4/IPv6，以及端口区间批量转发。
- 自动探测本机网络协议栈（IPv4/IPv6/Dual Stack）。
- 支持域名目标（含 A / AAAA 记录智能识别及动态 DNS 刷新）。
- 双栈匹配策略：可按需创建单服务或分别匹配 v4/v6 流量。
- 所有转发规则以 systemd 单元形式存在，具备自动重启能力。
- 支持动态解析域名目标地址并定时重启服务

使用方法:
```
chmod +x socat.sh
sudo ./socat.sh
```
