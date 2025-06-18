#!/bin/bash

# =======================================================
# 全功能 Socat 端口转发管理脚本
#
# 版本: v1.0
#
# 功能:
# - 基于 systemd 和 socat 实现的端口转发规则持久化与管理。
# - 支持 TCP/UDP，IPv4/IPv6，以及端口区间批量转发。
# - 自动探测本机网络协议栈（IPv4/IPv6/Dual Stack）。
# - 支持域名目标（含 A / AAAA 记录智能识别及动态 DNS 刷新）。
# - 双栈匹配策略：可按需创建单服务或分别匹配 v4/v6 流量。
# - 所有转发规则以 systemd 单元形式存在，具备自动重启能力。
# - 支持动态解析域名目标地址并定时重启服务
#
# 使用方法:
#       chmod +x socat.sh
#       sudo ./socat.sh
# =======================================================

# --- 配置 ---
SERVICE_PREFIX="socat-forwarder"
# 全局变量，用于存储本机网络栈类型 (dual, ipv4, ipv6)
LOCAL_STACK_TYPE="unknown"

# --- 颜色输出 ---
GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; BLUE="\033[0;34m"; NC="\033[0m"

# --- 核心依赖与环境检测 ---
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本必须以 root 权限运行。${NC}"
        exit 1
    fi
}

detect_environment() {
    for cmd in socat ip dig; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}错误: 核心依赖 '$cmd' 未安装。${NC}" >&2
            echo -e "${YELLOW}请尝试安装: apt install dnsutils iproute2 socat / yum install bind-utils iproute socat${NC}" >&2
            exit 1
        fi
    done

    local has_ipv4=false
    local has_ipv6=false
    if ip -4 addr show scope global | grep -q "inet"; then has_ipv4=true; fi
    if ip -6 addr show scope global | grep -q "inet6"; then has_ipv6=true; fi

    if $has_ipv4 && $has_ipv6; then LOCAL_STACK_TYPE="dual"
    elif $has_ipv4; then LOCAL_STACK_TYPE="ipv4"
    elif $has_ipv6; then LOCAL_STACK_TYPE="ipv6"
    else
        echo -e "${RED}错误: 未检测到任何可用的全局网络接口(IPv4 或 IPv6)。${NC}"
        exit 1
    fi
}

# --- 内部函数：创建服务单元 ---
# 参数: $1:协议(TCP/UDP) $2:本地端口 $3:监听类型(v4|v6|dual) $4:目标地址 $5:目标端口 $6:目标协议族(4/6) $7:DDNS(y/n) $8:间隔
_create_forwarder_unit() {
    local PROTOCOL_UPPER=$1; local LOCAL_PORT=$2; local LISTENER_TYPE=$3; local DEST_HOST=$4;
    local DEST_PORT=$5; local DEST_FAMILY=$6; local DYNAMIC_DNS_CHOICE=$7; local RESTART_INTERVAL=$8
    local PROTOCOL_LOWER=$(echo "$PROTOCOL_UPPER" | tr '[:upper:]' '[:lower:]')

    # 根据监听类型生成服务名后缀，确保唯一性
    local service_suffix="-${LISTENER_TYPE}"
    local SERVICE_NAME="${SERVICE_PREFIX}-${PROTOCOL_LOWER}-${LOCAL_PORT}${service_suffix}"
    local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${YELLOW}警告: 规则 ${SERVICE_NAME} 已存在，跳过创建。${NC}" >&2
        return 1
    fi

    local listen_cmd
    case "$LISTENER_TYPE" in
        "dual") listen_cmd="TCP6-LISTEN:${LOCAL_PORT},fork,reuseaddr,ipv6only=0" ;;
        "v4")   listen_cmd="TCP4-LISTEN:${LOCAL_PORT},fork,reuseaddr" ;;
        "v6")   listen_cmd="TCP6-LISTEN:${LOCAL_PORT},fork,reuseaddr" ;;
    esac
    # 如果是UDP，替换协议关键字
    [ "$PROTOCOL_UPPER" == "UDP" ] && listen_cmd="${listen_cmd/TCP/UDP}"

    # --- 格式化目标地址---
    # 规则: 仅当目标是字面量IPv6地址时，才需要用方括号包裹。
    # 判断依据: 如果目标协议族是IPv6 (DEST_FAMILY=6) 且地址本身包含冒号(:)，则视其为字面量IPv6。
    local dest_formatted_host="${DEST_HOST}"
    if [[ "${DEST_FAMILY}" == "6" && "${DEST_HOST}" == *:* ]]; then
        dest_formatted_host="[${DEST_HOST}]"
    fi

    local dest_cmd="TCP${DEST_FAMILY}:${dest_formatted_host}:${DEST_PORT}"
    [ "$PROTOCOL_UPPER" == "UDP" ] && dest_cmd="${dest_cmd/TCP/UDP}"

    local SOCAT_CMD="/usr/bin/socat ${listen_cmd} ${dest_cmd}"
    local description="[${PROTOCOL_UPPER}] local(${LISTENER_TYPE}) ${LOCAL_PORT} -> v${DEST_FAMILY}://${dest_formatted_host}:${DEST_PORT}"

    # 创建服务文件
    cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Socat Forwarder ${description}
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${SOCAT_CMD}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    echo -e "${GREEN}服务文件 ${SERVICE_NAME} 已生成。${NC}" >&2

    # 如果需要，创建定时器文件
    if [[ "$DYNAMIC_DNS_CHOICE" =~ ^[yY]$ ]]; then
        local TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"
        cat << EOF > "${TIMER_FILE}"
[Unit]
Description=Periodically restart ${SERVICE_NAME} for dynamic DNS resolution

[Timer]
OnBootSec=2min
OnUnitActiveSec=${RESTART_INTERVAL}min
Unit=${SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF
        echo -e "${GREEN}定时器文件 ${SERVICE_NAME}.timer 已生成。${NC}" >&2
        # 将服务名和定时器状态回传给调用者
        echo "${SERVICE_NAME}:timer"
    else
        echo "${SERVICE_NAME}:notimer"
    fi
    return 0
}

# --- 添加新的转发规则 ---
add_rule() {
    echo "--- ➕ 添加新的转发规则 ---"
    read -p "请输入【本地端口】或区间 (如 80 或 8000-8010): " LOCAL_PORT_INPUT
    read -p "请输入【目标地址】(域名, IPv4, 或 IPv6): " DEST_HOST
    read -p "请输入【目标端口】(留空则使用本地端口: ${LOCAL_PORT_INPUT}): " DEST_PORT_INPUT
    DEST_PORT_INPUT=${DEST_PORT_INPUT:-$LOCAL_PORT_INPUT}
    
    if [[ -z "$DEST_HOST" ]]; then echo -e "${RED}错误: 目标地址不能为空。${NC}"; sleep 2; return; fi
    local local_start local_end dest_start dest_end;
    if [[ "$LOCAL_PORT_INPUT" =~ ^([0-9]+)-([0-9]+)$ ]]; then local_start=${BASH_REMATCH[1]}; local_end=${BASH_REMATCH[2]}; elif [[ "$LOCAL_PORT_INPUT" =~ ^[0-9]+$ ]]; then local_start=$LOCAL_PORT_INPUT; local_end=$LOCAL_PORT_INPUT; else echo -e "${RED}错误: 本地端口格式无效。${NC}"; sleep 2; return; fi
    if [[ "$DEST_PORT_INPUT" =~ ^([0-9]+)-([0-9]+)$ ]]; then dest_start=${BASH_REMATCH[1]}; dest_end=${BASH_REMATCH[2]}; elif [[ "$DEST_PORT_INPUT" =~ ^[0-9]+$ ]]; then dest_start=$DEST_PORT_INPUT; dest_end=$DEST_PORT_INPUT; else echo -e "${RED}错误: 目标端口格式无效。${NC}"; sleep 2; return; fi
    if (( local_start > local_end )) || (( dest_start > dest_end )); then echo -e "${RED}错误: 端口区间的起始值不能大于结束值。${NC}"; sleep 2; return; fi
    local local_range_len=$((local_end - local_start)); local dest_range_len=$((dest_end - dest_start));
    if (( local_range_len > 0 && dest_range_len > 0 && local_range_len != dest_range_len )); then echo -e "${RED}错误: 当本地和目标都为区间时，它们的长度必须相等。${NC}"; sleep 2; return; fi

    read -p "请选择要应用的协议 (1:TCP, 2:UDP, 3:TCP+UDP) [3]: " PROTOCOL_CHOICE; PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-3}

    local connect_to_4="n"; local connect_to_6="n"
    local DYNAMIC_DNS="n"; local interval_minutes=5

    # --- 智能决策：根据目标类型决定转发策略 ---
    if [[ "$DEST_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        connect_to_4="y"
    elif [[ "$DEST_HOST" == *:* ]]; then
        connect_to_6="y"
    else # 域名处理
        echo -e "${BLUE}正在检测域名 ${DEST_HOST} 的DNS记录...${NC}"
        local has_a_record=$(dig +short A "$DEST_HOST" | grep -qE '^[0-9]' && echo "true" || echo "false")
        local has_aaaa_record=$(dig +short AAAA "$DEST_HOST" | grep -qE '[:a-fA-F0-9]' && echo "true" || echo "false")

        if $has_a_record && $has_aaaa_record; then
            echo -e "${GREEN}检测到域名 ${DEST_HOST} 是双栈域名。${NC}"
            echo "请选择连接策略:"
            echo "  1) 优先连接到它的IPv4地址 (本地所有流量 -> 远程IPv4)"
            echo "  2) 优先连接到它的IPv6地址 (本地所有流量 -> 远程IPv6)"
            if [ "$LOCAL_STACK_TYPE" == "dual" ]; then
                echo "  3) 智能匹配连接 (本地IPv4 -> 远程IPv4, 本地IPv6 -> 远程IPv6)"
            fi
            read -p "您的选择是? [1]: " connect_policy; connect_policy=${connect_policy:-1}
            case "$connect_policy" in
                1) connect_to_4="y" ;;
                2) connect_to_6="y" ;;
                3) if [ "$LOCAL_STACK_TYPE" == "dual" ]; then connect_to_4="y"; connect_to_6="y"; else echo "${RED}错误: 智能匹配仅在本地为双栈时可用。${NC}"; sleep 2; return; fi ;;
                *) echo "${RED}无效选择。${NC}"; sleep 2; return ;;
            esac
        elif $has_a_record; then
            echo -e "${GREEN}域名只有IPv4地址，将自动使用IPv4连接。${NC}"; connect_to_4="y"
        elif $has_aaaa_record; then
            echo -e "${GREEN}域名只有IPv6地址，将自动使用IPv6连接。${NC}"; connect_to_6="y"
        else
            echo -e "${RED}错误: 无法解析域名 ${DEST_HOST} 的任何有效IP地址。${NC}"; sleep 3; return
        fi
        
        read -p "是否为此域名启用动态解析 (DDNS)? [y/N]: " DYNAMIC_DNS
        DYNAMIC_DNS=${DYNAMIC_DNS:-Y}
        if [[ "$DYNAMIC_DNS" =~ ^[yY]$ ]]; then
            read -p "请输入重启间隔(分钟) [1440]: " interval_input; interval_minutes=${interval_input:-1440}
        fi
    fi

    local new_services=(); local new_timers=()
    echo "准备创建规则..."

    for (( i=0; i<=local_range_len; i++ )); do
        current_local_port=$((local_start + i))
        current_dest_port=$((dest_range_len > 0 ? dest_start + i : dest_start))

        create_units_for_proto() {
            local proto=$1; local info; local sname; local tstat;
            
            # --- 核心逻辑：根据连接策略和本地网络决定创建模式 ---
            # 模式1: 智能匹配 (双服务模式)
            if [ "$connect_to_4" == "y" ] && [ "$connect_to_6" == "y" ]; then
                # v4 -> v4
                info=$(_create_forwarder_unit "$proto" "$current_local_port" "v4" "$DEST_HOST" "$current_dest_port" "4" "$DYNAMIC_DNS" "$interval_minutes")
                [[ $? -eq 0 ]] && { sname=$(echo "$info" | cut -d: -f1); tstat=$(echo "$info" | cut -d: -f2); new_services+=("$sname"); [[ "$tstat" == "timer" ]] && new_timers+=("$sname"); }
                # v6 -> v6
                info=$(_create_forwarder_unit "$proto" "$current_local_port" "v6" "$DEST_HOST" "$current_dest_port" "6" "$DYNAMIC_DNS" "$interval_minutes")
                [[ $? -eq 0 ]] && { sname=$(echo "$info" | cut -d: -f1); tstat=$(echo "$info" | cut -d: -f2); new_services+=("$sname"); [[ "$tstat" == "timer" ]] && new_timers+=("$sname"); }
            # 模式2: 统一转发 (混合单服务模式)
            else
                local target_family=4; [ "$connect_to_6" == "y" ] && target_family=6
                local listener_type
                case "$LOCAL_STACK_TYPE" in
                    "dual") listener_type="dual" ;;
                    "ipv4") listener_type="v4" ;;
                    "ipv6") listener_type="v6" ;;
                esac
                info=$(_create_forwarder_unit "$proto" "$current_local_port" "$listener_type" "$DEST_HOST" "$current_dest_port" "$target_family" "$DYNAMIC_DNS" "$interval_minutes")
                [[ $? -eq 0 ]] && { sname=$(echo "$info" | cut -d: -f1); tstat=$(echo "$info" | cut -d: -f2); new_services+=("$sname"); [[ "$tstat" == "timer" ]] && new_timers+=("$sname"); }
            fi
        }

        case $PROTOCOL_CHOICE in
            1) create_units_for_proto "TCP" ;;
            2) create_units_for_proto "UDP" ;;
            3) create_units_for_proto "TCP"; create_units_for_proto "UDP" ;;
        esac
    done

    # 批量启动和状态检查
    if [ ${#new_services[@]} -gt 0 ]; then
        echo -e "\n${BLUE}正在应用新规则...${NC}"; systemctl daemon-reload
        local units_to_enable=("${new_services[@]}"); local units_to_start=("${new_services[@]}")
        if [ ${#new_timers[@]} -gt 0 ]; then
            mapfile -t timers_with_suffix < <(printf "%s.timer\n" "${new_timers[@]}");
            units_to_enable+=("${timers_with_suffix[@]}"); units_to_start+=("${timers_with_suffix[@]}");
        fi
        echo "批量启用并启动服务和定时器..."; systemctl enable "${units_to_enable[@]}" &>/dev/null; systemctl start "${units_to_start[@]}" &>/dev/null
        echo -e "\n=== 最终服务状态检查 ==="; local failed_services=()
        for unit in "${units_to_start[@]}"; do
            if systemctl is-active --quiet "$unit"; then echo -e "✓ ${GREEN}$unit: 运行正常${NC}";
            else echo -e "✗ ${RED}$unit: 运行异常${NC}"; failed_services+=("$unit"); fi
        done
        if [ ${#failed_services[@]} -eq 0 ]; then echo -e "\n${GREEN}所有新规则已成功添加并启动！${NC}";
        else echo -e "\n${YELLOW}警告: 以下单元启动失败:${NC}"; for failed in "${failed_services[@]}"; do echo -e "${RED}  - $failed${NC}"; done; fi
    else
        echo -e "\n${YELLOW}未创建任何新规则（可能已存在）。${NC}"
    fi
    echo; read -n 1 -s -r -p "按任意键返回主菜单..."
}

# --- 规则列表与管理函数 ---
list_rules() {
    echo "--- 📋 当前所有转发规则 ---"
    local files_unsorted=($(ls /etc/systemd/system/${SERVICE_PREFIX}-*.service 2>/dev/null))
    if [ ${#files_unsorted[@]} -eq 0 ]; then echo -e "${YELLOW}未找到任何转发规则。请使用选项 '1' 添加。${NC}"; return; fi
    
    # 使用自然排序，使 v4 和 v6 服务并列显示
    for file in $(printf "%s\n" "${files_unsorted[@]}" | sort -V); do
        local description=$(grep "Description=" "$file" | sed -e 's/Description=Socat Forwarder //')
        local service=$(basename "$file")
        if systemctl is-active --quiet "$service"; then status="${GREEN}● 运行中${NC}"; else status="${RED}○ 已停止${NC}"; fi
        local timer_tag=""
        if [ -f "/etc/systemd/system/${service%.service}.timer" ]; then
            if systemctl is-active --quiet "${service%.service}.timer"; then timer_tag=" ${GREEN}(DDNS)${NC}";
            else timer_tag=" ${RED}(DDNS-停)${NC}"; fi
        fi
        echo -e "${status} ${description} (${BLUE}${service}${NC})${timer_tag}"
    done
}

select_rule() {
    local prompt_message=$1; echo -e "$prompt_message"
    local files_unsorted=($(ls /etc/systemd/system/${SERVICE_PREFIX}-*.service 2>/dev/null))
    if [ ${#files_unsorted[@]} -eq 0 ]; then echo -e "${YELLOW}未找到任何转发规则。${NC}"; return 1; fi
    
    local files=($(printf "%s\n" "${files_unsorted[@]}" | sort -V))
    local i=0
    for file in "${files[@]}"; do
        local description=$(grep "Description=" "$file" | sed -e 's/Description=Socat Forwarder //')
        local service=$(basename "$file")
        systemctl is-active --quiet "$service" && status="${GREEN}运行中${NC}" || status="${RED}已停止${NC}"
        local timer_tag=""
        if [ -f "/etc/systemd/system/${service%.service}.timer" ]; then
            if systemctl is-active --quiet "${service%.service}.timer"; then timer_tag=" ${GREEN}(DDNS)${NC}";
            else timer_tag=" ${RED}(DDNS-停)${NC}"; fi
        fi
        echo -e " ${i}) ${status} ${description} (${BLUE}${service}${NC})${timer_tag}"
        i=$((i+1))
    done
    
    read -p "请选择一个规则的编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -lt ${#files[@]} ]; then
        SELECTED_SERVICE=$(basename "${files[$choice]}")
        return 0
    else
        echo -e "${RED}无效的选择。${NC}"; return 1
    fi
}

delete_rule() {
    echo "--- 🗑️ 删除一条转发规则 ---"
    if ! select_rule "请选择要删除的规则:"; then sleep 2; return; fi
    local service_to_delete=$SELECTED_SERVICE
    
    echo -e "${YELLOW}警告: 即将永久删除规则 ${service_to_delete}。${NC}"; read -p "您确定吗? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then echo "操作已取消。"; sleep 2; return; fi
    
    systemctl stop "${service_to_delete}" &>/dev/null
    systemctl disable "${service_to_delete}" &>/dev/null
    
    local timer_name="${service_to_delete%.service}.timer"
    if [ -f "/etc/systemd/system/${timer_name}" ]; then
        systemctl stop "${timer_name}" &>/dev/null
        systemctl disable "${timer_name}" &>/dev/null
        rm -f "/etc/systemd/system/${timer_name}"
    fi
    
    rm -f "/etc/systemd/system/${service_to_delete}"
    systemctl daemon-reload
    
    echo -e "${GREEN}规则 ${service_to_delete} 已被彻底删除。${NC}"; sleep 2
}

show_menu() {
    clear
    echo "======================================================"
    echo "  Socat 端口转发管理 (v1.0)"
    echo -e "      ${BLUE}本机网络环境: ${LOCAL_STACK_TYPE^^}${NC}"
    echo "======================================================"
    list_rules
    echo "------------------------------------------------------"
    echo " 1. ➕ 添加新规则"
    echo " 2. ❌ 删除一条转发规则"
    echo " 3. 🔼 启动一条规则"
    echo " 4. 🔽 停止一条规则"
    echo " 5. 🔄 重启一条规则"
    echo " 6. 📜 查看规则日志"
    echo " q. 退出"
    echo "------------------------------------------------------"
}

# --- 主循环 ---
check_root
clear
echo "正在检测环境..."
detect_environment
sleep 1

while true; do
    show_menu; read -p "请输入您的选择: " choice
    case $choice in
        1) add_rule ;;
        2) delete_rule ;;
        3) if select_rule "请选择要启动的规则:"; then systemctl start "$SELECTED_SERVICE"; echo -e "${GREEN}${SELECTED_SERVICE} 已启动。${NC}"; sleep 1; else sleep 2; fi ;;
        4) if select_rule "请选择要停止的规则:"; then systemctl stop "$SELECTED_SERVICE"; echo -e "${RED}${SELECTED_SERVICE} 已停止。${NC}"; sleep 1; else sleep 2; fi ;;
        5) if select_rule "请选择要重启的规则:"; then systemctl restart "$SELECTED_SERVICE"; echo -e "${YELLOW}${SELECTED_SERVICE} 已重启。${NC}"; sleep 1; else sleep 2; fi ;;
        6) if select_rule "请选择要查看日志的规则:"; then journalctl -u "$SELECTED_SERVICE" -f --no-pager; else sleep 2; fi ;;
        q|Q) echo "正在退出。"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${NC}"; sleep 1 ;;
    esac
done
