#!/usr/bin/env bash
# 云讯短信中心 管理脚本：启动 / 停止 / 重启 / 状态 / 日志
# 用法：./run.sh           进入交互菜单
#       ./run.sh start     启动（后台）
#       ./run.sh stop      停止
#       ./run.sh restart   重启
#       ./run.sh status    状态
#       ./run.sh log       查看日志

set -uo pipefail

cd "$(dirname "$0")"

# 自动选择可用的 Linux 二进制（按优先级）
BIN=""
for c in dx-server-linux-amd64 dx-server-linux-arm64 dx-server; do
  if [ -x "$c" ]; then
    BIN="$c"
    break
  fi
done

PIDFILE="data/dx-server.pid"
LOGFILE="data/server.log"
mkdir -p data

running_pid() {
  [ -f "$PIDFILE" ] || return 1
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && echo "$pid"
}

do_start() {
  local pid
  pid="$(running_pid || true)"
  if [ -n "$pid" ]; then
    echo "服务已在运行 (PID $pid)"
    return 0
  fi
  if [ -z "$BIN" ]; then
    echo "错误：未找到 Linux 二进制，请先执行 ./build.sh 编译"
    return 1
  fi
  nohup "./$BIN" >>"$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  sleep 1
  pid="$(running_pid || true)"
  if [ -n "$pid" ]; then
    echo "服务已启动 (PID $pid)，日志: $LOGFILE"
  else
    echo "启动失败，请查看日志: $LOGFILE"
    tail -n 20 "$LOGFILE" 2>/dev/null || true
    rm -f "$PIDFILE"
    return 1
  fi
}

do_stop() {
  local pid
  pid="$(running_pid || true)"
  if [ -z "$pid" ]; then
    echo "服务未运行"
    rm -f "$PIDFILE"
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "优雅退出超时，强制结束..."
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
  echo "服务已停止"
}

do_restart() {
  do_stop && do_start
}

do_status() {
  local pid
  pid="$(running_pid || true)"
  if [ -n "$pid" ]; then
    echo "运行中 (PID $pid)，二进制: ${BIN:-未找到}"
  else
    echo "未运行"
  fi
}

do_log() {
  if [ -f "$LOGFILE" ]; then
    tail -n 50 "$LOGFILE"
  else
    echo "暂无日志"
  fi
}

menu() {
  while true; do
    echo
    echo "====== 云讯短信中心 管理 ======"
    echo "二进制: ${BIN:-未找到}"
    echo " 1) 启动"
    echo " 2) 停止"
    echo " 3) 重启"
    echo " 4) 状态"
    echo " 5) 查看日志"
    echo " 0) 退出"
    printf "请选择: "
    read -r choice
    case "$choice" in
      1) do_start ;;
      2) do_stop ;;
      3) do_restart ;;
      4) do_status ;;
      5) do_log ;;
      0) echo "再见"; break ;;
      *) echo "无效选择: $choice" ;;
    esac
  done
}

case "${1:-}" in
  start)    do_start ;;
  stop)     do_stop ;;
  restart)  do_restart ;;
  status)   do_status ;;
  log|logs) do_log ;;
  "")       menu ;;
  *) echo "用法: $0 {start|stop|restart|status|log}"; exit 1 ;;
esac
