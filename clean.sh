#!/bin/bash
# clean.sh — 將題目容器重置回原始漏洞狀態
# 使用方式：bash clean.sh
# 效果：docker compose force-recreate challenge，重跑 start.sh，所有手動修改消失

set -e
COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

echo "================================================================"
echo "  重置 sec_challenge 容器至原始漏洞狀態..."
echo "  所有在容器內的修改將全部清除。"
echo "================================================================"
echo

# 重建容器（保留 image，僅重建 container，讓 start.sh 重跑）
docker compose -f "$COMPOSE_FILE" up -d --force-recreate challenge

echo
echo "[✓] 容器已重置。等待 5 秒讓服務啟動..."
sleep 5

# 確認容器運行中
if docker ps --format '{{.Names}}' | grep -q '^sec_challenge$'; then
    echo "[✓] sec_challenge 運行中"
else
    echo "[✗] 容器未正常啟動，請檢查：docker logs sec_challenge"
    exit 1
fi

echo
echo "================================================================"
echo "  重置完成！所有 23 題已恢復為初始漏洞狀態。"
echo "  連線: docker exec -it sec_challenge bash"
echo "  Web: http://localhost:8080"
echo "  驗題平台: http://localhost:5000"
echo "================================================================"
