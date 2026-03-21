# 網路安全競賽訓練平台

包含安全強化（23 題）、封包鑑識（10 題）、記憶體鑑識（10 題）的完整練習環境。

## 目錄結構

```
security_hardening/
├── challenge/          # 安全強化容器（單容器，23 題全在裡面）
├── platform/           # Web 驗證平台（Flask）
├── forensics/
│   ├── network/        # 封包鑑識（Task_practice.pcapng）
│   └── mem/            # 記憶體鑑識（memory.dmp, 4.1GB）
├── solve_all.sh        # 一鍵/指定解題腳本
├── clean.sh            # 重置容器至漏洞狀態
├── NOTES.md            # 完整解題筆記
└── COVERAGE.md         # 歷屆出題範圍對照表
```

## 快速啟動

```bash
docker compose up -d --build
```

## 三個練習平台

| 平台 | 網址 | 說明 |
|------|------|------|
| 安全強化 | http://localhost:5000 | 23 題 Linux 安全加固 |
| 封包鑑識 | http://localhost:5000/forensics | 10 題，用 Wireshark 分析 |
| 記憶體鑑識 | http://localhost:5000/memory | 10 題，用 Volatility 3 分析 |

## 安全強化連線方式

```bash
docker exec -it sec_challenge bash
```

## 解題腳本

```bash
./solve_all.sh                # 全部 23 題
./solve_all.sh -s 3 -e 7     # 第 3~7 題
./solve_all.sh -c 4           # 第 1~4 題
./solve_all.sh 3 7 15         # 只解第 3、7、15 題
```

## 重置

```bash
./clean.sh                    # 重置安全強化容器
```

## 鑑識練習檔案

```bash
# 封包（用 Wireshark 開，已包含在 repo）
forensics/network/Task_practice.pcapng

# 記憶體（需自行下載，4.1GB）
# 來源：CyberDefenders Ramnit challenge
# https://cyberdefenders.org/blueteam-ctf-challenges/159#nav-overview
# 下載後解壓到 forensics/mem/memory.dmp
```
