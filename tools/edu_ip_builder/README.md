# 教育网 IP → 高校归属库（离线）

AutoHunter 写报告时会自动把目标 IP/域名反查成「所属高校」，用于填充报告的归属单位与
EduSRC 提交 JSON 的标题/单位字段。归属数据是一个离线 SQLite 库
`app/data_static/edu_ip.db`（已随仓库附带，开箱即用）。

本目录提供**重建/更新**该库的脚本，数据来源为公开的「纯真 IP 库(qqwry.dat)」，
它把中国教育网 IP 段标注到了学校级（含校区/院系粒度）。

## 重建步骤

```bash
# 1. 准备依赖
python3 -m venv .venv && ./.venv/bin/pip install qqwry-py3

# 2. 下载纯真库数据文件（任选一个公开镜像），命名为 qqwry.dat 放到本目录
#    例如：https://github.com/FW27623/qqwry

# 3. 生成/更新 edu_ip.db（离线遍历，约 10 秒）
./.venv/bin/python import_qqwry.py

# 4. 把产物拷到应用数据目录
cp edu_ip.db ../../app/data_static/edu_ip.db
```

## 文件说明

| 文件 | 作用 |
|------|------|
| `db.py` | SQLite schema、反查、学校名清洗、噪音判定 |
| `import_qqwry.py` | 遍历纯真库，抽取教育网/高校记录并落库 |
| `cernet_blocks.py` | CERNET 教育网骨干网段清单（参考用） |

## 说明

- 库中会自动标记「网吧/宾馆/承建公司/培训机构」等**非高校本体**记录为噪音，
  应用查询默认只返回真高校。
- 查询完全离线、毫秒级，不依赖任何在线接口。
- 归属查不到时（如非教育网 IP），报告归属会回退到 worker 自行判定的 owner。
