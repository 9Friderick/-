#!/usr/bin/env python3
"""
鹰图 (Hunter) API 数据获取脚本
https://hunter.qianxin.com/

功能：
  - 通过 Hunter API 搜索互联网资产
  - 每次搜索硬限制 10 条/页（节约额度，共 500 条）
  - 支持分页拉取，自动扣减剩余额度
  - 结果保存为带时间戳的 JSON 文件

使用方式：
  1. 设置 API Key（三种方式，优先级从高到低）：
     a. 命令行参数 --key <YOUR_KEY>
     b. 环境变量 HUNTER_API_KEY
     c. 配置文件 ~/.hunter_config.json
  2. 执行搜索：
     python3 hunter_search.py --key <KEY> --search 'ip="1.1.1.1"'
     python3 hunter_search.py --key <KEY> --search 'domain="example.com"' --pages 3
  3. 读取已有结果文件：
     python3 hunter_search.py --load results_20260719_102030.json

API 说明：
  - 参数名: api-key（带连字符）
  - search 需 base64url 编码
  - 时间格式: yyyy-MM-dd
"""

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError

# ============================================================
# 硬限制：每页固定 10 条 — 节约额度（共 500 条）
# ============================================================
DEFAULT_PAGE_SIZE = 10

# Hunter API 端点
HUNTER_API_URL = "https://hunter.qianxin.com/openApi/search"

# 默认时间范围（最近 30 天）
DEFAULT_DAYS = 30


def base64url_encode(text: str) -> str:
    """对搜索语法进行 base64url 编码（符合 RFC 4648）"""
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


def load_api_key(args) -> str:
    """按优先级获取 API Key"""
    if args.key:
        return args.key

    env_key = os.environ.get("HUNTER_API_KEY")
    if env_key:
        return env_key

    config_path = os.path.expanduser("~/.hunter_config.json")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            cfg = json.load(f)
        if "api_key" in cfg:
            return cfg["api_key"]

    return ""


def build_search_params(args) -> dict:
    """构建 Hunter API 请求参数（search 自动 base64url 编码）"""
    now = datetime.now(timezone(timedelta(hours=8)))  # UTC+8

    if args.start_time:
        start_time = args.start_time
    else:
        start_dt = now - timedelta(days=args.days or DEFAULT_DAYS)
        start_time = start_dt.strftime("%Y-%m-%d")

    if args.end_time:
        end_time = args.end_time
    else:
        end_time = now.strftime("%Y-%m-%d")

    # search 需 base64url 编码
    search_encoded = base64url_encode(args.search)

    params = {
        "api-key": args.api_key,       # ← 连字符，不是下划线
        "search": search_encoded,      # ← base64url 编码后的搜索语法
        "page": args.page or 1,
        "page_size": DEFAULT_PAGE_SIZE,
        "start_time": start_time,
        "end_time": end_time,
        "is_web": args.is_web,
    }
    # 去除空值
    return {k: v for k, v in params.items() if v is not None and v != ""}


def call_hunter_api(params: dict) -> dict:
    """调用 Hunter API 并返回解析后的 JSON"""
    url = f"{HUNTER_API_URL}?{urlencode(params)}"
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})

    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"code": e.code, "msg": f"HTTP {e.code}: {body[:200]}"}
    except (URLError, OSError) as e:
        return {"code": 0, "msg": f"请求失败: {e}"}
    except json.JSONDecodeError:
        return {"code": 0, "msg": "响应不是有效的 JSON"}


def validate_response(data: dict) -> tuple[bool, str]:
    """校验 API 响应 — Hunter 返回 code=200 表示成功"""
    code = data.get("code")
    msg = data.get("msg", data.get("message", "未知错误"))

    if code == 200:
        return True, ""
    elif code == 401:
        return False, f"API Key 无效或未授权: {msg}"
    elif code == 402:
        return False, f"账户余额不足: {msg}"
    else:
        return False, f"错误 (code={code}): {msg}"


def fetch_all_pages(args) -> list[dict]:
    """按页拉取所有数据，每页固定 10 条"""
    all_results = []
    page = args.page or 1
    max_pages = args.pages
    total_fetched = 0
    consecutive_empty = 0

    print(f"\n{'='*60}")
    print(f"  鹰图 Hunter API 搜索")
    print(f"{'='*60}")
    print(f"  搜索语法: {args.search}")
    print(f"  每页条数: {DEFAULT_PAGE_SIZE}（硬限制）")
    print(f"{'='*60}\n")

    while True:
        if max_pages is not None and (page - (args.page or 1)) >= max_pages:
            print(f"\n  已达到指定页数上限 ({max_pages} 页)，停止拉取")
            break

        params = build_search_params(args)
        params["page"] = page

        print(f"  ▶ 正在获取第 {page} 页...", end=" ", flush=True)

        data = call_hunter_api(params)
        ok, err_msg = validate_response(data)

        if not ok:
            print(f"\n  ✗ {err_msg}")
            break

        data_body = data.get("data", {})
        results = data_body.get("arr", [])

        if not results:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                print("（连续空页，已无更多数据）")
                break
            print("（本页无数据）")
            page += 1
            continue

        consecutive_empty = 0
        result_count = len(results)
        total_fetched += result_count
        all_results.extend(results)

        total = data_body.get("total", 0)
        credit_consumed = data_body.get("consume_credit", 0)

        print(f"✓ {result_count} 条 | 累计 {total_fetched} 条 | 总额度: {total} 条 | 消耗积分: {credit_consumed}")

        if total_fetched >= total:
            print("\n  所有数据已拉取完毕")
            break

        page += 1
        time.sleep(0.5)

    print(f"\n{'='*60}")
    print(f"  共获取 {len(all_results)} 条资产数据")
    print(f"{'='*60}")

    return all_results


def save_results(results: list[dict], args) -> str:
    """保存结果到 JSON 文件并返回路径"""
    if not results:
        print("  ℹ 无结果可保存")
        return ""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    search_tag = args.search.replace('"', "").replace("=", "_").replace(" ", "_")[:30]
    filename = f"hunter_{search_tag}_{timestamp}.json"
    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    output = {
        "source": "hunter.qianxin.com",
        "search": args.search,
        "page_size": DEFAULT_PAGE_SIZE,
        "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_results": len(results),
        "results": results,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n  💾 结果已保存: {filepath}")
    return filepath


def load_result_file(filepath: str):
    """读取之前保存的结果文件并显示概况"""
    if not os.path.exists(filepath):
        print(f"  ✗ 文件不存在: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    print(f"\n{'='*60}")
    print(f"  文件: {filepath}")
    print(f"  搜索语法: {data.get('search', '-')}")
    print(f"  获取时间: {data.get('fetched_at', '-')}")
    print(f"  资产总数: {len(results)}")
    print(f"{'='*60}")

    if results:
        print(f"\n  前 5 条预览:")
        print(f"  {'IP':<18} {'端口':<8} {'域名':<30} {'标题':<20}")
        print(f"  {'-'*76}")
        for item in results[:5]:
            ip = item.get("ip", "-")
            port = str(item.get("port", "-"))
            domain = (item.get("domain") or item.get("host", "") or "-")[:28]
            title = (item.get("title") or "-")[:18]
            print(f"  {ip:<18} {port:<8} {domain:<30} {title:<20}")
        if len(results) > 5:
            print(f"  ... 还有 {len(results)-5} 条")

    return data


def main():
    parser = argparse.ArgumentParser(
        description="鹰图 Hunter API 数据获取工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 搜索特定 IP
  python3 hunter_search.py --key <KEY> --search 'ip="1.1.1.1"'

  # 搜索域名相关资产，拉取 3 页（共 30 条）
  python3 hunter_search.py --key <KEY> --search 'domain="example.com"' --pages 3

  # 搜索 Web 资产，指定时间范围
  python3 hunter_search.py --key <KEY> --search 'web.title="后台"' --is-web 1 --days 7

  # 读取之前保存的结果
  python3 hunter_search.py --load results.json

  # 使用配置文件（~/.hunter_config.json）
  # 格式: {"api_key": "你的key"}
  python3 hunter_search.py --search 'ip="1.1.1.1"'
        """,
    )

    parser.add_argument("--key", help="Hunter API Key（也可通过 HUNTER_API_KEY 环境变量或 ~/.hunter_config.json 设置）")
    parser.add_argument("--search", "-s", help='搜索语法，如: ip="1.1.1.1" / domain="example.com"')
    parser.add_argument("--page", "-p", type=int, default=1, help="起始页码（默认: 1）")
    parser.add_argument("--pages", type=int, default=None, help="拉取页数（默认: 不限，直到数据拉完或额度耗尽）")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help=argparse.SUPPRESS)
    parser.add_argument("--is-web", type=int, choices=[0, 1, 2, 3, 4], default=None,
                        help="资产类型: 0=未知, 1=web, 2=非web, 3=全部, 4=指纹")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="回溯天数（默认: 30）")
    parser.add_argument("--start-time", help="起始时间，格式: yyyy-MM-dd")
    parser.add_argument("--end-time", help="结束时间，格式: yyyy-MM-dd")
    parser.add_argument("--output-dir", "-o", default="./hunter_results", help="结果保存目录（默认: ./hunter_results）")
    parser.add_argument("--load", "-l", help="读取之前保存的结果 JSON 文件")

    args = parser.parse_args()

    # ============================================================
    # 硬限制检查：不允许修改 page_size
    # ============================================================
    if any(x.startswith("--page-size") or x.startswith("--page_size") for x in sys.argv):
        print("  ✗ 禁止修改 --page-size 参数！每次搜索固定 10 条以节约额度。")
        print("    如需调整请联系脚本维护者确认。")
        sys.exit(1)

    # ============================================================
    # 读取已有结果模式
    # ============================================================
    if args.load:
        load_result_file(args.load)
        return

    # ============================================================
    # 搜索模式 — 校验参数
    # ============================================================
    if not args.search:
        parser.print_help()
        print("\n  ✗ 请指定 --search 搜索语法 或使用 --load 读取已有结果")
        sys.exit(1)

    # 获取 API Key
    args.api_key = load_api_key(args)
    if not args.api_key:
        print("  ✗ 未设置 API Key！请通过以下方式之一提供：")
        print("     1. --key <YOUR_KEY> 参数")
        print("     2. export HUNTER_API_KEY=<YOUR_KEY>")
        print("     3. 写入 ~/.hunter_config.json: {\"api_key\": \"<YOUR_KEY>\"}")
        sys.exit(1)

    # ============================================================
    # 执行搜索
    # ============================================================
    print(f"\n  ℹ 每页固定 {DEFAULT_PAGE_SIZE} 条 — 节约额度（共约 500 条）")
    results = fetch_all_pages(args)

    if results:
        save_results(results, args)
        print(f"\n  预览前 5 条:")
        for i, item in enumerate(results[:5], 1):
            ip = item.get("ip", "-")
            port = item.get("port", "-")
            url = item.get("url", item.get("host", "-"))
            title = item.get("title", "-")
            print(f"    {i}. {ip}:{port}  {url}  [{title}]")
    else:
        print("\n  ℹ 未获取到数据")


if __name__ == "__main__":
    main()
