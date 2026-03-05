"""
Прокси-чекер (HTTPS)
Считывает прокси из текстового файла, проверяет их работоспособность,
измеряет отклик (пинг/ping) и предоставляет сводку.

Поддерживаемые форматы прокси в текстовом файле (по одному на строку):
  ip:port
  ip:port:username:password
  username:password@ip:port
  http://ip:port
  http://username:password@ip:port

[Оригинальный скрипт принадлежит Misha? и ЧД-ВК "Феникс"]
"""

import re
import sys
import time
import argparse
import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.exceptions import (
        ConnectTimeout,
        ConnectionError,
        ProxyError,
        ReadTimeout,
        SSLError,
    )
except ImportError:
    print("[!] Библиотека 'requests' не установлена, установите её через эту команду: ")
    print("    pip install requests")
    sys.exit(1)

# ──────────────────────────── константы ────────────────────────────
TEST_URL = "https://httpbin.org/ip"
DEFAULT_TIMEOUT = 10  # В секундах
DEFAULT_WORKERS = 20
DEFAULT_INPUT = "proxies.txt"
DEFAULT_OUTPUT_GOOD = "working_proxies.txt"

# ANSI цвета
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ──────────────────────────── классы данных ─────────────────────────
@dataclass
class ProxyResult:
    proxy_raw: str
    proxy_url: str
    is_working: bool = False
    ping_ms: float = 0.0
    external_ip: Optional[str] = None
    error: Optional[str] = None


# ──────────────────────────── парсер ───────────────────────────────
def parse_proxy_line(line: str) -> Optional[str]:
    """
    Нормализует прокси вот в такой формат:  http://[user:pass@]host:port
    Возвращает None если прокси отсутвует / неправильное
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Уже есть префикс (яхз как это называется)
    if line.startswith("http://") or line.startswith("https://"):
        return line if line.startswith("http://") else "http://" + line[8:]

    # username:password@host:port
    if "@" in line:
        return f"http://{line}"

    parts = line.split(":")
    # host:port
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    # host:port:user:pass
    if len(parts) == 4:
        host, port, user, password = parts
        return f"http://{user}:{password}@{host}:{port}"

    return None


# ──────────────────────────── чекер ──────────────────────────────
def check_proxy(
    raw_line: str,
    timeout: int = DEFAULT_TIMEOUT,
    test_url: str = TEST_URL,
) -> ProxyResult:
    """Проверяет один прокси и возвращает результат"""
    proxy_url = parse_proxy_line(raw_line)

    if proxy_url is None:
        return ProxyResult(
            proxy_raw=raw_line,
            proxy_url="",
            error="Invalid format",
        )

    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }

    result = ProxyResult(proxy_raw=raw_line, proxy_url=proxy_url)

    try:
        start = time.perf_counter()
        response = requests.get(
            test_url,
            proxies=proxies,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (ProxyChecker)"},
        )
        elapsed = (time.perf_counter() - start) * 1000  # ms

        if response.status_code == 200:
            result.is_working = True
            result.ping_ms = round(elapsed, 1)
            # httpbin.org/ip возвращает {"origin": "x.x.x.x"}
            try:
                result.external_ip = response.json().get("origin", "N/A")
            except ValueError:
                result.external_ip = "N/A"
        else:
            result.error = f"HTTP {response.status_code}"

    except ProxyError as e:
        result.error = "Proxy error (auth / connection refused)"
    except ConnectTimeout:
        result.error = "Connection timed out"
    except ReadTimeout:
        result.error = "Read timed out"
    except SSLError:
        result.error = "SSL error"
    except ConnectionError:
        result.error = "Connection refused / unreachable"
    except Exception as e:
        result.error = str(e)[:80]

    return result


# ──────────────────────────── отображение ──────────────────────────────
def ping_color(ms: float) -> str:
    if ms < 1000:
        return GREEN
    elif ms < 3000:
        return YELLOW
    return RED


def print_result(index: int, total: int, r: ProxyResult) -> None:
    tag = f"[{index}/{total}]"
    if r.is_working:
        c = ping_color(r.ping_ms)
        print(
            f"  {GREEN}✔{RESET} {tag}  {r.proxy_raw:<45}  "
            f"{c}{r.ping_ms:>8.1f} ms{RESET}   "
            f"IP: {r.external_ip}"
        )
    else:
        print(
            f"  {RED}✘{RESET} {tag}  {r.proxy_raw:<45}  "
            f"{RED}{'FAIL':>8}{RESET}      "
            f"({r.error})"
        )


def print_summary(results: list[ProxyResult]) -> None:
    working = [r for r in results if r.is_working]
    dead = [r for r in results if not r.is_working]

    avg_ping = (
        sum(r.ping_ms for r in working) / len(working) if working else 0
    )
    best = min(working, key=lambda r: r.ping_ms) if working else None
    worst = max(working, key=lambda r: r.ping_ms) if working else None

    print(f"\n{'═' * 72}")
    print(f"{BOLD}                        ИТОГИ ПРОВЕРКИ ПРОКСИ{RESET}")
    print(f"{'═' * 72}")
    print(f"  ВСЕГО ПРОВЕРЕНО : {CYAN}{len(results)}{RESET}")
    print(f"  {GREEN}Работает       : {len(working)}{RESET}")
    print(f"  {RED}Дохлые          : {len(dead)}{RESET}")
    if working:
        print(f"  Средний пинг      : {avg_ping:.1f} ms")
        print(f"  Лучший прокси    : {best.proxy_raw}  ({best.ping_ms:.1f} ms)")
        print(f"  Худший прокси   : {worst.proxy_raw}  ({worst.ping_ms:.1f} ms)")
    print(f"{'═' * 72}\n")


# ──────────────────────────── main ─────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Прокси-чекер (HTTPS)")
    parser.add_argument(
        "-f", "--file",
        default=DEFAULT_INPUT,
        help=f"Путь к файлу с прокси (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT_GOOD,
        help=f"Файл для сохранения рабочих прокси (default: {DEFAULT_OUTPUT_GOOD})",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Таймаут между проверками в секундах (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Количество потоков (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "-u", "--url",
        default=TEST_URL,
        help=f"Ссылка, на которую прокси будет отправлять запросы (default: {TEST_URL})",
    )
    args = parser.parse_args()

    # Читаем файл с прокси (или сообщаем что его нету)
    path = Path(args.file)
    if not path.exists():
        print(f"{RED}[!] Файл с прокси не найден: {path}{RESET}")
        sys.exit(1)

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    # Фильтруем комментарии и пустышки заранее
    proxy_lines = [l.strip() for l in raw_lines if l.strip() and not l.strip().startswith("#")]

    if not proxy_lines:
        print(f"{RED}[!] В твоем файле нету прокси, дубина: {path}{RESET}")
        sys.exit(1)

    total = len(proxy_lines)
    print(f"\n{BOLD}ПРОВЕРКА HTTPS ПРОКСИ{RESET}")
    print(f"{'─' * 72}")
    print(f"  Файл       : {path}")
    print(f"  Прокси    : {total}")
    print(f"  Задержка    : {args.timeout}s")
    print(f"  Потоки   : {args.workers}")
    print(f"  Ссылка-цель   : {args.url}")
    print(f"{'─' * 72}\n")

    # Проверяем прокси
    results: list[ProxyResult] = []
    counter = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_to_line = {
            pool.submit(check_proxy, line, args.timeout, args.url): line
            for line in proxy_lines
        }

        for future in concurrent.futures.as_completed(future_to_line):
            counter += 1
            result = future.result()
            results.append(result)
            print_result(counter, total, result)

    # Подводим итоги 
    print_summary(results)

    # Сохраняем рабочие прокси
    working = [r for r in results if r.is_working]
    if working:
        # Сортируем по пингу (по возрастанию)
        working.sort(key=lambda r: r.ping_ms)
        out_path = Path(args.output)
        with open(out_path, "w", encoding="utf-8") as f:
            for r in working:
                f.write(r.proxy_raw + "\n")
        print(
            f"  {GREEN}[✓]{RESET} {len(working)} рабочих прокси сохранено в новый файл: "
            f"{CYAN}{out_path}{RESET} (Сортировано по пингу)\n"
        )


if __name__ == "__main__":
    main()
