#!/usr/bin/env python3
"""Порог покрытия на добавленных строках.

Гейт смотрит на строки, которые появились в диффе, а не на файлы целиком.
Разница принципиальная: порог на файл упирается в его исторический процент,
поэтому правка в давно написанном модуле падает из-за чужого долга, а
свежий непокрытый код в хорошо покрытом файле проходит незамеченным.
Порог на добавленных строках ловит ровно то, ради чего гейт нужен: новый
код, приехавший без тестов.

Использование:
    cargo llvm-cov --all-targets --json --output-path coverage.json
    python3 scripts/coverage-gate.py coverage.json <base-ref> [--min 70]
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_MIN = 70.0
# Точка входа и сборочный скрипт исполняются, но не тестируются.
EXEMPT_SUFFIXES = ("src/main.rs", "build.rs")

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def repo_root() -> Path:
    """Корень рабочего дерева: от него считаются пути и в диффе, и в отчёте.

    Без git (распакованный архив исходников) корнем считается текущий
    каталог — гейт запускают из корня репозитория.
    """
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return Path.cwd().resolve()
    return Path(top).resolve()


def added_lines(root: Path, base_ref: str) -> dict[str, set[int]]:
    """Номера добавленных строк по файлам, из унифицированного диффа.

    Пути в диффе git всегда даёт от корня репозитория; `cwd=root` нужен
    ради pathspec `src`, который иначе считался бы от текущего каталога.
    """
    diff = subprocess.run(
        ["git", "diff", "-U0", "--diff-filter=d", f"{base_ref}...HEAD", "--", "src"],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )

    result: dict[str, set[int]] = {}
    current: str | None = None
    line_no = 0
    for line in diff.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/") :]
            current = path if path.endswith(".rs") else None
            continue
        if current is None:
            continue
        match = HUNK.match(line)
        if match:
            line_no = int(match.group(1))
            continue
        if line.startswith("+"):
            result.setdefault(current, set()).add(line_no)
            line_no += 1
    return result


def relative_to_root(filename: str, root: Path) -> str:
    """Путь из отчёта llvm-cov (абсолютный) — в путь от корня репозитория.

    Путь считается от корня, а не по имени каталога внутри него: клон
    может называться как угодно, а имя проекта может встретиться в пути
    дважды (в CI это `.../work/<repo>/<repo>/src/...`). Файлы вне
    репозитория (зависимости, стандартная библиотека) остаются как есть и
    с диффом не совпадут.
    """
    path = Path(filename)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def covered_and_executable(
    report_path: str, root: Path
) -> dict[str, tuple[set[int], set[int]]]:
    """По файлу: множества исполняемых и реально исполненных строк.

    Сегмент llvm-cov — это [line, col, count, has_count, entry, gap]. Строка
    считается исполняемой, если у неё есть сегмент со счётчиком; исполненной —
    если хотя бы один такой сегмент ненулевой. Gap-регионы пропускаются: они
    описывают не код, а промежутки между регионами.
    """
    report = json.loads(Path(report_path).read_text())
    files: dict[str, tuple[set[int], set[int]]] = {}
    for export in report.get("data", []):
        for entry in export.get("files", []):
            repo_relative = relative_to_root(entry["filename"], root)
            executable: set[int] = set()
            covered: set[int] = set()
            for line, _col, count, has_count, _entry, is_gap in entry.get("segments", []):
                if not has_count or is_gap:
                    continue
                executable.add(line)
                if count > 0:
                    covered.add(line)
            files[repo_relative] = (executable, covered)
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Порог покрытия на строках, добавленных относительно base-ref.",
    )
    parser.add_argument("report", help="JSON-отчёт cargo llvm-cov")
    parser.add_argument("base_ref", help="с чем сравнивать, например origin/master")
    parser.add_argument(
        "--min",
        type=float,
        default=DEFAULT_MIN,
        metavar="PERCENT",
        help=f"порог в процентах добавленных исполняемых строк (по умолчанию {DEFAULT_MIN:g})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    minimum = args.min
    root = repo_root()

    added = added_lines(root, args.base_ref)
    if not added:
        print("под src/ ничего не добавлено — гейт покрытия пропущен")
        return 0

    coverage = covered_and_executable(args.report, root)

    total_executable = 0
    total_covered = 0
    per_file: list[tuple[str, int, int]] = []
    missing: list[str] = []

    for path in sorted(added):
        if path.endswith(EXEMPT_SUFFIXES):
            continue
        if path not in coverage:
            # Файл не попал в отчёт: он не собирается в профиль покрытия.
            # Промолчать здесь значит показать зелёный гейт там, где он
            # ничего не проверил.
            missing.append(path)
            continue
        executable, covered = coverage[path]
        added_executable = added[path] & executable
        if not added_executable:
            continue
        added_covered = added_executable & covered
        per_file.append((path, len(added_covered), len(added_executable)))
        total_executable += len(added_executable)
        total_covered += len(added_covered)

    print(f"порог: {minimum:.1f}% добавленных исполняемых строк\n")
    for path, covered_count, executable_count in per_file:
        percent = 100.0 * covered_count / executable_count
        print(f"  {path} — {covered_count}/{executable_count} ({percent:.1f}%)")

    for path in missing:
        print(f"  {path} — нет данных о покрытии")

    if missing:
        print(
            "\nдля части изменённых файлов покрытие не измерено — гейт не может "
            "утверждать, что они покрыты",
            file=sys.stderr,
        )
        return 1

    if total_executable == 0:
        print("\nсреди добавленных строк нет исполняемых (комментарии, схемы, типы)")
        return 0

    percent = 100.0 * total_covered / total_executable
    print(f"\nитого: {total_covered}/{total_executable} ({percent:.1f}%)")
    if percent < minimum:
        print(
            f"покрытие добавленного кода {percent:.1f}% ниже порога {minimum:.1f}%. "
            "Либо покрыть тестами, либо осознанно снизить порог в вызове гейта — "
            "но не молча.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
