"""Parse analyzer C syntax with Tree-sitter; never invoke a C compiler.

Optional dependencies: tree-sitter==0.26.0, tree-sitter-c==0.24.2.
This checks grammar only, not SDK types, linking, or runtime behavior. Selected
main.c function bodies are parsed separately because the monolithic file uses
compiler-specific preprocessor and attribute syntax elsewhere.
"""

from pathlib import Path
import sys

from tree_sitter import Language, Parser
import tree_sitter_c

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_wifi_analyzer_integration import function_body


def main():
    parser = Parser(Language(tree_sitter_c.language()))
    sources = {}
    for name in (
        "main/wifi_analyzer.c", "main/wifi_analyzer.h",
        "main/wifi_analyzer_core.c", "main/wifi_analyzer_core.h",
        "tests/wifi_analyzer_core_test.c",
    ):
        sources[name] = (ROOT / name).read_bytes()
    main_source = (ROOT / "main/main.c").read_text(encoding="utf-8")
    for name in (
        "analyzer_legacy_scan_finished", "analyzer_tracked_wifi_connect",
        "wifi_event_handler", "ensure_wifi_mode", "ensure_ble_mode",
        "ensure_ieee802154_mode", "start_background_scan", "cmd_stop",
        "cmd_wifi_connect", "janos_console_cmd_dispatch",
        "janos_console_cmd_register", "uart_baud_idle_cb",
        "analyzer_host_busy_reason", "analyzer_host_prepare_wifi",
        "register_commands", "app_main",
    ):
        body = function_body(main_source, name)
        sources[f"main.c::{name} (body)"] = ("void syntax_check(void) {" + body + "}").encode()
    count = 0
    for name, source in sources.items():
        tree = parser.parse(source)
        stack = [tree.root_node]
        problems = []
        while stack:
            node = stack.pop()
            if node.type == "ERROR" or node.is_missing:
                problems.append(f"{node.type} at {node.start_point}")
            stack.extend(node.children)
        print(f"{name}: {len(problems)} syntax diagnostics")
        for problem in problems:
            print("  " + problem)
        count += len(problems)
    print(f"Parsed {len(sources)} sources/fragments; {count} diagnostics. No C compilation.")
    return bool(count)


if __name__ == "__main__":
    sys.exit(main())
