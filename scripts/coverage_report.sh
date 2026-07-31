#!/bin/bash
# Parses LCOV tracefiles and annotates PRs with missing code coverage.
# Usage: ./annotate_coverage.sh <path_to_lcov_file>

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Error: Missing LCOV tracefile."
    echo "Usage: $0 <lcov_tracefile.info>"
    exit 1
fi

COVERAGE_FILE="$1"

GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-push}"
GITHUB_BASE_REF="${GITHUB_BASE_REF:-main}"
GITHUB_STEP_SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

echo "Calculating changed lines..."
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    git diff FETCH_HEAD HEAD -U0 > changed_diff.txt
else
    git diff HEAD^1 HEAD -U0 > changed_diff.txt
fi

awk '
/^+++ b\// { file = substr($0, 7) }
/^@@ / {
    split($3, a, "+");
    split(a[2], b, ",");
    start = b[1];
    count = (length(b) == 1) ? 1 : b[2];
    for (i = 0; i < count; i++)
        print file ":" (start + i)
}' changed_diff.txt > changed_lines.txt

{
    echo "### 🔍 Missing code coverage for this PR";
    echo "| File | Lines | Snippet |";
    echo "|---|---|---|"
} >> "$GITHUB_STEP_SUMMARY"

echo "Analyzing coverage data from $COVERAGE_FILE..."

awk -v summary="$GITHUB_STEP_SUMMARY" -F'[:,]' '
# Helper function to print the current block of uncovered lines
function flush_block() {
    if (start_line != 0) {
        # Output native GitHub UI annotation block
        if (start_line == prev_line) {
            line_str = start_line
            printf "::warning file=%s,line=%s,title=Coverage::Line is never executed in tests\n", rel_file, start_line
        } else {
            line_str = start_line "-" prev_line
            printf "::warning file=%s,line=%s,endLine=%s,title=Coverage::Lines are never executed in tests\n", rel_file, start_line, prev_line
        }

        # Fetch the multi-line code snippet
        cmd = "sed -n \"" start_line "," prev_line "p\" " rel_file
        code_text = ""
        while ((cmd | getline seq_line) > 0) {
            sub(/^[ \t]+/, "", seq_line)      # Strip leading whitespace
            sub(/[ \t]+$/, "", seq_line)      # Strip trailing whitespace
            gsub(/\|/, "\\|", seq_line)       # Escape table pipes
            gsub(/`/, "\x27", seq_line)       # Escape backticks

            # Wrap each line in backticks and separate with HTML line breaks
            if (code_text == "")
                code_text = "`" seq_line "`"
            else code_text = code_text "<br>`" seq_line "`"
        }
        close(cmd)

        # Append the aggregated row to the Summary table
        printf "| %s | %s | %s |\n", rel_file, line_str, code_text >> summary

        # Reset block tracking
        start_line = 0
        prev_line = 0
    }
}

BEGIN {
    while ((getline line < "changed_lines.txt") > 0) {
        changed_lines[line] = 1
        split(line, p, ":")
        valid_files[p[1]] = 1
    }
    start_line = 0
    prev_line = 0
}
/^SF:/ {
    flush_block() # Flush any pending block from the previous file
    full_file = substr($0, 4)
    rel_file = ""
    for (f in valid_files) {
        if (substr(full_file, length(full_file) - length(f) + 1) == f) {
            rel_file = f
            break
        }
    }
}
/^DA:/ {
    line = $2; hits = $3
    # Only track if the line is uncovered AND modified in this PR
    if (rel_file != "" && changed_lines[rel_file ":" line] == 1 && hits == 0) {
        if (start_line == 0) {
            start_line = line
            prev_line = line
        } else if (line == prev_line + 1) {
            prev_line = line # Extend the block
        } else {
            flush_block()    # Gap found! Print current block and start a new one
            start_line = line
            prev_line = line
        }
    }
}
END {
    flush_block() # Ensure the final block in the last file is printed
}' "$COVERAGE_FILE"

echo "Annotations complete."
