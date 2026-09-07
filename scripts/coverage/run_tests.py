#!/usr/bin/env python3
import os, sys, tempfile, subprocess, re, shutil, glob, difflib

def run_test(script_path, test_file):
    with open(test_file, 'r') as f:
        lines = f.readlines()

    expected = []
    before_code, after_code, lcov_data = [], [], []
    in_expected = False
    after_line_num = 0

    # 1. Parse the inline annotations
    for line in lines:
        if line.startswith('/* EXPECTED'):
            in_expected = True
            continue
        if in_expected:
            if line.strip() == '*/':
                in_expected = False
            else:
                expected.append(line)
            continue

        # Match format: [ +|-| ] [hits| ] | code
        match = re.match(r'^([+\-\s])([0-9\s]*)\|(.*)', line.rstrip('\n'))
        if match:
            pr_mod = match.group(1)       # +, -, or space
            hits = match.group(2).strip() # 0, 1, or empty
            code = match.group(3)[1:]

            if pr_mod in ('-', ' '):
                before_code.append(code)

            if pr_mod in ('+', ' '):
                after_line_num += 1
                after_code.append(code)
                if hits.isdigit():
                    lcov_data.append(f"DA:{after_line_num},{hits}")

    test_dir = tempfile.mkdtemp()

    try:
        # 2. Write the "After" file to disk so `sed` can read the snippets
        src_file = os.path.join(test_dir, "src", "test.c")
        os.makedirs(os.path.dirname(src_file))
        with open(src_file, "w") as f:
            f.write("\n".join(after_code) + "\n")

        # 3. Generate the Unified Diff using Python, mimicking `git diff -U0`
        diff_lines = list(difflib.unified_diff(
            [l + "\n" for l in before_code],
            [l + "\n" for l in after_code],
            fromfile="a/src/test.c",
            tofile="b/src/test.c",
            n=0 # Context lines = 0 (Matches git diff -U0)
        ))

        diff_file = os.path.join(test_dir, "mock_diff.txt")
        with open(diff_file, "w") as f:
            f.write("".join(diff_lines))

        # 4. Create a Fake `git` Executable
        # When the bash script runs `git diff...`, it will run this instead!
        fake_git = os.path.join(test_dir, "git")
        with open(fake_git, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"if [ \"$1\" = \"diff\" ]; then cat '{diff_file}'; fi\n")
        os.chmod(fake_git, 0o755)

        # 5. Write LCOV tracefile
        lcov_file = os.path.join(test_dir, "coverage.info")
        with open(lcov_file, "w") as f:
            f.write("TN:\nSF:src/test.c\n")
            f.write("\n".join(lcov_data) + "\n")
            f.write("end_of_record\n")

        # 6. Execute the Bash Script
        summary_file = os.path.join(test_dir, "summary.md")
        env = os.environ.copy()
        # Inject our fake git into the PATH
        env["PATH"] = f"{test_dir}:{env.get('PATH', '')}"
        env["GITHUB_WORKSPACE"] = test_dir
        env["GITHUB_EVENT_NAME"] = "push"
        env["GITHUB_STEP_SUMMARY"] = summary_file

        subprocess.run(["bash", script_path, lcov_file], env=env, stdout=subprocess.DEVNULL, cwd=test_dir)

        # 7. Compare Outputs
        with open(summary_file, "r") as f:
            actual = f.read().strip()
        expected_str = "".join(expected).strip()

        if actual == expected_str:
            print(f"✅ PASS: {os.path.basename(test_file)}")
            return True
        else:
            print(f"❌ FAIL: {os.path.basename(test_file)}")
            print("\n--- EXPECTED ---\n" + expected_str)
            print("\n--- ACTUAL ---\n" + actual + "\n")
            return False

    finally:
        shutil.rmtree(test_dir)

if __name__ == '__main__':
    script_path = os.path.abspath(sys.argv[1])
    test_dir = sys.argv[2]

    success = True
    for test_file in sorted(glob.glob(os.path.join(test_dir, "*.test"))):
        if not run_test(script_path, test_file):
            success = False

    sys.exit(0 if success else 1)
