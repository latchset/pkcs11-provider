ACLOCAL_AMFLAGS = -Im4

SUBDIRS = src tests
dist_doc_DATA = README

check-style:
	@lines=`git diff -U0 --no-color --relative origin/main | clang-format-diff -p1 |wc -l`; \
	if [ "$$lines" != "0" ]; then \
		echo "Coding Style issues detected"; \
		exit 1; \
	else \
		echo "Coding Styles checks out"; \
	fi

check-style-show:
	git diff -U0 --no-color --relative origin/main | clang-format-diff -p1

check-style-fix:
	git diff -U0 --no-color --relative origin/main | clang-format-diff -i -p1
