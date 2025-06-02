Process to change coverity workflows
====================================

Coverity workflow changes are hard to test because we run the workflow only
from the _main_ branch.

Coverity workflows need access to github secrets to authenticate to the
coverity server as well as to manipulate labels on PRs.

Therefore we run coverity workflows from the _main_ branch via the
'pull_request_target' event type.

This means that changes to the coverity workflow cannot be tested on PRs, and
are executed for the first time on the next PR after the changes are merged
to the _main_ tree.

To be able to test changes on these workflows we allow them to run on the
_covscan_ branch as well. People with write access to the project can force
push changes to the _covscan_ branch with the changes that need testing; then
a PR can be opened against that branch to verify that the changes work as
expected.

Once the changes are validated a PR to synchronize the changes from the
_covscan_ branch to the _main_ branch can be created.
