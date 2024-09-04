# Contributing to pkcs11-provider

:+1::tada: First off, thanks for considering to contribute! :tada::+1:

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to abide by the code.

## What should I know before I get started?

If you want to contribute code you need to understand the [PKCS#11](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11) Specifications and the OpenSSL 3.0 provider APIs.
Useful links to learn about these are:
- [PKCS#11 2.4 Base Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [PKCS#11 3.1 Spec](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/csd01/pkcs11-spec-v3.1-csd01.html)
- [Providers Corner](https://github.com/provider-corner)
- [OpenSC wiki](https://github.com/OpenSC/OpenSC/wiki)

## How Can I Contribute?

### Reporting Bugs

Before reporting bugs please insure that you have checked the latest changes to
see if a bug has already been reported and corrected. Peruse your distribution
repositories and bug report system to find out if the bug has been reported
there first.

* Provide a description of the behavior experienced, as well as what you expected.
* Provide that make/model/version of the token used, including for software tokens.
* provide steps to repdouce the issue
* Use a clear and descriptive title

### Suggesting Enhancements

Before suggesting an enhancement please check if it has been reported and
accept/denied before.

* Include a clear description of what benefit this enhancemnt would provide and
  its impact
* If it affects a specific token please provide a statament on whether you are
  willing to test changes and report results
* Use a clear and descriptive title

### Contributing code

We accept code contributions via Pull Requests.

* Use a clear and descriptive title
* Unless it is obvious provide a description of the contribution about why and
  what is being proposed.
* Split your submission in logical, self contained commits.
  - Ideally each commit compile and pass tests on its own.
  - Each commit should have a commit message that describes the contents.
* for whole new features please add tests that exercise it.
* Use make check to test your code
* Use make check-style to verify your submission
* Monitor the CI jobs and fix issues proactively
* We use a rebase workflow
  - You can submit "fixup" commits if changes are complex in order to go through
    the review.
  - You are expected to rebase and provide logical commits before final merging.
* Each commit should be Signed-off-by the author.
