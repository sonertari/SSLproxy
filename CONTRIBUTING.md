# Contributing to This Project

Thank you for your interest in contributing! Your work helps improve and sustain this open source project.

---

## 🐞 Bug Reports & Feature Requests

- **Please use GitHub Issues only for bug reports and feature requests.**
- We do **not** provide individual support through GitHub issues.
- For user support or troubleshooting, please use:
    - [Information Security Stack Exchange](https://security.stackexchange.com/)
    - [Network Engineering Stack Exchange](https://networkengineering.stackexchange.com/)
    - [Super User](https://superuser.com/)

### When Reporting a Bug

Please include the following information where applicable:

- Output of `sslproxy -V`
- Output of `uname -a`
- Exact command line arguments used to run the software
- Relevant debug output (`-D`)
- NAT redirection rules in use, if relevant
- List of failing unit tests from `make test`
- Logs, PCAPs, screenshots, or other supporting materials

### When Reporting Build Problems

- Your OS version and output of `uname -a`
- Full output of the failed `make` run (including the header)
- Version and origin of OpenSSL and libevent

---

## 💡 Pull Requests

We welcome pull requests that:

- Fix bugs or security issues
- Add features or usability improvements
- Improve documentation or tests

### Guidelines

- Fork the repository and create your branch from `main` or the default branch.
- Write clear, descriptive commit messages.
- Ensure your code passes existing tests (`make test` or equivalent).
- Add new tests for new features or bug fixes if possible.
- Document any new behavior or configuration options.
- Make sure your code style is consistent with the rest of the project.

---

## 📝 Code of Conduct

This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## 🙏 Thank You

We appreciate your time and interest in making this project better!  
Your contributions help keep open source security strong.

---