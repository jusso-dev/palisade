# Git hooks (opt-in)

Hooks that run the quick local checks before Git records a commit (#29).
They are **not** enabled by cloning, by the dev container or by any
command in the repository. Turn them on for your clone with:

```sh
git config core.hooksPath .githooks
```

Turn them off with `git config --unset core.hooksPath`. Skip them for one
commit with `git commit --no-verify`. CI runs the same checks either way.

| Hook | Runs |
|---|---|
| `pre-commit` | `cargo fmt --all --check`; `typos` if installed; `cargo xtask check-banned-terms` once that command exists (#27) |
| `commit-msg` | `cargo xtask check-commit-msg`: the Conventional Commit rule CI applies to PR titles |

They need Bash (on Windows, the Bash that comes with Git), and `cargo`
on `PATH`.
