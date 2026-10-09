# Fixtures for SandvaultWorkflowTests

Host user `alice`, sandbox user `sandvault-alice`. Rows marked **synthetic** were written from the documented output
format, not captured on a Mac; replace each with real output and remove the word `synthetic` from its row. The git
rows were captured with git 2.43.0 on Linux (git's porcelain and `-z` formats are the same on macOS); the commands are
in the scratch script that produced them, reproduced here.

| File | Command on a Mac | Status |
|---|---|---|
| `otool-L-system-only.txt` | `/usr/bin/otool -L /opt/homebrew/Cellar/gh/2.62.0/bin/gh` (a Go binary: only `/usr/lib` and `/System` libraries) | synthetic |
| `otool-L-homebrew.txt` | `/usr/bin/otool -L /opt/homebrew/Cellar/jq/1.7.1/bin/jq` (links a Homebrew dylib) | synthetic |
| `otool-L-universal.txt` | `/usr/bin/otool -L /usr/local/bin/tool` for a universal binary with an `@rpath` library (one block per architecture) | synthetic |
| `brew-info-jq.json` | `brew info --json=v2 jq` (trimmed to the fields that matter) | synthetic |
| `brew-info-missing.stderr.txt` | stderr of `brew info --json=v2 rg` (no formula of that name; exit 1) | synthetic |
| `ssh-keygen-l-ed25519.txt` | `ssh-keygen -l -f ~/.config/codeofhonor/sandvault/authorized_keys.d/laptop` | synthetic |
| `sandbox-lookup-found.txt` | `sudo -n -u sandvault-alice /usr/bin/env -i HOME=/Users/sandvault-alice USER=sandvault-alice SHELL=/bin/zsh SHARED_WORKSPACE=/Users/Shared/sv-alice PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/sandbox-exec -f /var/sandvault/sandbox-sandvault-alice.sb /bin/zsh -c 'source ~/.zshenv; source ~/.zprofile; print -r -- sandvault-config:lookup; command -v -- jq'` | synthetic |
| `sandbox-lookup-missing.txt` | the same command for a name the sandbox does not have (exit 1) | synthetic |
| `git-symbolic-ref.txt` | `git symbolic-ref --quiet --short HEAD` in a clone | git 2.43.0 |
| `git-log-head.txt` | `git -c log.showSignature=false log -1 --no-color --format='%H %ct' HEAD` | git 2.43.0 |
| `git-rev-list-left-right.txt` | `git rev-list --left-right --count '@{upstream}...HEAD'` (1 behind, 2 ahead) | git 2.43.0 |
| `git-config-filters.bin` | `git config -z --name-only --get-regexp '^filter\.'` (NUL-separated; drivers `lfs` and `my.driver`) | git 2.43.0 |
| `git-status-dirty.bin` | `git --no-optional-locks status --porcelain=v1 -z --untracked-files=normal --ignore-submodules=all --no-renames` | git 2.43.0 |

Setup for the git rows: a bare `origin` with two commits, a clone that has one of them plus two local commits and a
fetch of the second, `filter.lfs.clean`, `filter.lfs.required` and `filter.my.driver.process` in its config, a
modified tracked file and an untracked file.
