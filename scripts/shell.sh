# shellcheck shell=bash
detect_shell_kind() {
  local kind="other"
  local omz=0

  if [ -n "${ZSH_VERSION:-}" ] || printf '%s' "${SHELL:-}" | grep -q 'zsh'; then
    kind="zsh"
    if [ -n "${ZSH:-}" ] && [ -d "$ZSH" ] && [ -f "$ZSH/oh-my-zsh.sh" ]; then
      omz=1
    elif [ -d "$HOME/.oh-my-zsh" ] && [ -f "$HOME/.oh-my-zsh/oh-my-zsh.sh" ]; then
      omz=1
    fi
  elif [ -n "${BASH_VERSION:-}" ] || printf '%s' "${SHELL:-}" | grep -q 'bash'; then
    kind="bash"
  fi

  printf '%s %s\n' "$kind" "$omz"
}

reload_shell_rc() {
  local force=0
  if [ "${1:-}" = "--force" ]; then
    force=1
  fi

  local kind=""
  local omz=""
  IFS=' ' read -r kind omz <<<"$(detect_shell_kind)"
  [ -n "$kind" ] || kind="other"
  [ -n "$omz" ] || omz=0

  if [ "$kind" = "zsh" ] && [ "$omz" -eq 1 ] && have_command omz; then
    if omz reload; then
      return 0
    fi
  fi

  local rc=""
  case "$kind" in
    zsh)
      [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
      ;;
    bash)
      if [ -r "$HOME/.bashrc" ]; then
        rc="$HOME/.bashrc"
      elif [ -r "$HOME/.bash_profile" ]; then
        rc="$HOME/.bash_profile"
      elif [ -r "$HOME/.profile" ]; then
        rc="$HOME/.profile"
      fi
      ;;
    *)
      [ -r "$HOME/.profile" ] && rc="$HOME/.profile"
      ;;
  esac

  if [ -z "$rc" ] && [ "$kind" = "zsh" ] && [ "$omz" -eq 1 ]; then
    [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
  fi

  if [ -n "$rc" ] && [ -r "$rc" ]; then
    # shellcheck disable=SC1090
    . "$rc" || return 1
    return 0
  fi

  if [ "$force" -eq 1 ]; then
    return 0
  fi

  return 1
}

