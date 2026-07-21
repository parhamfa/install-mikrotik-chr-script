#!/usr/bin/env bash
set -Eeuo pipefail

readonly repository="${CHR_INSTALL_REPOSITORY:-parhamfa/chr-install}"
readonly asset="chr-install-linux-amd64"
readonly release_base="https://github.com/${repository}/releases/latest/download"

fail() {
  printf 'chr-install bootstrap: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) fail "AMD64 is required" ;;
esac
[[ "${EUID}" -eq 0 ]] || fail "run through sudo or as root"

for command in curl sha256sum mktemp; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done

work_dir=""
select_work_dir() {
  local candidate candidate_dir probe
  for candidate in "${CHR_INSTALL_TMPDIR:-}" "${TMPDIR:-}" /var/tmp /tmp; do
    [[ -n "${candidate}" && -d "${candidate}" && -w "${candidate}" ]] || continue
    candidate_dir="$(mktemp -d -p "${candidate}" chr-install.XXXXXXXX 2>/dev/null)" || continue
    probe="${candidate_dir}/.exec-test"
    printf '#!/bin/sh\nexit 0\n' >"${probe}"
    chmod 0700 "${probe}"
    if "${probe}" >/dev/null 2>&1; then
      rm -f "${probe}"
      work_dir="${candidate_dir}"
      return 0
    fi
    rm -f "${probe}"
    rmdir "${candidate_dir}" 2>/dev/null || true
  done
  fail "no writable executable temporary directory is available; set CHR_INSTALL_TMPDIR to one"
}
select_work_dir
readonly work_dir
cleanup() {
  if [[ -n "${work_dir:-}" && -d "${work_dir}" ]]; then
    rm -f "${work_dir}/${asset}" "${work_dir}/${asset}.sha256"
    rmdir "${work_dir}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

readonly -a curl_options=(
  --proto '=https' --tlsv1.2 --fail --silent --show-error --location
  --retry 4 --retry-all-errors --retry-delay 2
  --connect-timeout 15 --max-time 900
)

curl "${curl_options[@]}" \
  "${release_base}/${asset}" --output "${work_dir}/${asset}"
curl "${curl_options[@]}" \
  "${release_base}/${asset}.sha256" --output "${work_dir}/${asset}.sha256"

(
  cd "${work_dir}"
  sha256sum --check --status "${asset}.sha256"
) || fail "release checksum verification failed"

chmod 0700 "${work_dir}/${asset}"
if [[ -t 0 && -r /dev/tty && -w /dev/tty ]]; then
  "${work_dir}/${asset}" "$@" </dev/tty >/dev/tty 2>/dev/tty
else
  "${work_dir}/${asset}" "$@"
fi
