#!/usr/bin/env bash
# Run on the Wazuh manager after copying the rule files:  sudo ./run_wazuh_tests.sh
# Uses wazuh-logtest unit mode (-U rule:level:decoder) for each expected case,
# and checks that "none" cases match none of rules 100700-100721.
set -u
LT=/var/ossec/bin/wazuh-logtest
DIR=$(cd "$(dirname "$0")" && pwd)
pass=0; fail=0
run() {   # $1 file
  while IFS=$'\t' read -r exp line; do
    case "$exp" in ''|\#*) continue ;; esac
    if [ "$exp" = none ]; then
      hit=$(echo "$line" | $LT 2>&1 | grep -oE "id: '1007([01][0-9]|2[01])'")
      if [ -z "$hit" ]; then pass=$((pass+1)); echo "PASS none"; else fail=$((fail+1)); echo "FAIL expected none, got $hit | $line"; fi
    else
      id=${exp%%:*}; lvl=${exp#*:}
      if echo "$line" | $LT -q -U "$id:$lvl:json" >/dev/null 2>&1; then pass=$((pass+1)); echo "PASS $id/$lvl"
      else fail=$((fail+1)); echo "FAIL $id/$lvl | $line"; fi
    fi
  done < "$1"
}
run "$DIR/wazuh_event_cases.txt"
run "$DIR/wazuh_receiver_cases.txt"
echo "frequency: 5 rejections from one source (expect 100716 x4 then 100718)"
for i in 1 2 3 4 5; do echo '{"result": "rejected", "reason": "ip_not_allowed", "source_ip": "203.0.113.10"}'; done \
  | $LT 2>&1 | grep -oE "id: '10071[68]'" | tr '\n' ' '; echo
echo "RESULT: $pass pass, $fail fail"
[ "$fail" -eq 0 ]
