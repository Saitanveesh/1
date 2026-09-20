T=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill | sed -n 's/^password=//p'); SHA=$(git rev-parse HEAD)
for i in $(seq 1 38); do curl -s -H "Authorization: Bearer $T" https://api.github.com/repos/Saitanveesh/1/commits/$SHA/check-runs > .cr.json; n=$(python -c "
import json;d=json.load(open('.cr.json'))['check_runs'];print(sum(c['status']!='completed' for c in d), len(d))"); case "$n" in "0 "[1-9]*) break;; esac; sleep 15; done
python -c "
import json
for c in json.load(open('.cr.json'))['check_runs']: print(c['name'],c['status'],c['conclusion'])"
unset T
