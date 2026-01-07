
#!/usr/bin/env bash
set -euo pipefail

BASE="https://nodehncngtke-ayjx--3000--365214aa.local-corp.webcontainer.io"

echo "== GET / =="
curl -s -i "$BASE/"

echo "== POST /user =="
curl -s -i -X POST "$BASE/user" -H "Content-Type: application/json" -d '{"name":"山田"}'

echo "== GET /classes =="
curl -s -i "$BASE/classes"

echo "== GET /classes/101 =="
curl -s -i "$BASE/classes/101"

echo "== POST /register =="
curl -s -i -X POST "$BASE/register" -H "Content-Type: application/json" \
  -d '{"student_name":"佐藤太郎","parent_name":"佐藤花子","school_name":"広瀬中","login_id":"sato1","password":"p@ss","grade":3,"email":"taro@example.com"}'

echo "== POST /login =="
curl -s -i -X POST "$BASE/login" -H "Content-Type: application/json" \
  -d '{"login_id":"sato1","password":"p@ss"}'

echo "== POST /applications (締切後で400想定) =="
curl -s -i -X POST "$BASE/applications" -H "Content-Type: application/json" \
  -d '{"user_id":1,"session_id":5001}'

echo "== GET /applications/mine?user_id=1 =="
curl -s -i "$BASE/applications/mine?user_id=1"

echo "== POST /admin/lottery =="
curl -s -i -X POST "$BASE/admin/lottery"
