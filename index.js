// index.js — Helmet / bcryptjs / CORS（開発は全許可） / JWT / 管理API（スタブ）
// Express v5対応：ワイルドカード記法は使わず、必要最小限のルートのみ定義

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

/* ============================= ミドルウェア ============================= */

// いったん開発用に全許可（あとで厳格化の差分を提示します）
app.use(cors());

// JSONパーサ
app.use(express.json());

// セキュリティヘッダ
app.use(helmet());

// （任意）アクセスログ
app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

/* ============================= インメモリデータ ============================= */
// 本番ではPrisma/DBへ移行予定

const users = []; // { user_id, login_id, password_hash, student_name, parent_name, school_name, grade, email, registered_at }
let userSeq = 1;

const lectures = [
  {
    lecture_id: 101,
    title: '数学講座',
    description_pdf: '/files/101.pdf',
    teacher_name: '山本',
    location_name: '理科棟A',
    location_code: 'A-101',
    max_capacity: 40,
  },
];

const sessions = [
  {
    session_id: 5001,
    lecture_id: 101,
    start_time: new Date('2025-12-20T10:00:00+09:00'),
    end_time: new Date('2025-12-20T10:50:00+09:00'),
    deadline: new Date('2025-12-18T23:59:59+09:00'),
    capacity: 25,
    current_applicants: 0,
  },
  {
    session_id: 5002,
    lecture_id: 101,
    start_time: new Date('2025-12-20T11:00:00+09:00'),
    end_time: new Date('2025-12-20T11:50:00+09:00'),
    deadline: new Date('2025-12-18T23:59:59+09:00'),
    capacity: 25,
    current_applicants: 0,
  },
];

const applications = []; // { application_id, user_id, session_id, applied_at, status }
let applicationSeq = 1;

/* ============================= ユーティリティ ============================= */

function isOverlap(aStart, aEnd, bStart, bEnd) {
  return aStart < bEnd && aEnd > bStart;
}
function sameDay(d1, d2) {
  const y1 = d1.getFullYear(),
    m1 = d1.getMonth(),
    day1 = d1.getDate();
  const y2 = d2.getFullYear(),
    m2 = d2.getMonth(),
    day2 = d2.getDate();
  return y1 === y2 && m1 === m2 && day1 === day2;
}
function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/* ============================= JWT ============================= */

// 環境変数が無ければ開発用デフォルト
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function auth(requiredRole) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: 'トークン未提供' });
    try {
      const payload = jwt.verify(m[1], JWT_SECRET);
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: '権限不足' });
      }
      req.user = { id: payload.sub, role: payload.role };
      next();
    } catch {
      return res.status(401).json({ error: 'トークン不正' });
    }
  };
}

/* ============================= 疎通用ルート ============================= */

app.get('/', (_req, res) => {
  res.json({ message: 'Hello from Express!' });
});

app.post('/user', (req, res) => {
  const { name } = req.body;
  res.json({ message: `Hello, ${name}!` });
});

/* ============================= 認証・登録 ============================= */

// 仮登録（bcryptjsでハッシュ化）
app.post('/register', async (req, res, next) => {
  try {
    const {
      student_name,
      parent_name,
      school_name,
      login_id,
      password,
      grade,
      email,
    } = req.body;

    if (
      !student_name ||
      !parent_name ||
      !school_name ||
      !login_id ||
      !password ||
      !grade
    ) {
      return res.status(400).json({ error: '必須項目不足' });
    }
    if (users.find((u) => u.login_id === login_id)) {
      return res.status(409).json({ error: 'login_idが登録済み' });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const user = {
      user_id: userSeq++,
      login_id,
      password_hash,
      student_name,
      parent_name,
      school_name,
      grade,
      email: email || '',
      registered_at: new Date(),
    };
    users.push(user);

    res.json({
      status: 'success',
      message: '仮登録が完了しました。確認コードを送信しました。',
    });
  } catch (e) {
    next(e);
  }
});

// ログイン（JWT発行）
app.post('/login', async (req, res, next) => {
  try {
    const { login_id, password } = req.body;
    const u = users.find((x) => x.login_id === login_id);
    if (!u) return res.status(404).json({ error: 'login_idが存在しない' });

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'パスワード不正' });

    const token = signToken({ sub: u.user_id, role: 'student' });
    res.json({ status: 'success', token, role: 'student', user_id: u.user_id });
  } catch (e) {
    next(e);
  }
});

/* ============================= 一般API（講座） ============================= */

app.get('/classes', (_req, res) => {
  const list = lectures.map((lec) => {
    const applied = sessions
      .filter((s) => s.lecture_id === lec.lecture_id)
      .reduce((sum, s) => sum + s.current_applicants, 0);
    return {
      id: lec.lecture_id,
      title: lec.title,
      capacity: lec.max_capacity,
      applied,
      pdf_url: lec.description_pdf || null,
    };
  });
  res.json(list);
});

app.get('/classes/:id', (req, res) => {
  const id = Number(req.params.id);
  const lec = lectures.find((l) => l.lecture_id === id);
  if (!lec) return res.status(404).json({ error: 'not found' });
  const applied = sessions
    .filter((s) => s.lecture_id === id)
    .reduce((sum, s) => sum + s.current_applicants, 0);
  res.json({
    id: lec.lecture_id,
    title: lec.title,
    description: '高校数学の体験授業です',
    capacity: lec.max_capacity,
    applied,
    pdf_url: lec.description_pdf || null,
  });
});

/* ============================= 学生API（JWT必須） ============================= */

// 申込（締切・重複・同時間帯・同日2件の検証）
app.post('/applications', auth('student'), (req, res) => {
  const user_id = req.user.id; // ← トークンから取得
  const { session_id } = req.body;
  const session = sessions.find((s) => s.session_id === Number(session_id));
  if (!session) return res.status(404).json({ error: 'session not found' });

  if (new Date() > session.deadline) {
    return res.status(400).json({ error: '締切後です' });
  }
  if (
    applications.find(
      (a) =>
        a.user_id === Number(user_id) && a.session_id === Number(session_id)
    )
  ) {
    return res.status(409).json({ error: 'すでに申込済み' });
  }

  const already = applications.filter((a) => a.user_id === Number(user_id));
  for (const ap of already) {
    const s2 = sessions.find((s) => s.session_id === ap.session_id);
    if (
      s2 &&
      isOverlap(
        s2.start_time,
        s2.end_time,
        session.start_time,
        session.end_time
      )
    ) {
      return res
        .status(400)
        .json({ error: '同時間帯の別セッションに申込済みです' });
    }
  }

  const dayCount = already.reduce((cnt, ap) => {
    const s2 = sessions.find((s) => s.session_id === ap.session_id);
    return s2 && sameDay(s2.start_time, session.start_time) ? cnt + 1 : cnt;
  }, 0);
  if (dayCount >= 2) {
    return res
      .status(400)
      .json({ error: '1日の参加上限（2件）を超えています' });
  }

  const appObj = {
    application_id: applicationSeq++,
    user_id: Number(user_id),
    session_id: Number(session_id),
    applied_at: new Date(),
    status: 'applied',
  };
  applications.push(appObj);
  session.current_applicants += 1;

  res.json({ status: 'success', message: '申し込みが完了しました' });
});

// 自分の申込一覧（ISO時刻）
app.get('/applications/mine', auth('student'), (req, res) => {
  const uid = Number(req.user.id);
  const mine = applications
    .filter((a) => a.user_id === uid)
    .map((a) => {
      const s = sessions.find((x) => x.session_id === a.session_id);
      const lec = s
        ? lectures.find((l) => l.lecture_id === s.lecture_id)
        : null;
      return {
        class_id: lec ? lec.lecture_id : null,
        class_name: lec ? lec.title : null,
        session_id: s ? s.session_id : null,
        time: s
          ? { start: s.start_time.toISOString(), end: s.end_time.toISOString() }
          : null,
        status: a.status,
      };
    });
  res.json(mine);
});

/* ============================= 管理API（JWT: admin） ============================= */

// 管理者ログイン（スタブ：固定ID/パスでJWT発行）
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  // TODO: 本番はDBのAdminテーブルで照合
  if (username === 'admin' && password === 'secret') {
    const token = signToken({ sub: 0, role: 'admin' });
    return res.json({ status: 'success', token });
  }
  return res.status(401).json({ error: '認証失敗' });
});

// 抽選実行（締切後のみ）
app.post('/admin/lottery', auth('admin'), (_req, res) => {
  const now = new Date();
  const results = [];
  for (const s of sessions) {
    if (now < s.deadline) continue;

    const appl = applications.filter(
      (a) => a.session_id === s.session_id && a.status === 'applied'
    );
    if (appl.length === 0) continue;

    if (appl.length <= s.capacity) {
      for (const a of appl) {
        a.status = 'confirmed';
        results.push({ application_id: a.application_id, result: 'win' });
      }
      continue;
    }

    const shuffled = shuffle(appl);
    const winners = shuffled.slice(0, s.capacity);
    const losers = shuffled.slice(s.capacity);

    for (const w of winners) {
      w.status = 'confirmed';
      results.push({ application_id: w.application_id, result: 'win' });
    }
    for (const l of losers) {
      l.status = 'waitlisted';
      results.push({ application_id: l.application_id, result: 'lose' });
    }
  }
  res.json({ status: 'done', results });
});

/* ============================= エラーハンドラ ============================= */

app.use((err, _req, res, _next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res
      .status(403)
      .json({ error: 'CORS: このオリジンは許可されていません' });
  }
  console.error('[ERROR]', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

/* ============================= サーバ起動 ============================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started on ${PORT}`);
});

