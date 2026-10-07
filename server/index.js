const express = require('express');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { initDatabase, getDb, save } = require('./db');
const { generateToken, authMiddleware, teacherOnly } = require('./auth');
const multer = require('multer');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '30d',
  immutable: true
}));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = Date.now() + '-' + Math.round(Math.random() * 1E9) + ext;
    cb(null, name);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowedImage = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const allowedVideo = ['.mp4', '.webm', '.mov', '.avi'];
    const ext = path.extname(file.originalname).toLowerCase();
    if ([...allowedImage, ...allowedVideo].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('不支持的文件格式'));
    }
  }
});

// ============ Auth Routes ============

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }
  const db = getDb();
  const result = db.exec("SELECT * FROM users WHERE username = ?", [username]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }
  const cols = result[0].columns;
  const vals = result[0].values[0];
  const user = {};
  cols.forEach((c, i) => user[c] = vals[i]);

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  const token = generateToken(user);
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, display_name: user.display_name }
  });
});

app.post('/api/auth/register-teacher', (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请填写完整信息' });
  }
  const db = getDb();
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, 'teacher', ?)",
      [username, hash, display_name || username]);
    save();
    res.json({ message: '注册成功' });
  } catch (e) {
    res.status(400).json({ error: '用户名已存在' });
  }
});

app.post('/api/auth/register-students', authMiddleware, teacherOnly, (req, res) => {
  const { students, password } = req.body;
  if (!students || !Array.isArray(students) || !password) {
    return res.status(400).json({ error: '请提供学生名单和统一密码' });
  }
  const db = getDb();
  const hash = bcrypt.hashSync(password, 10);
  const results = [];
  for (const name of students) {
    const trimmed = name.trim();
    if (!trimmed) continue;
    try {
      db.run("INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, 'student', ?)",
        [trimmed, hash, trimmed]);
      const r = db.exec("SELECT last_insert_rowid() as id");
      const id = r[0].values[0][0];
      results.push({ id, username: trimmed, display_name: trimmed });
    } catch (e) {
      // Student already exists, get their id
      const existing = db.exec("SELECT id, display_name FROM users WHERE username = ?", [trimmed]);
      if (existing.length > 0 && existing[0].values.length > 0) {
        results.push({ id: existing[0].values[0][0], username: trimmed, display_name: existing[0].values[0][1] });
      }
    }
  }
  save();
  res.json({ message: `成功处理 ${results.length} 个学生账号`, students: results });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const db = getDb();
  const result = db.exec("SELECT id, username, role, display_name, created_at FROM users WHERE id = ?", [req.user.id]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(404).json({ error: '用户不存在' });
  }
  const cols = result[0].columns;
  const vals = result[0].values[0];
  const user = {};
  cols.forEach((c, i) => user[c] = vals[i]);
  res.json(user);
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: '已退出登录' });
});

// ============ Student Management ============

app.get('/api/students', authMiddleware, teacherOnly, (req, res) => {
  const db = getDb();
  const result = db.exec("SELECT id, username, display_name, created_at FROM users WHERE role = 'student' ORDER BY id");
  const students = [];
  if (result.length > 0) {
    const cols = result[0].columns;
    result[0].values.forEach(v => {
      const s = {};
      cols.forEach((c, i) => s[c] = v[i]);
      students.push(s);
    });
  }
  res.json(students);
});

app.delete('/api/students/:id', authMiddleware, teacherOnly, (req, res) => {
  const db = getDb();
  db.run("DELETE FROM users WHERE id = ? AND role = 'student'", [req.params.id]);
  save();
  res.json({ message: '已删除' });
});

// ============ Topic Routes ============

app.post('/api/topics', authMiddleware, teacherOnly, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: '请输入投票主题' });
  const db = getDb();
  db.run("INSERT INTO topics (title, teacher_id, status) VALUES (?, ?, 'active')", [title, req.user.id]);
  const r = db.exec("SELECT last_insert_rowid()");
  const id = r[0].values[0][0];
  save();
  res.json({ id, title, message: '主题创建成功' });
});

app.get('/api/topics', authMiddleware, (req, res) => {
  const db = getDb();
  let result;
  if (req.user.role === 'teacher') {
    result = db.exec(`
      SELECT t.*, u.display_name as teacher_name,
        (SELECT COUNT(DISTINCT s.id) FROM submissions s WHERE s.topic_id = t.id) as submission_count
      FROM topics t JOIN users u ON t.teacher_id = u.id
      ORDER BY t.created_at DESC
    `);
  } else {
    result = db.exec("SELECT t.*, u.display_name as teacher_name FROM topics t JOIN users u ON t.teacher_id = u.id WHERE t.status = 'active' ORDER BY t.created_at DESC");
  }
  const topics = [];
  if (result.length > 0) {
    const cols = result[0].columns;
    result[0].values.forEach(v => {
      const t = {};
      cols.forEach((c, i) => t[c] = v[i]);
      topics.push(t);
    });
  }
  res.json(topics);
});

app.get('/api/topics/:id', authMiddleware, (req, res) => {
  const db = getDb();
  const result = db.exec(`
    SELECT t.*, u.display_name as teacher_name,
      (SELECT COUNT(*) FROM votes v WHERE v.topic_id = t.id) as total_votes,
      (SELECT COUNT(*) FROM comments c WHERE c.topic_id = t.id) as total_comments,
      (SELECT COUNT(*) FROM submissions s WHERE s.topic_id = t.id) as submission_count
    FROM topics t JOIN users u ON t.teacher_id = u.id WHERE t.id = ?
  `, [req.params.id]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(404).json({ error: '主题不存在' });
  }
  const cols = result[0].columns;
  const vals = result[0].values[0];
  const topic = {};
  cols.forEach((c, i) => topic[c] = vals[i]);

  // Record view
  try {
    db.run("INSERT INTO topic_views (topic_id, user_id) VALUES (?, ?)", [req.params.id, req.user.id]);
    save();
  } catch(e) {}

  res.json(topic);
});

app.put('/api/topics/:id/end', authMiddleware, teacherOnly, (req, res) => {
  const db = getDb();
  db.run("UPDATE topics SET status = 'ended', ended_at = datetime('now', 'localtime') WHERE id = ?",
    [req.params.id]);
  save();
  res.json({ message: '投票已结束' });
});

app.delete('/api/topics/:id', authMiddleware, teacherOnly, (req, res) => {
  const db = getDb();
  const topicId = req.params.id;

  const topic = db.exec("SELECT id FROM topics WHERE id = ?", [topicId]);
  if (topic.length === 0 || topic[0].values.length === 0) {
    return res.status(404).json({ error: '投票不存在' });
  }

  const fileResult = db.exec(`
    SELECT sf.file_path
    FROM submission_files sf
    JOIN submissions s ON sf.submission_id = s.id
    WHERE s.topic_id = ?
  `, [topicId]);

  const filePaths = [];
  if (fileResult.length > 0) {
    fileResult[0].values.forEach(row => filePaths.push(row[0]));
  }

  db.run("DELETE FROM votes WHERE topic_id = ?", [topicId]);
  db.run("DELETE FROM comments WHERE topic_id = ?", [topicId]);
  db.run("DELETE FROM topic_views WHERE topic_id = ?", [topicId]);
  db.run("DELETE FROM submission_files WHERE submission_id IN (SELECT id FROM submissions WHERE topic_id = ?)", [topicId]);
  db.run("DELETE FROM submissions WHERE topic_id = ?", [topicId]);
  db.run("DELETE FROM topics WHERE id = ?", [topicId]);

  for (const filePath of filePaths) {
    const fullPath = path.join(__dirname, 'uploads', filePath);
    try {
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    } catch (e) {
      console.warn(`Failed to delete upload ${filePath}:`, e.message);
    }
  }

  save();
  res.json({ message: '投票已删除' });
});

// ============ Submission Routes ============

app.post('/api/topics/:topicId/submissions', authMiddleware, teacherOnly, upload.array('files', 10), (req, res) => {
  const { topicId } = req.params;
  const { student_id, text_content } = req.body;
  if (!student_id) return res.status(400).json({ error: '请指定学生' });

  const db = getDb();

  // Check if submission already exists
  const existing = db.exec("SELECT id FROM submissions WHERE topic_id = ? AND student_id = ?", [topicId, student_id]);

  let submissionId;
  if (existing.length > 0 && existing[0].values.length > 0) {
    // Update existing
    submissionId = existing[0].values[0][0];
    db.run("UPDATE submissions SET text_content = ? WHERE id = ?", [text_content || '', submissionId]);
  } else {
    // Create new
    db.run("INSERT INTO submissions (topic_id, student_id, text_content) VALUES (?, ?, ?)",
      [topicId, student_id, text_content || '']);
    const r = db.exec("SELECT last_insert_rowid()");
    submissionId = r[0].values[0][0];
  }

  // Add files
  if (req.files && req.files.length > 0) {
    for (const file of req.files) {
      const ext = path.extname(file.originalname).toLowerCase();
      const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      const fileType = imageExts.includes(ext) ? 'image' : 'video';
      db.run("INSERT INTO submission_files (submission_id, file_type, file_path) VALUES (?, ?, ?)",
        [submissionId, fileType, file.filename]);
    }
  }

  save();
  res.json({ message: '作业已保存', submission_id: submissionId });
});

// Batch upload submissions
app.post('/api/topics/:topicId/submissions/batch', authMiddleware, teacherOnly, upload.array('files', 50), (req, res) => {
  const { topicId } = req.params;
  const submissionsData = JSON.parse(req.body.submissions || '[]');
  const db = getDb();

  // Build file map by fieldname
  const fileMap = {};
  if (req.files) {
    req.files.forEach(f => {
      const match = f.fieldname.match(/^files_(\d+)$/);
      if (match) {
        if (!fileMap[match[1]]) fileMap[match[1]] = [];
        fileMap[match[1]].push(f);
      } else {
        // files without student index go to a general pool
        if (!fileMap['general']) fileMap['general'] = [];
        fileMap['general'].push(f);
      }
    });
  }

  const results = [];
  for (const item of submissionsData) {
    const { student_id, text_content } = item;
    if (!student_id) continue;

    const existing = db.exec("SELECT id FROM submissions WHERE topic_id = ? AND student_id = ?", [topicId, student_id]);

    let submissionId;
    if (existing.length > 0 && existing[0].values.length > 0) {
      submissionId = existing[0].values[0][0];
      const currentText = db.exec("SELECT text_content FROM submissions WHERE id = ?", [submissionId]);
      const oldText = currentText[0]?.values[0]?.[0] || '';
      db.run("UPDATE submissions SET text_content = ? WHERE id = ?", [text_content || oldText, submissionId]);
    } else {
      db.run("INSERT INTO submissions (topic_id, student_id, text_content) VALUES (?, ?, ?)",
        [topicId, student_id, text_content || '']);
      const r = db.exec("SELECT last_insert_rowid()");
      submissionId = r[0].values[0][0];
    }

    // Add files for this student
    const files = fileMap[String(student_id)] || [];
    for (const file of files) {
      const ext = path.extname(file.originalname).toLowerCase();
      const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      const fileType = imageExts.includes(ext) ? 'image' : 'video';
      db.run("INSERT INTO submission_files (submission_id, file_type, file_path) VALUES (?, ?, ?)",
        [submissionId, fileType, file.filename]);
    }

    results.push({ student_id, submission_id: submissionId });
  }

  save();
  res.json({ message: `成功保存 ${results.length} 份作业`, results });
});

// Get submissions for a topic
app.get('/api/topics/:topicId/submissions', authMiddleware, (req, res) => {
  const db = getDb();
  const page = Math.max(parseInt(req.query.page, 10) || 0, 0);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 0, 1), 50);
  const usePagination = page > 0 && limit > 0;
  const offset = usePagination ? (page - 1) * limit : 0;

  const totalResult = db.exec("SELECT COUNT(*) FROM submissions WHERE topic_id = ?", [req.params.topicId]);
  const total = totalResult[0]?.values[0]?.[0] || 0;

  const paginationClause = usePagination ? "LIMIT ? OFFSET ?" : "";
  const queryParams = usePagination ? [req.params.topicId, limit, offset] : [req.params.topicId];
  const result = db.exec(`
    SELECT s.*, u.display_name as student_name,
      (SELECT COUNT(*) FROM votes v WHERE v.submission_id = s.id) as vote_count,
      (SELECT COUNT(*) FROM comments c WHERE c.submission_id = s.id) as comment_count
    FROM submissions s
    JOIN users u ON s.student_id = u.id
    WHERE s.topic_id = ?
    ORDER BY s.created_at ASC
    ${paginationClause}
  `, queryParams);

  const submissions = [];
  if (result.length > 0) {
    const cols = result[0].columns;
    result[0].values.forEach(v => {
      const s = {};
      cols.forEach((c, i) => s[c] = v[i]);
      submissions.push(s);
    });
  }

  // Get files for each submission
  for (const sub of submissions) {
    const files = db.exec("SELECT id, file_type, file_path FROM submission_files WHERE submission_id = ?", [sub.id]);
    sub.files = [];
    if (files.length > 0) {
      const fcols = files[0].columns;
      files[0].values.forEach(v => {
        const f = {};
        fcols.forEach((c, i) => f[c] = v[i]);
        sub.files.push(f);
      });
    }

    // Check if current user voted
    const voted = db.exec("SELECT id FROM votes WHERE submission_id = ? AND voter_id = ?", [sub.id, req.user.id]);
    sub.has_voted = voted.length > 0 && voted[0].values.length > 0;
  }

  if (usePagination) {
    return res.json({
      items: submissions,
      page,
      limit,
      total,
      has_more: offset + submissions.length < total
    });
  }

  res.json(submissions);
});

// ============ Vote Routes ============

app.post('/api/submissions/:submissionId/vote', authMiddleware, (req, res) => {
  const db = getDb();
  const { submissionId } = req.params;

  // Get topic and check if active
  const subResult = db.exec("SELECT topic_id FROM submissions WHERE id = ?", [submissionId]);
  if (subResult.length === 0) return res.status(404).json({ error: '作业不存在' });
  const topicId = subResult[0].values[0][0];

  const topicResult = db.exec("SELECT status FROM topics WHERE id = ?", [topicId]);
  if (topicResult.length > 0 && topicResult[0].values[0][0] === 'ended') {
    return res.status(400).json({ error: '投票已结束' });
  }

  // Check if already voted
  const existing = db.exec("SELECT id FROM votes WHERE submission_id = ? AND voter_id = ?",
    [submissionId, req.user.id]);
  if (existing.length > 0 && existing[0].values.length > 0) {
    // Unvote
    db.run("DELETE FROM votes WHERE submission_id = ? AND voter_id = ?", [submissionId, req.user.id]);
    save();
    return res.json({ voted: false, message: '已取消投票' });
  }

  db.run("INSERT INTO votes (topic_id, submission_id, voter_id) VALUES (?, ?, ?)",
    [topicId, submissionId, req.user.id]);
  save();
  res.json({ voted: true, message: '投票成功' });
});

// ============ Comment Routes ============

app.post('/api/submissions/:submissionId/comments', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: '请输入评论内容' });

  const db = getDb();
  const subResult = db.exec("SELECT topic_id FROM submissions WHERE id = ?", [req.params.submissionId]);
  if (subResult.length === 0) return res.status(404).json({ error: '作业不存在' });
  const topicId = subResult[0].values[0][0];

  db.run("INSERT INTO comments (topic_id, submission_id, user_id, content) VALUES (?, ?, ?, ?)",
    [topicId, req.params.submissionId, req.user.id, content]);
  save();

  const r = db.exec("SELECT last_insert_rowid()");
  const commentId = r[0].values[0][0];

  res.json({ id: commentId, content, user_id: req.user.id, display_name: req.user.display_name });
});

app.delete('/api/comments/:id', authMiddleware, (req, res) => {
  const db = getDb();
  const result = db.exec("SELECT id, user_id FROM comments WHERE id = ?", [req.params.id]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(404).json({ error: '评论不存在' });
  }

  const userId = result[0].values[0][1];
  if (req.user.role !== 'teacher' && userId !== req.user.id) {
    return res.status(403).json({ error: '不能删除这条评论' });
  }

  db.run("DELETE FROM comments WHERE id = ?", [req.params.id]);
  save();
  res.json({ message: '已删除' });
});
app.get('/api/submissions/:submissionId/comments', authMiddleware, (req, res) => {
  const db = getDb();
  const result = db.exec(`
    SELECT c.id, c.content, c.created_at, c.user_id, u.display_name, u.role
    FROM comments c JOIN users u ON c.user_id = u.id
    WHERE c.submission_id = ?
    ORDER BY c.created_at ASC
  `, [req.params.submissionId]);

  const comments = [];
  if (result.length > 0) {
    const cols = result[0].columns;
    result[0].values.forEach(v => {
      const c = {};
      cols.forEach((col, i) => c[col] = v[i]);
      comments.push(c);
    });
  }
  res.json(comments);
});

// ============ Report Routes ============

app.get('/api/topics/:topicId/report', authMiddleware, teacherOnly, (req, res) => {
  const db = getDb();
  const topicId = req.params.topicId;

  // View count
  const views = db.exec("SELECT COUNT(*) FROM topic_views WHERE topic_id = ?", [topicId]);
  const viewCount = views[0]?.values[0]?.[0] || 0;

  // Vote count
  const votes = db.exec("SELECT COUNT(*) FROM votes WHERE topic_id = ?", [topicId]);
  const voteCount = votes[0]?.values[0]?.[0] || 0;

  // Comment count
  const commentsCount = db.exec("SELECT COUNT(*) FROM comments WHERE topic_id = ?", [topicId]);
  const commentCount = commentsCount[0]?.values[0]?.[0] || 0;

  // All comments text for word cloud
  const commentsText = db.exec("SELECT content FROM comments WHERE topic_id = ?", [topicId]);
  const allComments = [];
  if (commentsText.length > 0) {
    commentsText[0].values.forEach(v => allComments.push(v[0]));
  }

  // Submission stats
  const subStats = db.exec(`
    SELECT s.id, u.display_name,
      (SELECT COUNT(*) FROM votes v WHERE v.submission_id = s.id) as votes,
      (SELECT COUNT(*) FROM comments c WHERE c.submission_id = s.id) as comments
    FROM submissions s JOIN users u ON s.student_id = u.id
    WHERE s.topic_id = ?
    ORDER BY votes DESC
  `, [topicId]);

  const submissions = [];
  if (subStats.length > 0) {
    const cols = subStats[0].columns;
    subStats[0].values.forEach(v => {
      const s = {};
      cols.forEach((c, i) => s[c] = v[i]);
      submissions.push(s);
    });
  }

  res.json({
    view_count: viewCount,
    vote_count: voteCount,
    comment_count: commentCount,
    comments_text: allComments,
    submissions
  });
});

// ============ Serve React App (production) ============

app.use('/assets', express.static(path.join(__dirname, '..', 'client', 'dist', 'assets'), {
  maxAge: '30d',
  immutable: true
}));
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));

app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'dist', 'index.html'));
});

// ============ Seed Data & Start ============

async function seedData() {
  const db = getDb();

  // Check if seed data already exists
  const existing = db.exec("SELECT COUNT(*) FROM users");
  if (existing[0].values[0][0] > 0) return;

  // Create teacher account
  const teacherHash = bcrypt.hashSync('ls123456', 10);
  db.run("INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, 'teacher', ?)",
    ['实验-老师', teacherHash, '实验-老师']);

  // Create student account
  const studentHash = bcrypt.hashSync('xs123456', 10);
  db.run("INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, 'student', ?)",
    ['实验-学生', studentHash, '实验-学生']);

  save();
  console.log('Seed data created: 实验-老师 / ls123456, 实验-学生 / xs123456');
}

async function start() {
  await initDatabase();
  await seedData();

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

start().catch(console.error);

module.exports = app;
