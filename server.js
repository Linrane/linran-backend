const express = require('express');
const cors = require('cors');
const jsonfile = require('jsonfile');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const DB_FILE = 'database.json';
const JWT_SECRET = 'linran-secret-key-23333'; // 生产环境要改复杂点

// 中间件
app.use(cors());
app.use(express.json());

// 辅助函数：读取数据库
async function readDB() {
  try {
    return await jsonfile.readFile(DB_FILE);
  } catch (error) {
    return { users: [], articles: [] };
  }
}

// 辅助函数：写入数据库
async function writeDB(data) {
  await jsonfile.writeFile(DB_FILE, data, { spaces: 2 });
}

// ==================== API接口 ====================

// 1. 用户注册
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    
    const db = await readDB();
    
    // 检查用户名是否存在
    const exists = db.users.find(u => u.username === username);
    if (exists) {
      return res.status(400).json({ error: '用户名已存在' });
    }
    
    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 创建新用户（默认是普通用户，不是管理员）
    const newUser = {
      id: Date.now(), // 简单ID生成
      username,
      password: hashedPassword,
      isAdmin: false,
      createdAt: new Date().toISOString()
    };
    
    db.users.push(newUser);
    await writeDB(db);
    
    // 返回数据（不包含密码）
    res.json({ 
      message: '注册成功！',
      user: { id: newUser.id, username, isAdmin: false }
    });
    
  } catch (error) {
    res.status(500).json({ error: '服务器错误: ' + error.message });
  }
});

// 2. 用户登录
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const db = await readDB();
    const user = db.users.find(u => u.username === username);
    
    if (!user) {
      return res.status(400).json({ error: '用户不存在' });
    }
    
    // 验证密码
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: '密码错误' });
    }
    
    // 生成JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, isAdmin: user.isAdmin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      message: '登录成功！',
      token,
      user: { id: user.id, username: user.username, isAdmin: user.isAdmin }
    });
    
  } catch (error) {
    res.status(500).json({ error: '服务器错误: ' + error.message });
  }
});

// 3. 获取文章列表（公开接口，无需登录）
app.get('/api/articles', async (req, res) => {
  try {
    const db = await readDB();
    // 按日期倒序排列
    const sortedArticles = db.articles.sort((a, b) => 
      new Date(b.date) - new Date(a.date)
    );
    res.json(sortedArticles);
  } catch (error) {
    res.status(500).json({ error: '服务器错误: ' + error.message });
  }
});

// 4. 发布新文章（需要登录）
app.post('/api/articles', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer token
    
    if (!token) {
      return res.status(401).json({ error: '请先登录' });
    }
    
    // 验证token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { title, content } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: '标题和内容不能为空' });
    }
    
    const db = await readDB();
    
    const newArticle = {
      id: Date.now(),
      title,
      content,
      date: new Date().toISOString().split('T')[0], // YYYY-MM-DD
      authorId: decoded.userId
    };
    
    db.articles.push(newArticle);
    await writeDB(db);
    
    res.json({ message: '文章发布成功！', article: newArticle });
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    res.status(500).json({ error: '服务器错误: ' + error.message });
  }
});

// 启动服务器
app.listen(PORT, () => {
  console.log('✨ 凌然后端服务器已启动！');
  console.log(`📡 API地址: http://localhost:${PORT}`);
  console.log(`📄 数据库文件: ${DB_FILE}`);
});


// 5. 删除文章（需要登录且是作者或管理员）
app.delete('/api/articles/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: '请先登录' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await readDB();
    
    const articleId = parseInt(req.params.id);
    const articleIndex = db.articles.findIndex(a => a.id === articleId);
    
    if (articleIndex === -1) {
      return res.status(404).json({ error: '文章不存在' });
    }
    
    const article = db.articles[articleIndex];
    
    // 检查权限（只有作者本人或管理员能删除）
    if (article.authorId !== decoded.userId && !decoded.isAdmin) {
      return res.status(403).json({ error: '无权删除此文章' });
    }
    
    // 删除文章
    db.articles.splice(articleIndex, 1);
    await writeDB(db);
    
    res.json({ message: '文章删除成功' });
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: '登录已过期' });
    }
    res.status(500).json({ error: '服务器错误: ' + error.message });
  }
});