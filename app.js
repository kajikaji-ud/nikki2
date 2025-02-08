require("dotenv").config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Configuration = require('openai');
const OpenAIApi  = require('openai');
const crypto = require("crypto");
const nodemailer = require('nodemailer');

const app = express();

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({extended: true}));

//mysqlの設定
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Taiga1732',
  database: 'nikki'
});

connection.connect((err) => {
  if (err) {
    console.log('error connecting: ' + err.stack);
    return;
  }
  console.log('success');
});

//sessionの設定
app.use(
  session({
    secret: 'my_secret_key',
    resave: false,
    saveUninitialized: false,
  })
);

// OpenAIの設定
const configuration = new Configuration({
  apiKey: process.env.OPENAI_API_KEY,
});
const openai = new OpenAIApi(configuration);


//ユーザーネームの表示
app.use((req, res, next) => {
  if (req.session.userId === undefined) { 
  } else {
    res.locals.userName = req.session.userName; 
  }
  next();
});

app.get('/', (req, res) => {
  res.render('top.ejs');
});

//loginページの表示
app.get('/login', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('セッションの削除に失敗しました:', err);
      return res.render('login.ejs', { errors: ['サーバーエラーが発生しました'] });
    }
    res.render('login.ejs', { errors: [] }); 
  });
});

//loginの処理
app.post('/login', (req, res) => {
  const errors = [];
  const email = req.body.email;
  const plainPassword = req.body.password;

  connection.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    (err, results) => {
      if (err) {
        console.error('データベースエラー:', err);
        errors.push('サーバーエラーが発生しました');
        return res.render('login.ejs', { errors: errors });
      }

      if (results.length === 0) {
        errors.push('このメールアドレスは登録されていません');
        return res.render('login.ejs', { errors: errors });
      }

      if (!results[0].is_verified) {
        errors.push('メールアドレスが未認証です。メールを確認してください。');
        return res.render('login.ejs', { errors: errors });
      }

      const hash = results[0].password;
      bcrypt.compare(plainPassword, hash, (err, isEqual) => {
        if (err) {
          console.error('bcryptエラー:', err);
          errors.push('サーバーエラーが発生しました');
          return res.render('login.ejs', { errors: errors });
        }

        if (isEqual) {
          req.session.userId = results[0].id;
          req.session.userName = results[0].name; 
          return res.redirect('/list');
        } else {
          errors.push('パスワードが間違っています');
          return res.render('login.ejs', { errors: errors });
        }
      });
    }
  );
});

//新規登録ページの表示
app.get('/signup', (req, res) => {
  res.render('signup.ejs', { errors: [] });
});

//新規登録の処理
app.post('/signup',
  (req, res, next) => {
    const regEmail = req.body.regEmail;
    const regPassword = req.body.regPassword;
    const regConfirmPassword = req.body.regConfirmPassword;
    const errors = [];

    connection.query(
      'SELECT * FROM users WHERE email = ?',
      [regEmail],
      (err, results) => {
        if (err) {
          console.error(err);
          errors.push('データベースエラーが発生しました');
        }

        if (results.length > 0) {
          errors.push('このメールアドレスはすでに使用されています');
        }

        if (regPassword !== regConfirmPassword) {
          errors.push('確認用に入力されたパスワードが間違っています');
        }

        if (errors.length > 0) {
          return res.render('signup.ejs', { errors: errors });
        } else {
          next();
        }
      }
    );
  },

  (req, res) => {
    const regName = req.body.regName;
    const regEmail = req.body.regEmail;
    const regPassword = req.body.regPassword;

    const verificationTokenExpiry = new Date(Date.now() + 3600000);
    const verificationToken = crypto.randomBytes(32).toString("hex"); // トークンを生成
    const verificationLink = `http://localhost:3000/verify/${verificationToken}?email=${encodeURIComponent(regEmail)}`; // 確認リンク
    const errors = [];

    bcrypt.hash(regPassword, 10, (error, hash) => {
      connection.beginTransaction((err) => {
        if (err) {
          console.error('トランザクション開始エラー:', err);
          errors.push('トランザクション開始に失敗しました');
          return res.render('signup.ejs', { errors });
        }

        // ユーザーをデータベースに挿入
        connection.query(
          'INSERT INTO users (name, email, password, is_verified, verification_token, verification_token_expiry) VALUES (?, ?, ?, false, ?, ?)',
          [regName, regEmail, hash, verificationToken, verificationTokenExpiry],
          (err, results) => {
            if (err) {
              console.error('ユーザー挿入エラー:', err);
              return connection.rollback(() => {
                errors.push('登録に失敗しました');
                res.render('signup.ejs', { errors });
              });
            }

            // メール送信設定
            const transporter = nodemailer.createTransport({
              service: 'gmail',
              auth: {
                user: process.env.EMAIL_USER, // 環境変数に設定したメールアドレス
                pass: process.env.EMAIL_PASS  // 環境変数に設定したアプリパスワード
              }
            });

            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: regEmail,
              subject: 'メールアドレスの確認',
              text: `以下のリンクをクリックしてメールアドレスを確認してください: ${verificationLink}`
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('メール送信エラー:', error);
                return connection.rollback(() => {
                  errors.push('確認メールの送信に失敗しました');
                  res.render('signup.ejs', { errors });
                });
              }

              // トランザクションをコミット
              connection.commit((err) => {
                if (err) {
                  console.error('トランザクションコミットエラー:', err);
                  return connection.rollback(() => {
                    errors.push('登録処理中にエラーが発生しました');
                    res.render('signup.ejs', { errors });
                  });
                }

                console.log('確認メールが送信されました:', info.response);
                res.render('signup_success.ejs'); // サインアップ成功ページへ
              });
            });
          }
        );
      });
    });
  }
);


//tokenのURLを踏んだ時
app.get('/verify/:token', (req, res) => {
  const token = req.params.token;
  const email = req.query.email;

  connection.beginTransaction((err) => {
    if (err) {
      console.error('トランザクション開始エラー:', err);
      return res.render('verification_fail.ejs', { 
        error: 'トランザクション開始に失敗しました' ,
        email: email
      });
    }

    connection.query(
      'SELECT * FROM users WHERE verification_token = ? AND verification_token_expiry > NOW()',
      [token],
      (err, results) => {
        if (err || results.length === 0) {
          console.error('トークン確認エラー:', err);
          return connection.rollback(() => {
            res.render('verification_fail.ejs', {
              error: '無効なトークンです' ,
              email: email
            });
          });
        }

        connection.query(
          'UPDATE users SET is_verified = true, verification_token = NULL WHERE id = ?',
          [results[0].id],
          (err) => {
            if (err) {
              console.error('認証更新エラー:', err);
              return connection.rollback(() => {
                res.render('verification_fail.ejs', {
                  error: '認証処理中にエラーが発生しました',
                  email: email
                });
              });
            }

            connection.commit((err) => {
              if (err) {
                console.error('トランザクションコミットエラー:', err);
                return connection.rollback(() => {
                  res.render('verification_fail.ejs', {
                    error: '認証処理中にエラーが発生しました',
                    email: email
                  });
                });
              }

              res.render('verification_success.ejs'); // 認証成功ページへ
            });
          }
        );
      }
    );
  });
});

//再送信
app.get('/resend-verification', (req, res) => {
  const email = req.query.email;  // クエリパラメータからメールアドレスを取得

  if (!email) {
    return res.render('error.ejs', { message: 'メールアドレスが指定されていません。' });
  }

  // メールアドレスでユーザーをデータベースから取得
  connection.query('SELECT * FROM users WHERE email = ?', 
    [email], 
    (err, results) => {
    if (err || results.length === 0) {
      console.error('ユーザー情報取得エラー:', err);
      return res.render('error.ejs', { message: '指定されたメールアドレスのユーザーが見つかりません。' });
    }

    const user = results[0];

    if (user.is_verified) {
      return res.render('error.ejs', { message: 'このアカウントは既に認証されています。' });
    }

    // 新しい確認トークンを生成
    const verificationTokenExpiry = new Date(Date.now() + 3600000);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationLink = `http://localhost:3000/verify/${verificationToken}?email=${encodeURIComponent(user.email)}`;

    // データベース内のトークンを更新
    connection.query('UPDATE users SET verification_token = ?, verification_token_expiry = ? WHERE id = ?', 
      [verificationToken, verificationTokenExpiry, user.id], 
      (err) => {
      if (err) {
        console.error('トークン更新エラー:', err);
        return res.render('error.ejs', { message: '確認トークンの更新に失敗しました。' });
      }

      // メール送信設定
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'メールアドレスの確認',
        text: `以下のリンクをクリックしてメールアドレスを確認してください: ${verificationLink}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('メール送信エラー:', error);
          return res.render('error.ejs', { message: '確認メールの再送信に失敗しました。' });
        }

        console.log('確認メールが再送信されました:', info.response);
        res.render('resend_success.ejs'); // 再送信成功ページ
      });
    });
  });
});


//一覧ページの表示
app.get('/list', (req, res) => {
  if (req.session.userId === undefined) {
    res.redirect('/login');
  } else {
    const id = req.session.userId;
    const perPage = 10; // 1ページに表示する件数
    const page = parseInt(req.query.page) || 1; // クエリパラメータ `page` を取得（デフォルトは1）

    connection.query(
      'SELECT COUNT(*) AS total FROM dailys WHERE userId = ?', // 合計件数を取得
      [id],
      (error, countResults) => {
        if (error) {
          console.error(error);
          res.status(500).send('データベースエラー');
        } else {
          const totalItems = countResults[0].total; // 合計件数
          const totalPages = Math.ceil(totalItems / perPage); // 総ページ数

          connection.query(
            'SELECT * FROM dailys WHERE userId = ? ORDER BY date DESC LIMIT ? OFFSET ?',
            [id, perPage, (page - 1) * perPage], // 表示件数とスキップする件数
            (error, results) => {
              if (error) {
                console.error(error);
                res.status(500).send('データベースエラー');
              } else {
                res.render('list.ejs', {
                  dailys: results,
                  count: totalItems,
                  currentPage: page,
                  totalPages: totalPages,
                });
              }
            }
          );
        }
      }
    );
  }
});

//日記の削除
app.post('/delete/:id', (req, res) =>{
  connection.query(
    'delete from dailys where id = ?',
    [req.params.id],
    (error, results) =>{
      res.redirect('/list');
    }
  );
});

//日記各ページの表示
app.get('/today', (req, res) => {
  if (req.session.userId === undefined) {
    res.redirect('/login');
  } else {
    res.render('today.ejs');  
  }
});

//AIコメント生成
app.post("/generate-comment", async (req, res) => {//ボタンがクリックされたときのルートなので再読み込みでコメントが生成されず、getリクエストになるはず
  const diaryText = req.body.diary; // フォームから送信された日記テキスト

  try {
      const response = await openai.chat.completions.create({//非同期処理
          model: "gpt-4o-mini",
          messages: [
            {role: "system", content: "あなたは日記に100字以内でコメントを返すアシスタントです。敬語は使わず親しげな言葉を使います。"},
            { role: "user", content: `この日記にコメントしてください。: ${diaryText}` }
          ],
      });
    
      const messageContent = response.choices[0]?.message?.content;
      if (!messageContent) {
        throw new Error("Message content is undefined or null.");
      }
      console.log(messageContent);
      res.json({ aiComment: messageContent });
    } catch (error) {
      console.error("Error generating AI comment:", error.message);
      res.status(500).json({ error: "AIコメントの生成に失敗しました。" });
    }
});

//保存
app.post('/save', (req, res) => {
  const date = req.body.date;
  const diary = req.body.diary;
  const aiComment = req.body.aiComment;
  const id = req.session.userId

  connection.query(
    'INSERT INTO dailys (date, contents, comments, userId) VALUES (?, ?, ?, ?)',
    [date, diary, aiComment, id],
    (err, results) => {
      if (err) {
        console.error(err);
        res.redirect('/list'); 
      } else {
        console.log('日記が保存されました');
        res.redirect('/list');
      }
    }
  );
});

//ログアウト
app.get('/logout', (req, res) =>{
  req.session.destroy((error) =>{
    res.redirect('/login');
  });
});

app.listen(3000);
