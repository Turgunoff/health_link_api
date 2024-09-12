const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('./db'); // Ma'lumotlar bazasi bilan ishlash uchun modulni import qilish (bu faylni alohida yaratishingiz kerak)
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // JSON formatdagi so'rovlarni qayta ishlash uchun middleware

// Tokenni yaratish
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET, // Maxfiy kalit
    { expiresIn: '1h' } // Token muddati
  );
};

// Tokenni tekshirish uchun middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).json({ message: 'Token mavjud emas' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token noto\'g\'ri' });
    req.user = user;
    next();
  });
};

// Barcha doktorlarni olish
app.get('/doctors', authenticateToken, async (req, res) => {
  try {
    const results = await pool.query('SELECT * FROM doctors');
    res.status(200).json(results.rows);
  } catch (err) {
    console.error('Server xatosi:', err);
    res.status(500).json({ message: 'Server xatosi' });
  }
});

// Yangi doktor qo'shish
app.post('/add/doctor', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    // Parolni xeshlash
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Doktorni ma'lumotlar bazasiga qo'shish
    const newDoctor = await pool.query(
      'INSERT INTO doctors (first_name, last_name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING *',
      [first_name, last_name, email, hashedPassword]
    );

    // Yangi doktor uchun token yaratish
    const token = generateToken(newDoctor.rows[0]);

    // Yangi doktor ma'lumotlari va tokenni qaytarish
    res.status(201).json({ 
      user: newDoctor.rows[0],
      token: token
    });
  } catch (err) {
    console.error('Server xatosi:', err);
    res.status(500).json({ message: 'Server xatosi' });
  }
});

// Foydalanuvchi ma'lumotlarini olish
app.get('/user', authenticateToken, async (req, res) => {
  try {
    // Assuming 'req.user' contains the user's ID from the token
    const userId = req.user.id; 

    const userResult = await pool.query('SELECT * FROM doctors WHERE id = $1', [userId]);

    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];
      // Omit the password_hash from the response for security
      delete user.password_hash; 
      res.status(200).json(user);
    } else {
      res.status(404).json({ message: 'Foydalanuvchi topilmadi' });
    }
  } catch (err) {
    console.error('Server xatosi:', err);
    res.status(500).json({ message: 'Server xatosi' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userResult = await pool.query('SELECT * FROM doctors WHERE email = $1', [email]);

    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];
      const isMatch = await bcrypt.compare(password, user.password_hash);

      if (isMatch) {
        const token = generateToken(user);
        res.status(200).json({ token });
      } else {
        res.status(401).json({ message: 'Noto\'g\'ri parol' });
      }
    } else {
      res.status(404).json({ message: 'Foydalanuvchi topilmadi' });
    }
  } catch (err) {
    console.error('Server xatosi:', err);
    res.status(500).json({ message: 'Server xatosi' });
  }
});

app.listen(port, () => {
  console.log(`Server ${port} portda ishga tushdi.`);
});