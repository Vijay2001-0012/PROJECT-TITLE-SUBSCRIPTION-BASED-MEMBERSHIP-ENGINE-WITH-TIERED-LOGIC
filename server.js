require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'frontend')));

// MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Razorpay Instance
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Middlewares
const isAuth = (req, res, next) => req.session.user_id ? next() : res.status(401).json({ error: 'Unauthorized' });
const isAdmin = (req, res, next) => req.session.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

// ======================= AUTH APIs =======================
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        await pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',[username, password, 'user']);
        res.json({ message: 'Signup successful! You can now login.' });
    } catch (err) {
        console.error("DATABASE ERROR:", err); // This will print the exact error in your VS Code terminal
        
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Username already exists. Choose a different one.' });
        } else {
            res.status(500).json({ error: 'Database error. Please check your VS Code terminal for details.' });
        }
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
    if (rows.length > 0) {
        req.session.user_id = rows[0].id;
        req.session.role = rows[0].role;
        res.json({ message: 'Login successful', role: rows[0].role });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

// ======================= SUBSCRIPTION APIs =======================
app.get('/subscription-status', isAuth, async (req, res) => {
    const [user] = await pool.query('SELECT points FROM users WHERE id = ?', [req.session.user_id]);
    const [sub] = await pool.query(
        'SELECT *, DATEDIFF(end_date, CURDATE()) as remaining_days FROM subscriptions WHERE user_id = ? AND end_date >= CURDATE() ORDER BY end_date DESC LIMIT 1',[req.session.user_id]
    );
    res.json({ points: user[0].points, subscription: sub.length ? sub[0] : null });
});

app.post('/subscribe-free', isAuth, async (req, res) => {
    const userId = req.session.user_id;
    await pool.query(
        "INSERT INTO subscriptions (user_id, plan, start_date, end_date, status) VALUES (?, 'basic', CURDATE(), DATE_ADD(CURDATE(), INTERVAL 30 DAY), 'active')",
        [userId]
    );
    res.json({ message: 'Basic (Free) plan activated for 30 days!' });
});

// ======================= PAYMENT APIs =======================
app.post('/create-order', isAuth, async (req, res) => {
    const { plan } = req.body;
    const amount = plan === 'premium' ? 500 : 300; // INR
    
    const options = { amount: amount * 100, currency: 'INR', receipt: `receipt_${req.session.user_id}` };
    const order = await razorpay.orders.create(options);

    await pool.query(
        'INSERT INTO payments (user_id, order_id, amount, plan, status) VALUES (?, ?, ?, ?, ?)',[req.session.user_id, order.id, amount, plan, 'pending']
    );

    res.json({ orderId: order.id, amount: order.amount, key: process.env.RAZORPAY_KEY_ID });
});

app.post('/verify-payment', isAuth, async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;

    const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + "|" + razorpay_payment_id)
        .digest('hex');

    if (generated_signature === razorpay_signature) {
        await pool.query("UPDATE payments SET payment_id = ?, status = 'successful' WHERE order_id = ?",[razorpay_payment_id, razorpay_order_id]);
        
        const days = plan === 'premium' ? 365 : 90;
        await pool.query(
            "INSERT INTO subscriptions (user_id, plan, start_date, end_date, status) VALUES (?, ?, CURDATE(), DATE_ADD(CURDATE(), INTERVAL ? DAY), 'active')",[req.session.user_id, plan, days]
        );
        res.json({ message: 'Payment successful, subscription activated!' });
    } else {
        await pool.query("UPDATE payments SET status = 'failed' WHERE order_id = ?", [razorpay_order_id]);
        res.status(400).json({ error: 'Payment verification failed' });
    }
});

// ======================= COURSES & ENROLLMENT =======================
app.get('/courses', isAuth, async (req, res) => {
    const[courses] = await pool.query('SELECT * FROM courses');
    res.json(courses);
});

app.post('/enroll', isAuth, async (req, res) => {
    const { course_id } = req.body;
    const userId = req.session.user_id;

    const[courseReq] = await pool.query('SELECT * FROM courses WHERE id = ?', [course_id]);
    const course = courseReq[0];

    const [subReq] = await pool.query('SELECT * FROM subscriptions WHERE user_id = ? AND end_date >= CURDATE() ORDER BY end_date DESC LIMIT 1',[userId]);
    const sub = subReq[0];

    if (!sub) return res.status(403).json({ error: 'No active subscription found.' });

    // Tier Logic Checking
    const userPlan = sub.plan;
    if (course.level === 'premium' && userPlan !== 'premium') return res.status(403).json({ error: 'Premium plan required.' });
    if (course.level === 'advanced' && userPlan === 'basic') return res.status(403).json({ error: 'Standard or Premium plan required.' });

    const [userReq] = await pool.query('SELECT points FROM users WHERE id = ?',[userId]);
    let points = userReq[0].points;

    if (points < course.points_required) return res.status(403).json({ error: 'Not enough points.' });

    // Deduct points and enroll
    await pool.query('UPDATE users SET points = points - ? WHERE id = ?', [course.points_required, userId]);
    await pool.query('INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)', [userId, course_id]);

    res.json({ message: 'Enrolled successfully!' });
});
// Get User Profile Data
app.get('/profile', isAuth, async (req, res) => {
    const [user] = await pool.query('SELECT username, role, points FROM users WHERE id = ?',[req.session.user_id]);
    res.json(user[0]);
});

// Get User's Enrolled Courses
app.get('/my-enrollments', isAuth, async (req, res) => {
    const userId = req.session.user_id;
    
    // Check if user has an active subscription
    const [subReq] = await pool.query('SELECT * FROM subscriptions WHERE user_id = ? AND end_date >= CURDATE() ORDER BY end_date DESC LIMIT 1', [userId]);
    const hasActiveSub = subReq.length > 0;

    // Get all enrolled courses
    const [enrollments] = await pool.query(`
        SELECT c.name, c.category, c.level, e.enrollment_date 
        FROM enrollments e 
        JOIN courses c ON e.course_id = c.id 
        WHERE e.user_id = ?
        ORDER BY e.enrollment_date DESC
    `, [userId]);

    res.json({ enrollments, hasActiveSub });
});
// ======================= ADMIN APIs =======================
app.get('/admin/users', isAdmin, async (req, res) => {
    const [users] = await pool.query('SELECT id, username, role, points FROM users');
    res.json(users);
});

app.post('/admin/add-points', isAdmin, async (req, res) => {
    const { user_id, points } = req.body;
    await pool.query('UPDATE users SET points = LEAST(points + ?, 10000) WHERE id = ?', [points, user_id]);
    res.json({ message: 'Points added successfully' });
});

app.post('/admin/add-course', isAdmin, async (req, res) => {
    const { name, category, level, points_required } = req.body;
    await pool.query('INSERT INTO courses (name, category, level, points_required) VALUES (?, ?, ?, ?)', [name, category, level, points_required]);
    res.json({ message: 'Course added successfully' });
});

app.listen(process.env.PORT, () => console.log(`Server running on http://localhost:${process.env.PORT}`));