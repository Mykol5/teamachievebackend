const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';

const staffData = JSON.parse(fs.readFileSync(path.join(__dirname, 'staffs.json')));
const loansData = JSON.parse(fs.readFileSync(path.join(__dirname, 'loans.json')));

app.use(cors({
    origin: ["http://localhost:8080", "https://teamachievebuysimply.netlify.app"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());
app.use(morgan('dev'));

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Access denied' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

const roleMiddleware = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: 'Forbidden' });
    }
    next();
};

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use(apiLimiter);

app.post('/login', (req, res) => {
    console.log("Received login attempt:", req.body); // Log input data

    const { email, password } = req.body;
    const user = staffData.find(staff => staff.email === email && staff.password === password);

    if (!user) {
        console.log("Invalid credentials for:", email); // Log invalid attempts
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ success: true, token, user });
});


app.post('/logout', (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

app.get('/loans', authMiddleware, (req, res) => {
    const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
    const loans = loansData.map(loan => isAdmin ? loan : { ...loan, totalLoan: undefined });
    res.json(loans);
});

app.get('/loans/status', authMiddleware, (req, res) => {
    const { status } = req.query;
    const filteredLoans = loansData.filter(loan => loan.status === status);
    res.json(filteredLoans);
});

app.get('/loans/:userEmail/get', authMiddleware, (req, res) => {
    const userLoans = loansData.filter(loan => loan.email === req.params.userEmail);
    res.json({ loans: userLoans });
});

app.get('/loans/expired', authMiddleware, (req, res) => {
    const expiredLoans = loansData.filter(loan => new Date(loan.maturityDate) < new Date());
    res.json(expiredLoans);
});

app.delete('/loan/:loanId/delete', authMiddleware, roleMiddleware(['superadmin']), (req, res) => {
    const index = loansData.findIndex(loan => loan.id === req.params.loanId);
    if (index === -1) return res.status(404).json({ message: 'Loan not found' });
    loansData.splice(index, 1);
    res.json({ message: 'Loan deleted successfully' });
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Internal Server Error' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
