const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());
app.set('trust proxy', true);

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = 'maya-app';
let mongoClient = null;

// ========================================
// IP WHITELISTING MIDDLEWARE (FIXED TOGGLE)
// ========================================
const IP_WHITELIST_ENABLED = process.env.IP_WHITELIST_ENABLED === 'true'; // Fixed logic
const allowedIpsEnv = process.env.ALLOWED_IPS || '';
const allowedIps = allowedIpsEnv.split(',').map(ip => ip.trim()).filter(Boolean);

console.log('=== IP WHITELIST ===');
console.log('Enabled:', IP_WHITELIST_ENABLED ? 'YES' : 'NO (all IPs allowed)');
if (IP_WHITELIST_ENABLED) console.log('Whitelisted IPs:', allowedIps.length > 0 ? allowedIps : '[NONE - ALL BLOCKED]');
console.log('====================');

app.use((req, res, next) => {
    if (!IP_WHITELIST_ENABLED) return next();
    if (allowedIps.length === 0) {
        return res.status(403).send('IP whitelist enabled but empty.');
    }
    let clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '';
    clientIp = clientIp.split(',')[0].trim();
    const cleanIp = clientIp.replace(/^::ffff:/, '');
    if (allowedIps.includes(cleanIp)) { next(); } else { res.status(403).send('Access Denied'); }
});

async function getDb() {
    if (!mongoClient) { mongoClient = new MongoClient(MONGO_URI); await mongoClient.connect(); }
    return mongoClient.db(DB_NAME);
}

async function seedAdmin() {
    try {
        const db = await getDb();
        const users = db.collection('users');
        var existing = await users.findOne({ employeeId: 'ancel' });
        if (!existing) {
            await users.insertOne({ id: 'USR001', employeeId: 'ancel', fullName: 'Ancel Claudio', password: 'maya2026', role: 'ADMIN', securityQuestion: 'What is your pet\'s name?', securityAnswer: 'maya', createdAt: new Date().toISOString() });
        } else if (!existing.securityQuestion) {
            await users.updateOne({ employeeId: 'ancel' }, { $set: { securityQuestion: 'What is your pet\'s name?', securityAnswer: 'maya' } });
        }
    } catch (e) { console.error('MONGO FAILED:', e.message); process.exit(1); }
}

function getRoleLevel(role) { var levels = { 'ADMIN': 6, 'CLIENT': 5, 'OPERATIONS MANAGER': 4, 'TEAM LEADER': 3, 'AGENT': 2, 'TRAINING': 1 }; return levels[role] || 0; }
function generateToken(user) { var payload = JSON.stringify({ id: user.employeeId, name: user.fullName, role: user.role, exp: Date.now() + (12 * 60 * 60 * 1000) }); var cipher = crypto.createCipheriv('aes-256-cbc', crypto.createHash('sha256').update('maya-secret-salt-2025').digest(), Buffer.alloc(16, 'maya-calculator-iv')); var token = cipher.update(payload, 'utf8', 'hex'); token += cipher.final('hex'); return token; }
function verifyToken(token) { try { var decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update('maya-secret-salt-2025').digest(), Buffer.alloc(16, 'maya-calculator-iv')); var payload = decipher.update(token, 'hex', 'utf8'); payload += decipher.final('utf8'); var data = JSON.parse(payload); if (data.exp < Date.now()) return null; return data; } catch (e) { return null; } }
function authMiddleware(req, res, next) { var token = req.headers['x-maya-token'] || req.query.token; if (!token) return res.status(401).json({ error: 'No token provided' }); var user = verifyToken(token); if (!user) return res.status(401).json({ error: 'Invalid or expired token' }); req.user = user; next(); }

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/auth/login', async (req, res) => { /*... kept exactly the same ...*/ var employeeId = (req.body.employeeId || '').toLowerCase(); var password = req.body.password; if (!employeeId || !password) return res.status(400).json({ error: 'Employee ID and password are required' }); try { const db = await getDb(); var user = await db.collection('users').findOne({ employeeId: employeeId }); if (!user || user.password !== password) return res.status(401).json({ error: 'Invalid Employee ID or Password' }); res.json({ token: generateToken(user), user: { employeeId: user.employeeId, fullName: user.fullName, role: user.role } }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.get('/api/auth/verify', authMiddleware, (req, res) => res.json({ valid: true, user: req.user }));
app.get('/api/auth/users', authMiddleware, async (req, res) => { if (getRoleLevel(req.user.role) < 3) return res.status(403).json({ error: 'Not authorized' }); try { const db = await getDb(); res.json((await db.collection('users').find({}).toArray()).map(u => ({ id: u.id, employeeId: u.employeeId, fullName: u.fullName, role: u.role, createdAt: u.createdAt }))); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.post('/api/auth/users', authMiddleware, async (req, res) => { /*... kept exactly the same ...*/ var creatorLevel = getRoleLevel(req.user.role); if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' }); var { fullName, employeeId, password, role, securityQuestion, securityAnswer } = req.body; if (!fullName || !employeeId || !password) return res.status(400).json({ error: 'All fields required' }); if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' }); if (!role) role = 'AGENT'; if (getRoleLevel(role) >= creatorLevel) return res.status(403).json({ error: 'Cannot create equal or higher role' }); if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' }); try { const db = await getDb(); if (await db.collection('users').findOne({ employeeId: employeeId.toLowerCase() })) return res.status(409).json({ error: 'Employee ID already exists' }); var newUser = { id: 'USR' + Date.now().toString().slice(-6), employeeId: employeeId.toLowerCase(), fullName, password, role, securityQuestion, securityAnswer: securityAnswer.toLowerCase().trim(), createdAt: new Date().toISOString() }; await db.collection('users').insertOne(newUser); res.status(201).json({ message: 'Account created' }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.put('/api/auth/users/:employeeId', authMiddleware, async (req, res) => { /*... kept exactly the same ...*/ var creatorLevel = getRoleLevel(req.user.role); if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' }); var targetId = req.params.employeeId.toLowerCase(); if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot edit own account' }); try { const db = await getDb(); var targetUser = await db.collection('users').findOne({ employeeId: targetId }); if (!targetUser) return res.status(404).json({ error: 'User not found' }); if (getRoleLevel(targetUser.role) >= creatorLevel) return res.status(403).json({ error: 'Cannot edit equal or higher role' }); var updateFields = {}; if (req.body.fullName) updateFields.fullName = req.body.fullName; if (req.body.role && getRoleLevel(req.body.role) < creatorLevel) updateFields.role = req.body.role; if (req.body.password && req.body.password.length >= 6) updateFields.password = req.body.password; if (Object.keys(updateFields).length === 0) return res.status(400).json({ error: 'No changes provided' }); await db.collection('users').updateOne({ employeeId: targetId }, { $set: updateFields }); res.json({ message: 'Updated' }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.delete('/api/auth/users/:employeeId', authMiddleware, async (req, res) => { /*... kept exactly the same ...*/ var creatorLevel = getRoleLevel(req.user.role); if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' }); var targetId = req.params.employeeId.toLowerCase(); if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot delete own account' }); try { const db = await getDb(); var targetUser = await db.collection('users').findOne({ employeeId: targetId }); if (!targetUser) return res.status(404).json({ error: 'User not found' }); if (getRoleLevel(targetUser.role) >= creatorLevel) return res.status(403).json({ error: 'Cannot delete equal or higher role' }); await db.collection('users').deleteOne({ employeeId: targetId }); res.json({ message: 'Deleted' }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });

app.post('/api/auth/check-user', async (req, res) => { var employeeId = (req.body.employeeId || '').toLowerCase(); if (!employeeId) return res.status(400).json({ error: 'Employee ID required' }); try { var user = await (await getDb()).collection('users').findOne({ employeeId: employeeId }); if (!user) return res.status(404).json({ error: 'No account found' }); res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName, securityQuestion: user.securityQuestion || null }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.post('/api/auth/verify-security', async (req, res) => { var employeeId = (req.body.employeeId || '').toLowerCase(); var answer = (req.body.answer || '').trim().toLowerCase(); if (!employeeId || !answer) return res.status(400).json({ error: 'All fields required' }); try { var user = await (await getDb()).collection('users').findOne({ employeeId: employeeId }); if (!user || !user.securityAnswer || answer !== user.securityAnswer.toLowerCase()) return res.status(401).json({ error: 'Incorrect answer' }); res.json({ verified: true }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });
app.post('/api/auth/reset-password', async (req, res) => { var employeeId = (req.body.employeeId || '').toLowerCase(); var newPassword = req.body.newPassword; if (!employeeId || !newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Invalid data' }); try { var db = await getDb(); var result = await db.collection('users').updateOne({ employeeId: employeeId }, { $set: { password: newPassword } }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No account found' }); res.json({ message: 'Password updated' }); } catch (e) { res.status(500).json({ error: 'Database error' }); } });

app.post('/api/chat', async (req, res) => { var token = (req.headers.authorization || '').replace('Bearer ', '').trim(); if (token !== process.env.RENDER_AUTH_KEY) return res.status(401).json({ error: { message: 'Please contact support.' } }); if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: { message: 'Please contact support.' } }); try { var response = await fetch('https://api.groq.com/openai/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + process.env.GROQ_API_KEY }, body: JSON.stringify(req.body) }); res.status(response.status).json(await response.json()); } catch (err) { res.status(500).json({ error: { message: 'Proxy error: ' + err.message } }); } });

app.get('/api/fx-rates', async (req, res) => { try { const response = await fetch('https://open.er-api.com/v6/latest/PHP'); res.json(await response.json()); } catch (err) { res.status(500).json({ error: 'Failed to fetch rates' }); } });

app.post('/api/email/send', authMiddleware, async (req, res) => { /*... kept exactly the same ...*/ let { to_email, to_name, subject, receipt_html, receipt_summary, total_amount, principal, interest_total, installments, from_name } = req.body; if (!to_email || !subject) return res.status(400).json({ error: 'Missing fields' }); try { await fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_PUBLIC_KEY, template_params: { to_email, to_name: to_name || 'Customer', from_name: from_name || req.user.name, subject, receipt_html: receipt_html || '', receipt_summary: receipt_summary || '', total_amount: total_amount || 'N/A', principal: principal || 'N/A', interest_total: interest_total || 'N/A', installments: installments || 'N/A' } }) }); res.json({ message: 'Email sent' }); } catch (e) { res.status(500).json({ error: 'Failed' }); } });

// ========================================
// NEW: INTERNAL COMMUNICATION API (SLACK-STYLE)
// ========================================
// Get all users for the DM sidebar
app.get('/api/comms/users', authMiddleware, async (req, res) => {
    try {
        const db = await getDb();
        const users = await db.collection('users').find({}, { projection: { password: 0, securityAnswer: 0, securityQuestion: 0 } }).toArray();
        res.json(users);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// Get messages for a specific channel or DM
app.get('/api/comms/messages', authMiddleware, async (req, res) => {
    const { channel, recipientId } = req.query;
    let query = {};
    if (recipientId) {
        // DM Logic: Find chats between me and recipientId
        query = { 
            $or: [
                { senderId: req.user.id, recipientId: recipientId, type: 'dm' },
                { senderId: recipientId, recipientId: req.user.id, type: 'dm' }
            ]
        };
    } else if (channel) {
        query = { channel: channel, type: 'channel' };
    }
    try {
        const db = await getDb();
        // Sort by oldest first for chat rendering
        const messages = await db.collection('messages').find(query).sort({ createdAt: 1 }).limit(100).toArray();
        res.json(messages);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// Send a message
app.post('/api/comms/messages', authMiddleware, async (req, res) => {
    const { text, recipientId, channel } = req.body;
    if (!text && !req.body.text) return res.status(400).json({ error: 'Message text required' });
    
    let messageData = {
        text: text || req.body.text,
        senderId: req.user.id,
        senderName: req.user.name,
        senderRole: req.user.role,
        createdAt: new Date().toISOString()
    };

    if (recipientId) {
        messageData.type = 'dm';
        messageData.recipientId = recipientId;
    } else {
        messageData.type = 'channel';
        messageData.channel = channel || 'general';
    }

    try {
        const db = await getDb();
        await db.collection('messages').insertOne(messageData);
        res.status(201).json(messageData);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.use(express.static(path.join(__dirname, 'public')));
var PORT = process.env.PORT || 10000;
app.listen(PORT, async () => { console.log('Maya app running on port ' + PORT); await seedAdmin(); });
