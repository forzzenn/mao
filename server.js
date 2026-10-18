
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const ethers = require('ethers');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname))); // serve html

const JWT_SECRET = process.env.JWT_SECRET || 'mao_exchange_super_secret_jwt_key_2025';

// Database Setup
const db = new sqlite3.Database('crypto.db');
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function(err) { if (err) reject(err); else resolve(this); }));
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); }));
const dbAll = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); }));

// Attach IO to req
app.use((req, res, next) => {
    req.io = io;
    next();
});

// Helper auth middleware for routes that need req.user globally
const globalAuthenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) req.user = user;
            next();
        });
    } else {
        next();
    }
};
app.use('/api/p2p', globalAuthenticate);
app.use('/api/user', globalAuthenticate);

// ==== MODULES INLINED ====

// --- AUTH & USER API ---
(function() {
    
    const router = express.Router();

    const authenticate = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Unauthorized' });

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ error: 'Forbidden' });
            req.user = user;
            next();
        });
    };

    router.get('/auth/me', authenticate, (req, res) => {
        db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub, is_pinned, telegram_id, phone, is_verified_trader, telegram_username FROM users WHERE id = ?', [req.user.id], (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!row) return res.status(404).json({ error: 'User not found' });
            res.json(row);
        });
    });

    router.post('/auth/email/register-init', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

            const userExists = await new Promise((resolve, reject) => {
                db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (userExists) return res.status(400).json({ error: 'User already exists' });

            const code = Math.floor(100000 + Math.random() * 900000).toString();
            const passwordHash = await bcrypt.hash(password, 10);
            const expiresAt = Date.now() + 15 * 60 * 1000;

            await new Promise((resolve, reject) => {
                db.run(
                    'INSERT OR REPLACE INTO email_codes (email, code, password_hash, expires_at) VALUES (?, ?, ?, ?)',
                    [email, code, passwordHash, expiresAt],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            console.log(`[STUB EMAIL] To: ${email} | Code: ${code}`);
            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/auth/email/register-confirm', async (req, res) => {
        try {
            const { email, code } = req.body;
            if (!email || !code) return res.status(400).json({ error: 'Missing fields' });

            const row = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM email_codes WHERE email = ?', [email], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });

            if (!row || row.code !== code || row.expires_at < Date.now()) {
                return res.status(400).json({ error: 'Invalid or expired code' });
            }

            const userId = await new Promise((resolve, reject) => {
                db.run(
                    'INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)',
                    [email, row.password_hash, email.split('@')[0]],
                    function (err) {
                        if (err) reject(err);
                        else resolve(this.lastID);
                    }
                );
            });

            db.run('DELETE FROM email_codes WHERE email = ?', [email]);

            const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
            
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE id = ?', [userId], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });

            res.json({ success: true, token, user });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/auth/email/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

            const user = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!user) return res.status(401).json({ error: 'Invalid credentials' });

            const valid = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
            if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
            
            const returnUser = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE id = ?', [user.id], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });
            res.json({ success: true, token, user: returnUser });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
    
    router.post('/auth/email/forgot-init', async (req, res) => {
        try {
            const { email } = req.body;
            if (!email) return res.status(400).json({ error: 'Missing fields' });
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            if (user) {
                const code = Math.floor(100000 + Math.random() * 900000).toString();
                const expiresAt = Date.now() + 15 * 60 * 1000;
                await new Promise((resolve, reject) => {
                    db.run(
                        'INSERT OR REPLACE INTO email_codes (email, code, expires_at) VALUES (?, ?, ?)',
                        [email, code, expiresAt],
                        function(err) {
                            if (err) reject(err);
                            else resolve();
                        }
                    );
                });
                console.log(`[STUB EMAIL] To: ${email} | Password Reset Code: ${code}`);
            }
            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
    
    router.post('/auth/email/forgot-confirm', async (req, res) => {
        try {
            const { email, code, newPassword } = req.body;
            if (!email || !code || !newPassword) return res.status(400).json({ error: 'Missing fields' });
            const row = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM email_codes WHERE email = ?', [email], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });
            if (!row || row.code !== code || row.expires_at < Date.now()) {
                return res.status(400).json({ error: 'Invalid or expired code' });
            }
            const passwordHash = await bcrypt.hash(newPassword, 10);
            await new Promise((resolve, reject) => {
                db.run('UPDATE users SET password_hash = ? WHERE email = ?', [passwordHash, email], function (err) {
                    if (err) reject(err);
                    else resolve();
                });
            });
            db.run('DELETE FROM email_codes WHERE email = ?', [email]);
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE email = ?', [email], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ success: true, token, user });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/auth/register', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
            const passwordHash = await bcrypt.hash(password, 10);
            const userId = await new Promise((resolve, reject) => {
                db.run('INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)',
                    [email, passwordHash, email.split('@')[0]], function (err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                });
            });
            const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE id = ?', [userId], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });
            res.json({ success: true, token, user });
        } catch (err) {
            if (err.message && err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'User already exists' });
            }
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/auth/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            if (!user) return res.status(401).json({ error: 'Invalid credentials' });
            const valid = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
            if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
            const returnUser = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE id = ?', [user.id], (err, r) => {
                    if (err) reject(err);
                    else resolve(r);
                });
            });
            res.json({ success: true, token, user: returnUser });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/auth/logout', (req, res) => res.json({ success: true }));

    router.get('/auth/me', authenticate, async (req, res) => {
        try {
            const user = await new Promise((resolve, reject) => {
                db.get('SELECT id, email, display_name, wallet_address, usdt_balance, role, balance_rub FROM users WHERE id = ?', [req.user.id], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });

            if (!user) return res.status(404).json({ error: 'User not found' });
            res.json(user);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/user/wallet', authenticate, async (req, res) => {
        try {
            const { wallet_address, usdt_balance, signature, message } = req.body;
            if (!wallet_address || !signature || !message) {
                return res.status(400).json({ error: 'Missing fields' });
            }

            const recoveredAddress = ethers.utils.verifyMessage(message, signature);
            if (recoveredAddress.toLowerCase() !== wallet_address.toLowerCase()) {
                return res.status(403).json({ error: 'Invalid signature' });
            }

            await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE users SET wallet_address = ?, usdt_balance = ? WHERE id = ?',
                    [wallet_address, parseFloat(usdt_balance) || 0, req.user.id],
                    function (err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    router.post('/user/wallet/disconnect', authenticate, async (req, res) => {
        try {
            await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE users SET wallet_address = NULL, usdt_balance = 0 WHERE id = ?',
                    [req.user.id],
                    function (err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    app.use("/api", router);

})();

// --- P2P & ESCROW LOGIC ---
(function() {
    

    // Helper for transactions
    const runInTx = async (callback) => {
        // Simple serialization since we don't have a guaranteed connection pool
        // This is a naive lock to prevent overlapping BEGIN/COMMIT
        if (!global.txLock) {
            global.txLock = Promise.resolve();
        }
        
        let releaseLock;
        const lock = new Promise(resolve => releaseLock = resolve);
        const oldLock = global.txLock;
        global.txLock = global.txLock.then(() => lock);
        
        await oldLock;
        try {
            await dbRun("BEGIN IMMEDIATE TRANSACTION");
            const result = await callback();
            await dbRun("COMMIT");
            return result;
        } catch (e) {
            try { await dbRun("ROLLBACK"); } catch(err) {}
            throw e;
        } finally {
            releaseLock();
        }
    };

    // 1. Create Ad
    app.post('/api/p2p/ads', async (req, res) => {
        try {
            const userId = req.user.id;
            const { type, crypto, fiat, price, min_limit, max_limit, payment_methods, available_amount } = req.body;
            
            const newAdId = await runInTx(async () => {
                if (type === 'sell') {
                    // Maker is selling crypto. Freeze balance.
                    const user = await dbGet('SELECT usdt_balance FROM users WHERE id = ?', [userId]);
                    if (!user || user.usdt_balance < available_amount) {
                        throw new Error('Insufficient balance');
                    }
                    await dbRun('UPDATE users SET usdt_balance = usdt_balance - ? WHERE id = ?', [available_amount, userId]);
                }
                
                const query = `
                    INSERT INTO p2p_ads (maker_id, type, crypto, fiat, price, min_limit, max_limit, payment_methods, available_amount, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
                `;
                const result = await dbRun(query, [userId, type, crypto, fiat, price, min_limit, max_limit, JSON.stringify(payment_methods), available_amount]);
                return result.lastID;
            });
            
            res.json({ success: true, id: newAdId });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 2. Get active Ads
    
    

    app.get('/api/p2p/ads', async (req, res) => {
        try {
            const ads = await dbAll("SELECT p2p_ads.*, users.display_name as display_name, users.is_verified_trader as is_verified_trader FROM p2p_ads JOIN users ON p2p_ads.maker_id = users.id WHERE p2p_ads.status = 'active'");
            res.json(ads || []);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 3. Get My Ads
    app.get('/api/p2p/my-ads', async (req, res) => {
        try {
            const userId = req.user.id;
            const ads = await dbAll(`SELECT * FROM p2p_ads WHERE maker_id = ? AND status != 'deleted'`, [userId]);
            res.json(ads || []);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 4. Delete Ad
    app.delete('/api/p2p/ads/:id', async (req, res) => {
        try {
            const userId = req.user.id;
            const adId = req.params.id;
            
            await runInTx(async () => {
                const ad = await dbGet('SELECT * FROM p2p_ads WHERE id = ? AND maker_id = ? AND status != \'deleted\'', [adId, userId]);
                if (!ad) throw new Error('Ad not found');
                
                if (ad.type === 'sell' && ad.available_amount > 0) {
                    // Refund remaining crypto
                    await dbRun('UPDATE users SET usdt_balance = usdt_balance + ? WHERE id = ?', [ad.available_amount, userId]);
                }
                
                await dbRun(`UPDATE p2p_ads SET status = 'deleted', available_amount = 0 WHERE id = ?`, [adId]);
            });
            
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 5. Toggle Ad Status
    app.post('/api/p2p/ads/:id/toggle', async (req, res) => {
        try {
            const userId = req.user.id;
            const adId = req.params.id;
            
            const ad = await dbGet('SELECT * FROM p2p_ads WHERE id = ? AND maker_id = ?', [adId, userId]);
            if (!ad) return res.status(404).json({ success: false, error: 'Ad not found' });
            if (ad.status === 'deleted') return res.status(400).json({ success: false, error: 'Ad is deleted' });
            
            const newStatus = ad.status === 'active' ? 'inactive' : 'active';
            await dbRun('UPDATE p2p_ads SET status = ? WHERE id = ?', [newStatus, adId]);
            
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 6. Open Deal
    app.post('/api/p2p/deals', async (req, res) => {
        try {
            const takerId = req.user.id;
            const { ad_id, amount_fiat, amount_crypto } = req.body;
            let resultId;
            let adCrypto = 'USDT';
            
            await runInTx(async () => {
                const ad = await dbGet('SELECT * FROM p2p_ads WHERE id = ? AND status = \'active\'', [ad_id]);
                if (!ad) throw new Error('Ad not found or inactive');
                if (ad.maker_id === takerId) throw new Error('Cannot take your own ad');
                
                if (ad.type === 'sell') {
                    // Maker sells crypto. Take from ad.available_amount
                    if (ad.available_amount < amount_crypto) {
                        throw new Error('Not enough crypto available in this ad');
                    }
                    await dbRun('UPDATE p2p_ads SET available_amount = available_amount - ? WHERE id = ?', [amount_crypto, ad.id]);
                } else if (ad.type === 'buy') {
                    // Maker buys crypto, meaning Taker sells crypto. Freeze from taker.
                    const taker = await dbGet('SELECT usdt_balance FROM users WHERE id = ?', [takerId]);
                    if (!taker || taker.usdt_balance < amount_crypto) {
                        throw new Error('Insufficient crypto balance');
                    }
                    await dbRun('UPDATE users SET usdt_balance = usdt_balance - ? WHERE id = ?', [amount_crypto, takerId]);
                }
                
                const maker = await dbGet('SELECT display_name FROM users WHERE id = ?', [ad.maker_id]);
                const dealType = ad.type === 'buy' ? 'sell' : 'buy'; // from Taker's perspective
                
                const query = `
                    INSERT INTO p2p_deals (ad_id, taker_id, amount_fiat, amount_crypto, status, escrow_step, maker_name, rate, asset, fiat, type)
                    VALUES (?, ?, ?, ?, 'open', 'created', ?, ?, ?, ?, ?)
                `;
                const result = await dbRun(query, [
                    ad.id, takerId, amount_fiat, amount_crypto,
                    maker ? maker.display_name : 'Maker', ad.price, ad.crypto, ad.fiat, dealType
                ]);
                resultId = result.lastID;
                adCrypto = ad.crypto;
            });
            
            if (global.tgNotifyAdmin) {
                global.tgNotifyAdmin(`Новая P2P-сделка #${resultId}, сумма: ${amount_crypto}, актив: ${adCrypto}`);
            }

            res.json({ success: true, deal_id: resultId });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 7. Get My Deals
    app.get('/api/p2p/my-deals', async (req, res) => {
        try {
            const userId = req.user.id;
            const deals = await dbAll(`
                SELECT d.*, a.type as ad_type, a.maker_id 
                FROM p2p_deals d
                JOIN p2p_ads a ON d.ad_id = a.id
                WHERE d.taker_id = ? OR a.maker_id = ?
            `, [userId, userId]);
            res.json(deals || []);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 8. Get specific deal
    app.get('/api/p2p/deals/:id', async (req, res) => {
        try {
            const dealId = req.params.id;
            const deal = await dbGet(`
                SELECT d.*, a.type as ad_type, a.maker_id, a.payment_methods
                FROM p2p_deals d
                JOIN p2p_ads a ON d.ad_id = a.id
                WHERE d.id = ?
            `, [dealId]);
            if (!deal) return res.status(404).json({ success: false, error: 'Deal not found' });
            res.json(deal);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 9. Deal Messages (Chat)
    app.get('/api/p2p/deals/:id/messages', async (req, res) => {
        try {
            const messages = await dbAll('SELECT * FROM p2p_messages WHERE deal_id = ? ORDER BY created_at ASC', [req.params.id]);
            res.json(messages || []);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    app.post('/api/p2p/deals/:id/messages', async (req, res) => {
        try {
            const { text } = req.body;
            if (!text) return res.status(400).json({ success: false, error: 'Empty message' });
            
            const dealId = req.params.id;
            const userId = req.user.id;
            
            const deal = await dbGet('SELECT d.taker_id, a.maker_id FROM p2p_deals d JOIN p2p_ads a ON d.ad_id = a.id WHERE d.id = ?', [dealId]);
            if (!deal) return res.status(404).json({ success: false, error: 'Deal not found' });
            
            let senderType = 'user';
            if (deal.taker_id === userId) senderType = 'taker';
            else if (deal.maker_id === userId) senderType = 'maker';
            
            await dbRun('INSERT INTO p2p_messages (deal_id, sender_type, message) VALUES (?, ?, ?)', [dealId, senderType, text]);
            
            // Broadcast via Socket.IO if available
            if (req.io) {
                req.io.to('p2p_deal_' + dealId).emit('deal:chat_send', { sender: senderType, message: text });
            }
            
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // 10. File upload dummy
    app.post('/api/p2p/deals/:id/upload', async (req, res) => {
        res.json({ success: true, url: '/dummy-upload.jpg' });
    });

    // 11. Deal Status actions
    app.post('/api/p2p/deals/:id/paid', async (req, res) => {
        try {
            const dealId = req.params.id;
            await runInTx(async () => {
                const deal = await dbGet('SELECT status FROM p2p_deals WHERE id = ?', [dealId]);
                if (!deal || deal.status !== 'open') throw new Error('Deal cannot be marked as paid');
                await dbRun('UPDATE p2p_deals SET status = \'paid\', escrow_step = \'paid\' WHERE id = ?', [dealId]);
                const dealInfo = await dbGet('SELECT * FROM p2p_deals WHERE id = ?', [dealId]);
                if (dealInfo && global.tgNotifyUser) global.tgNotifyUser(dealInfo.maker_id || dealInfo.user_id, "⏳ Покупатель отметил ордер #" + dealId + " как оплаченный! Проверьте поступление средств.");
            });
            if (req.io) req.io.to('p2p_deal_' + dealId).emit('deal:update', { status: 'paid' });
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    app.post('/api/p2p/deals/:id/dispute', async (req, res) => {
        try {
            const dealId = req.params.id;
            await dbRun('UPDATE p2p_deals SET dispute_status = \'open\' WHERE id = ?', [dealId]);
            if (req.io) {
                req.io.to('p2p_deal_' + dealId).emit('deal:update', { dispute_status: 'open' });
                req.io.to('admin_room').emit('admin:request_freeze', { dealId });
            }
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    app.post('/api/p2p/deals/:id/cancel', async (req, res) => {
        try {
            const dealId = req.params.id;
            await runInTx(async () => {
                const deal = await dbGet('SELECT d.*, a.type as ad_type FROM p2p_deals d JOIN p2p_ads a ON d.ad_id = a.id WHERE d.id = ?', [dealId]);
                if (!deal || deal.status !== 'open') throw new Error('Cannot cancel deal');
                
                if (deal.ad_type === 'buy') {
                    // Taker sells crypto, refund Taker
                    await dbRun('UPDATE users SET usdt_balance = usdt_balance + ? WHERE id = ?', [deal.amount_crypto, deal.taker_id]);
                } else if (deal.ad_type === 'sell') {
                    // Maker sells crypto, refund back to Ad available_amount
                    await dbRun('UPDATE p2p_ads SET available_amount = available_amount + ? WHERE id = ?', [deal.amount_crypto, deal.ad_id]);
                }
                
                await dbRun('UPDATE p2p_deals SET status = \'cancelled\', escrow_step = \'cancelled\' WHERE id = ?', [dealId]);
            });
            if (req.io) req.io.to('p2p_deal_' + dealId).emit('deal:update', { status: 'cancelled' });
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    app.post('/api/p2p/deals/:id/release', async (req, res) => {
        try {
            const dealId = req.params.id;
            await runInTx(async () => {
                const deal = await dbGet('SELECT d.*, a.type as ad_type, a.maker_id FROM p2p_deals d JOIN p2p_ads a ON d.ad_id = a.id WHERE d.id = ?', [dealId]);
                if (!deal || deal.status === 'completed' || deal.status === 'cancelled') throw new Error('Cannot release crypto for this deal');
                
                // Release crypto to the buyer
                let buyerId;
                if (deal.ad_type === 'sell') {
                    // Maker sold, Taker bought
                    buyerId = deal.taker_id;
                } else if (deal.ad_type === 'buy') {
                    // Maker bought, Taker sold
                    buyerId = deal.maker_id;
                }
                
                await dbRun('UPDATE users SET usdt_balance = usdt_balance + ? WHERE id = ?', [deal.amount_crypto, buyerId]);
                await dbRun('UPDATE p2p_deals SET status = \'completed\', escrow_step = \'released\' WHERE id = ?', [dealId]);
            });
            if (req.io) req.io.to('p2p_deal_' + dealId).emit('deal:update', { status: 'completed' });
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

})();

// --- ADMIN CRM & WEBSOCKETS ---
(function() {
    
    // Cookie-based Admin Auth Middleware
    const adminAuth = (req, res, next) => {
        if (req.cookies && req.cookies.admin_session === 'authenticated') {
            next();
        } else {
            res.status(401).json({ error: 'Unauthorized' });
        }
    };

    // 1. Admin Login
    app.post('/api/admin/login', (req, res) => {
        const { password } = req.body;
        if (password === 'admin123') {
            res.cookie('admin_session', 'authenticated', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false, error: 'Invalid password' });
        }
    });

    // Logout
    app.post('/api/admin/logout', (req, res) => {
        res.clearCookie('admin_session');
        res.json({ success: true });
    });

    // 2. Users list
    app.post('/api/admin/users/:id/pin', adminAuth, (req, res) => {
        const userId = req.params.id;
        db.get('SELECT is_pinned FROM users WHERE id = ?', [userId], (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!row) return res.status(404).json({ error: 'User not found' });
            const newStatus = row.is_pinned ? 0 : 1;
            db.run('UPDATE users SET is_pinned = ? WHERE id = ?', [newStatus, userId], (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json({ success: true, is_pinned: newStatus });
            });
        });
    });

    app.get('/api/admin/users', adminAuth, (req, res) => {
        const query = `
            SELECT id, telegram_id, email, display_name, wallet_address, balance_rub, usdt_balance, is_banned, role, is_verified_trader, created_at, is_pinned 
            FROM users
            WHERE is_fake = 0
            ORDER BY is_pinned DESC, id ASC
        `;
        db.all(query, [], (err, users) => {
            if (err) {
                console.error('Error fetching users:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json(users);
        });
    });

    // 3. User balance update
    app.post('/api/admin/users/:id/balance', adminAuth, (req, res) => {
        const { id } = req.params;
        
        let newBalance = req.body.rub_balance;
        if (newBalance === undefined) {
            newBalance = req.body.amount || req.body.balance || 0;
        }

        const amount = parseFloat(newBalance);
        if (isNaN(amount) || amount < 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }
        
        db.run('UPDATE users SET balance_rub = ? WHERE id = ?', [amount, id], function(err) {
            if (err) {
                console.error('Error updating balance:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ success: true, newBalance: amount });
        });
    });

    // 4. Deals (P2P and general)
    app.get('/api/admin/deals', adminAuth, (req, res) => {
        db.all('SELECT * FROM p2p_deals', [], (err, deals) => {
            if (err) {
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json(deals);
        });
    });
    
    app.get('/api/admin/p2p_deals', adminAuth, (req, res) => {
        db.all('SELECT * FROM p2p_deals', [], (err, deals) => {
            if (err) {
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json(deals);
        });
    });

    app.get('/api/admin/p2p_ads', adminAuth, (req, res) => {
        db.all('SELECT * FROM p2p_ads WHERE maker_id IN (SELECT id FROM users WHERE is_fake = 0)', [], (err, ads) => {
            if (err) return res.status(500).json({ error: 'Internal server error' });
            res.json(ads);
        });
    });

    app.post('/api/admin/p2p_ads/:id/moderate', adminAuth, (req, res) => {
        const { status, admin_comment } = req.body;
        db.run('UPDATE p2p_ads SET status = ?, admin_comment = ? WHERE id = ?', [status, admin_comment || null, req.params.id], function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        });
    });
    // WebSockets Setup
    io.on('connection', (socket) => {
        console.log('Socket connected:', socket.id);

        // Join Deal Room
        socket.on('join_deal', (dealId) => {
            socket.join(`p2p_deal_${dealId}`);
            console.log(`Socket ${socket.id} joined p2p_deal_${dealId}`);
        });

        // Join Admin Room
        socket.on('join_admin', () => {
            socket.join('admin_room');
            console.log(`Socket ${socket.id} joined admin_room`);
        });

        // Broadcast chat messages in deals
        socket.on('deal:chat_send', (data) => {
            const { dealId, message, sender } = data;
            if (dealId) {
                io.to(`p2p_deal_${dealId}`).emit('deal:chat_send', data);
            }
        });

        // Broadcast deal updates
        socket.on('deal:update', (data) => {
            if (data.dealId) {
                io.to(`p2p_deal_${data.dealId}`).emit('deal:update', data);
                io.to('admin_room').emit('deal:update', data);
            }
        });

        // Broadcast request freeze
        socket.on('admin:request_freeze', (data) => {
            io.to('admin_room').emit('admin:request_freeze', data);
        });
        
        socket.on('disconnect', () => {
            console.log('Socket disconnected:', socket.id);
        });
    });

})();
require('./telegram_bot.js')(app, io, dbGet, dbRun, dbAll, JWT_SECRET);
// ==== END MODULES ====


// ==================== REVIEWS API ====================
const reviewsAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    });
};

app.get('/api/reviews/preview', async (req, res) => {
    try {
        const rows = await dbAll("SELECT * FROM reviews WHERE status = 'approved' ORDER BY created_at DESC LIMIT 3");
        res.json({ reviews: rows });
    } catch(err) {
        res.status(500).json({ error: 'DB Error' });
    }
});

app.get('/api/reviews', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 4;
    const offset = (page - 1) * limit;

    try {
        const row = await dbGet("SELECT COUNT(*) as cnt FROM reviews WHERE status = 'approved'");
        const totalPages = Math.ceil(row.cnt / limit);
        const rows = await dbAll("SELECT * FROM reviews WHERE status = 'approved' ORDER BY created_at DESC LIMIT ? OFFSET ?", [limit, offset]);
        res.json({ reviews: rows, totalPages });
    } catch (err) {
        res.status(500).json({ error: 'DB Error' });
    }
});

app.post('/api/reviews', reviewsAuth, async (req, res) => {
    const { text } = req.body;
    if (!text || text.trim().length < 5) return res.status(400).json({ error: 'Review too short' });

    try {
        await dbRun("INSERT INTO reviews (user_id, author, text, status) VALUES (?, ?, ?, 'pending')", 
            [req.user.id, req.user.username || 'Пользователь', text.trim()]);
        res.json({ success: true, message: 'Review submitted for moderation' });
    } catch(err) {
        res.status(500).json({ error: 'DB Error' });
    }
});





// ==================== RESTORED MODULES ====================
const strictGlobalAuthenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const secret = typeof JWT_SECRET !== 'undefined' ? JWT_SECRET : (process.env.JWT_SECRET || 'mao_exchange_super_secret_jwt_key_2025');
    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    });
};

const strictGlobalAdminAuth = (req, res, next) => {
    if (req.cookies && req.cookies.admin_session === 'authenticated') {
        req.user = { role: 'admin' };
        return next();
    }
    strictGlobalAuthenticate(req, res, () => {
        if (req.user && req.user.role === 'admin') return next();
        res.status(403).json({ error: 'Forbidden: Admins only' });
    });
};

// Classic Exchange & Settings API Endpoints
// Assuming `app`, `authenticate`, `adminAuth`, `dbRun`, `dbGet`, `dbAll` are available in scope.

// Use an in-memory lock to prevent sqlite3 transaction interleaving on a shared connection
let orderMutex = Promise.resolve();

// 1. GET /api/reserves and GET /api/settings
app.get('/api/reserves', async (req, res) => {
    try {
        const row = await dbGet("SELECT value FROM settings WHERE key = 'reserves'");
        if (row && row.value) {
            res.json({ success: true, reserves: JSON.parse(row.value) });
        } else {
            res.json({ success: false, message: "Reserves not found" });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.get('/api/settings', async (req, res) => {
    try {
        const rows = await dbAll("SELECT key, value FROM settings");
        const settings = {};
        for (const r of rows) {
            try { 
                settings[r.key] = JSON.parse(r.value); 
            } catch { 
                settings[r.key] = r.value; 
            }
        }
        res.json({ success: true, settings });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// 2. GET /api/user/orders (User exchange history)
app.get('/api/user/orders', strictGlobalAuthenticate, async (req, res) => {
    try {
        const rows = await dbAll("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
        res.json({ success: true, orders: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});


// GET /api/activity (Public live activity feed)
app.get('/api/activity', async (req, res) => {
    try {
        const activities = await dbAll("SELECT from_currency, to_currency, amount_give as amount, status, created_at FROM orders ORDER BY created_at DESC LIMIT 8");
        res.json({ success: true, data: activities || [] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. POST /api/orders (Create classic exchange order)
app.post('/api/orders', strictGlobalAuthenticate, async (req, res) => {
    const { from_currency, to_currency, amount_give, amount_get, user_wallet, from_network, to_network } = req.body;
    const userId = req.user.id;
    
    const amtGet = parseFloat(amount_get);
    const amtGive = parseFloat(amount_give);

    if (isNaN(amtGet) || isNaN(amtGive) || amtGet <= 0 || amtGive <= 0) {
        return res.status(400).json({ success: false, message: "Invalid amount provided" });
    }

    const executeOrder = async () => {
        // P2P-Escrow-Architect Principle: ACID Atomicity
        // Using an explicit transaction (serialized by orderMutex to prevent Node async interleaving)
        await dbRun("BEGIN IMMEDIATE TRANSACTION");
        try {
            const reservesRow = await dbGet("SELECT value FROM settings WHERE key = 'reserves'");
            let reserves = {};
            if (reservesRow && reservesRow.value) {
                reserves = JSON.parse(reservesRow.value);
            }
            
            // Prevent overselling of reserves. If undefined, we assume unlimited.
            if (reserves[to_currency] !== undefined && reserves[to_currency] < amtGet) {
                 throw new Error("Insufficient pool reserves for this transaction");
            }
            
            if (reserves[to_currency] !== undefined) {
                reserves[to_currency] -= amtGet;
                await dbRun("UPDATE settings SET value = ? WHERE key = 'reserves'", [JSON.stringify(reserves)]);
            }
            
            // Find an active requisite to receive fiat/crypto
            const reqRow = await dbGet("SELECT * FROM service_requisites WHERE currency = ? AND is_active = 1 LIMIT 1", [from_currency]);
            const depositAddress = reqRow ? reqRow.account_number : null;

            const result = await dbRun(`
                INSERT INTO orders (
                    user_id, from_currency, to_currency, amount_give, amount_get, user_wallet, 
                    from_network, to_network, deposit_address, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
            `, [
                userId, from_currency, to_currency, amtGive, amtGet, 
                user_wallet, from_network, to_network, depositAddress
            ]);
            
            await dbRun("COMMIT");
            return { orderId: result.lastID, depositAddress };
        } catch (err) {
            try { await dbRun("ROLLBACK"); } catch (e) {}
            throw err;
        }
    };

    try {
        let result;
        const currentMutex = orderMutex;
        orderMutex = currentMutex.then(async () => {
            try {
                result = await executeOrder();
            } catch (err) {
                result = { error: err };
            }
        });
        await orderMutex;
        if (result && result.error) throw result.error;
        
        if (global.tgNotifyAdmin) {
            global.tgNotifyAdmin(`Новый классический ордер #${result.orderId}, сумма: ${amtGet}, актив: ${to_currency}`);
        }

        res.json({ success: true, orderId: result.orderId, depositAddress: result.depositAddress });
    } catch (err) {
        if (err.message === "Insufficient pool reserves for this transaction") {
            res.status(400).json({ success: false, message: err.message });
        } else {
            res.status(500).json({ success: false, message: err.message });
        }
    }
});

// 4. Admin Routes for Requisites (GET/POST/DELETE)
app.get('/api/admin/requisites', strictGlobalAdminAuth, async (req, res) => {
    try {
        const rows = await dbAll("SELECT * FROM service_requisites");
        res.json({ success: true, requisites: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/admin/requisites', strictGlobalAdminAuth, async (req, res) => {
    const { id, currency, bank_name, recipient_name, account_number, daily_limit, is_active } = req.body;
    try {
        if (id) {
            await dbRun(`
                UPDATE service_requisites 
                SET currency = ?, bank_name = ?, recipient_name = ?, account_number = ?, daily_limit = ?, is_active = ?
                WHERE id = ?
            `, [
                currency, 
                bank_name || null, 
                recipient_name || null, 
                account_number, 
                daily_limit || 500000, 
                is_active === undefined ? 1 : is_active, 
                id
            ]);
        } else {
            await dbRun(`
                INSERT INTO service_requisites (currency, bank_name, recipient_name, account_number, daily_limit, is_active)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [
                currency, 
                bank_name || null, 
                recipient_name || null, 
                account_number, 
                daily_limit || 500000, 
                is_active === undefined ? 1 : is_active
            ]);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/admin/requisites/:id', strictGlobalAdminAuth, async (req, res) => {
    try {
        await dbRun("DELETE FROM service_requisites WHERE id = ?", [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});



const optionalAuth = (req, res, next) => {
    if (req.headers && req.headers.authorization) {
        if (typeof authenticate === 'function') {
            return authenticate(req, res, next);
        }
    }
    next();
};

// POST /api/support/messages (юзер пишет в саппорт)
app.post('/api/support/messages', optionalAuth, async (req, res) => {
    try {
        const { message, guest_id, override_user_id, sender } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        let userId = req.user ? req.user.id : null;
        let guestId = guest_id || null;
        let actualSender = 'user';

        if (req.user && (req.user.role === 'admin' || req.user.role === 'superadmin') && sender === 'agent') {
            if (override_user_id) {
                if (override_user_id.startsWith('guest_')) {
                    guestId = override_user_id;
                    userId = null;
                } else {
                    userId = override_user_id;
                }
            }
            actualSender = 'agent';
        }
        
        if (!userId && !guestId) {
            return res.status(400).json({ error: 'User ID or Guest ID is required' });
        }

        await dbRun(
            `INSERT INTO support_messages (user_id, guest_id, sender, message) VALUES (?, ?, ?, ?)`,
            [userId, guestId, actualSender, message]
        );
        
        res.json({ success: true, message: 'Message sent successfully' });
    } catch (err) {
        console.error('Error sending support message:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/support/chats
app.get('/api/admin/support/chats', strictGlobalAdminAuth, async (req, res) => {
    try {
        const chats = await dbAll(`
            SELECT 
                user_id, 
                guest_id,
                message as last_message,
                sender as last_sender,
                MAX(created_at) as last_message_date,
                COUNT(id) as message_count
            FROM support_messages
            GROUP BY user_id, guest_id
            ORDER BY last_message_date DESC
        `);
        res.json({ success: true, chats });
    } catch (err) {
        console.error('Error fetching support chats:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/support/messages/:chatId
app.get('/api/admin/support/messages/:chatId', strictGlobalAdminAuth, async (req, res) => {
    try {
        const { chatId } = req.params;
        let messages = [];

        let isUser = false;
        let isGuest = false;
        let idValue = chatId;

        if (chatId.startsWith('user_')) {
            isUser = true;
            idValue = chatId.replace('user_', '');
        } else if (chatId.startsWith('guest_')) {
            isGuest = true;
            idValue = chatId.replace('guest_', '');
        } else if (!isNaN(chatId)) {
            isUser = true;
        } else {
            isGuest = true;
        }

        if (isUser) {
            messages = await dbAll(
                `SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at ASC`,
                [idValue]
            );
        } else {
            messages = await dbAll(
                `SELECT * FROM support_messages WHERE guest_id = ? OR guest_id = ? ORDER BY created_at ASC`,
                [idValue, chatId]
            );
        }

        res.json({ success: true, messages });
    } catch (err) {
        console.error('Error fetching support messages:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/users/:userId/ban
app.post('/api/admin/users/:userId/ban', strictGlobalAdminAuth, async (req, res) => {
    try {
        const { userId } = req.params;
        let banStatus = 1;

        if (req.body && typeof req.body.is_banned !== 'undefined') {
            banStatus = req.body.is_banned ? 1 : 0;
        } else {
            const user = await dbGet('SELECT is_banned FROM users WHERE id = ?', [userId]);
            if (user) {
                banStatus = user.is_banned ? 0 : 1;
            } else {
                return res.status(404).json({ error: 'User not found' });
            }
        }

        await dbRun(`UPDATE users SET is_banned = ? WHERE id = ?`, [banStatus, userId]);
        res.json({ success: true, message: banStatus ? 'User banned' : 'User unbanned' });
    } catch (err) {
        console.error('Error updating user ban status:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/users/:userId/verify_trader
app.post('/api/admin/users/:userId/verify_trader', strictGlobalAdminAuth, async (req, res) => {
    try {
        const { userId } = req.params;
        let verifyStatus = 1;

        if (req.body && typeof req.body.is_verified_trader !== 'undefined') {
            verifyStatus = req.body.is_verified_trader ? 1 : 0;
        } else {
            const user = await dbGet('SELECT is_verified_trader FROM users WHERE id = ?', [userId]);
            if (user) {
                verifyStatus = user.is_verified_trader ? 0 : 1;
            } else {
                return res.status(404).json({ error: 'User not found' });
            }
        }

        await dbRun(`UPDATE users SET is_verified_trader = ? WHERE id = ?`, [verifyStatus, userId]);
        res.json({ success: true, message: verifyStatus ? 'Trader verified' : 'Trader verification removed' });
    } catch (err) {
        console.error('Error updating trader verification status:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/admin/reviews
app.get('/api/admin/reviews', strictGlobalAdminAuth, async (req, res) => {
    try {
        const status = req.query.status;
        let reviews = [];
        if (status) {
            reviews = await dbAll(`SELECT * FROM reviews WHERE status = ? ORDER BY created_at DESC`, [status]);
        } else {
            reviews = await dbAll(`SELECT * FROM reviews ORDER BY created_at DESC`);
        }
        res.json({ success: true, reviews });
    } catch (err) {
        console.error('Error fetching reviews:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/admin/reviews/:id/approve
app.post('/api/admin/reviews/:id/approve', strictGlobalAdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await dbRun(`UPDATE reviews SET status = 'approved' WHERE id = ?`, [id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Review not found' });
        }
        res.json({ success: true, message: 'Review approved' });
    } catch (err) {
        console.error('Error approving review:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/admin/reviews/:id/delete
app.delete('/api/admin/reviews/:id/delete', strictGlobalAdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await dbRun(`DELETE FROM reviews WHERE id = ?`, [id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Review not found' });
        }
        res.json({ success: true, message: 'Review deleted' });
    } catch (err) {
        console.error('Error deleting review:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const { generateSecret, verify, NobleCryptoPlugin, ScureBase32Plugin } = require('otplib');
const qrcode = require('qrcode');

// POST /api/auth/2fa/generate
app.post('/api/auth/2fa/generate', strictGlobalAuthenticate, async (req, res) => {
    try {
        const secret = generateSecret({ base32: new ScureBase32Plugin() });
        const email = req.user.email || 'user@example.com';
        const otpauth_url = `otpauth://totp/CryptoApp:${encodeURIComponent(email)}?secret=${secret}&issuer=CryptoApp`;
        
        await dbRun('UPDATE users SET two_factor_secret = ? WHERE id = ?', [secret, req.user.id]);
        
        const qr_code_url = await qrcode.toDataURL(otpauth_url);
        
        res.json({
            secret: secret,
            qr_code_url: qr_code_url
        });
    } catch (error) {
        console.error('Error generating 2FA secret:', error);
        res.status(500).json({ error: 'Failed to generate 2FA secret' });
    }
});

// POST /api/auth/2fa/enable
app.post('/api/auth/2fa/enable', strictGlobalAuthenticate, async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ error: 'Token is required' });

        const user = await dbGet('SELECT two_factor_secret FROM users WHERE id = ?', [req.user.id]);
        
        if (!user || !user.two_factor_secret) {
            return res.status(400).json({ error: '2FA not initialized' });
        }

        const result = await verify({ 
            token, 
            secret: user.two_factor_secret,
            crypto: new NobleCryptoPlugin(),
            base32: new ScureBase32Plugin()
        });

        if (result.valid) {
            await dbRun('UPDATE users SET two_factor_enabled = 1 WHERE id = ?', [req.user.id]);
            res.json({ message: '2FA enabled successfully' });
        } else {
            res.status(400).json({ error: 'Invalid 2FA token' });
        }
    } catch (error) {
        console.error('Error enabling 2FA:', error);
        res.status(500).json({ error: 'Failed to enable 2FA' });
    }
});

// GET /api/auth/telegram/init
app.get('/api/auth/telegram/init', async (req, res) => {
    try {
        const code = Math.random().toString(36).substring(2, 10).toUpperCase();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        
        await dbRun('INSERT INTO auth_codes (code, expires_at, status) VALUES (?, ?, ?)', [code, expiresAt, 'pending']);

        const botUsername = 'CryptoAppMockBot';
        res.json({ 
            code, 
            bot_url: `https://t.me/${botUsername}?start=${code}` 
        });
    } catch (error) {
        console.error('Error initializing Telegram auth:', error);
        res.status(500).json({ error: 'Failed to initialize Telegram auth' });
    }
});

// GET /api/auth/telegram/check/:code
app.get('/api/auth/telegram/check/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        const authData = await dbGet('SELECT * FROM auth_codes WHERE code = ?', [code]);

        if (!authData) {
            return res.status(404).json({ error: 'Code not found' });
        }

        const now = new Date();
        const expires = new Date(authData.expires_at);
        if (now > expires) {
            return res.status(400).json({ error: 'Code expired' });
        }

        if (authData.status === 'verified' && authData.user_id) {
            const user = await dbGet('SELECT * FROM users WHERE id = ?', [authData.user_id]);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            const jwtSecret = typeof JWT_SECRET !== 'undefined' ? JWT_SECRET : (process.env.JWT_SECRET || 'mao_exchange_super_secret_jwt_key_2025');
            const token = jwt.sign({ id: user.id, email: user.email }, jwtSecret, { expiresIn: '7d' }); 
            
            await dbRun('DELETE FROM auth_codes WHERE code = ?', [code]);
            
            const returnUser = {
                id: user.id,
                email: user.email,
                display_name: user.display_name,
                wallet_address: user.wallet_address,
                usdt_balance: user.usdt_balance,
                role: user.role,
                balance_rub: user.balance_rub
            };

            return res.json({ status: 'success', token, user: returnUser });
        } else {
            return res.json({ status: 'pending' });
        }
    } catch (error) {
        console.error('Error checking Telegram auth code:', error);
        res.status(500).json({ error: 'Failed to check Telegram auth' });
    }
});

// HTML Fallbacks
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.use((req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function autoGenerateActivity() {
    const minTime = 2 * 60 * 1000;
    const maxTime = 7 * 60 * 1000;
    const delay = Math.floor(Math.random() * (maxTime - minTime + 1)) + minTime;

    setTimeout(async () => {
        try {
            const rand = Math.random();
            let status = 'completed';
            if (rand > 0.9) {
                status = 'canceled';
            } else if (rand > 0.7) {
                status = 'pending';
            }
            
            const coins = ['USDT', 'BTC', 'ETH', 'USDC', 'SOL', 'BNB', 'TON', 'TRX', 'XRP', 'DOGE', 'LTC'];
            const from_currency = coins[Math.floor(Math.random() * coins.length)];
            const to_currency = 'RUB';
            const amount_give = (Math.random() * 500 + 10).toFixed(2);
            
            await dbRun(
                `INSERT INTO orders (
                    user_id, from_currency, to_currency, amount_give, amount_get, user_wallet, 
                    from_network, to_network, deposit_address, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    0, from_currency, to_currency, amount_give, amount_give * 90, 
                    'system', 'Network', 'Network', 'system', status
                ]
            );
        } catch (err) {
            console.error('Error in autoGenerateActivity:', err);
        }
        autoGenerateActivity();
    }, delay);
}
autoGenerateActivity();

const PORT = process.env.PORT || 5050;
server.listen(PORT, () => {
    console.log('🚀 Сервер MAO Exchange запущен на порту ' + PORT);
});
