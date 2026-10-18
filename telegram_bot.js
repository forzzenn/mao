const TelegramBot = require('node-telegram-bot-api');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

module.exports = function(app, io, dbGet, dbRun, dbAll, JWT_SECRET) {
    const token = '8962012080:AAHmLPGSFA3unRYUtukTPsSuj27O6RCnQ68';
    const bot = new TelegramBot(token, { polling: true });
    
    const authRequests = {};
    
    bot.onText(/\/start (.+)/, async (msg, match) => {
        const chatId = msg.chat.id;
        const username = msg.from.username || msg.from.first_name || 'Трейдер';
        const payload = match[1];
        
        if (payload.startsWith('auth_')) {
            const uuid = payload.replace('auth_', '');
            if (authRequests[uuid]) {
                const socketId = authRequests[uuid];
                
                let user = await dbGet('SELECT * FROM users WHERE telegram_id = ?', [chatId]);
                if (!user) {
                    const res = await dbRun(
                        `INSERT INTO users (telegram_id, telegram_username, display_name, verification_status, is_verified_trader) VALUES (?, ?, ?, ?, ?)`,
                        [chatId, username, username, 'verified', 0]
                    );
                    user = await dbGet('SELECT * FROM users WHERE id = ?', [res.lastID]);
                }
                
                const jwtToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
                
                bot.sendMessage(chatId, '✅ Вы успешно авторизовались на MAO Exchange! Возвращайтесь на сайт.');
                io.to(socketId).emit('telegram:auth_success', { token: jwtToken, user });
                delete authRequests[uuid];
            } else {
                bot.sendMessage(chatId, '❌ Ссылка для авторизации недействительна или устарела. Попробуйте обновить страницу на сайте.');
            }
        }
    });

    bot.onText(/\/start$/, (msg) => {
        if (msg.chat.type === 'private') {
            bot.sendMessage(msg.chat.id, 'Добро пожаловать в бота MAO Exchange! Для авторизации на сайте используйте кнопку "Войти через Telegram" на сайте.');
        }
    });

    bot.on('message', (msg) => {
        if (msg.chat.type === 'group' || msg.chat.type === 'supergroup') {
            if (!global.ADMIN_GROUP_CHAT_ID) {
                global.ADMIN_GROUP_CHAT_ID = msg.chat.id;
                bot.sendMessage(msg.chat.id, '✅ Эта группа привязана как административная. Сюда будут приходить логи и алерты MAO Exchange.');
                console.log(`[TG BOT] Registered admin group: ${msg.chat.id}`);
            }
        }
    });

    app.get('/api/auth/telegram-request', (req, res) => {
        const socketId = req.query.socketId;
        if (!socketId) return res.status(400).json({ error: 'socketId required' });
        
        const uuid = uuidv4();
        authRequests[uuid] = socketId;
        setTimeout(() => { delete authRequests[uuid]; }, 5 * 60 * 1000);
        
        bot.getMe().then(botInfo => {
            res.json({ success: true, botUrl: `https://t.me/${botInfo.username}?start=auth_${uuid}` });
        }).catch(err => {
            res.json({ success: false, error: err.message });
        });
    });
    
    global.tgNotifyAdmin = (text) => {
        if (global.ADMIN_GROUP_CHAT_ID) {
            bot.sendMessage(global.ADMIN_GROUP_CHAT_ID, `🛡 [АДМИН] ${text}`).catch(e => console.error(e));
        }
    };
    
    global.tgNotifyUser = async (userId, text) => {
        try {
            const user = await dbGet('SELECT telegram_id FROM users WHERE id = ?', [userId]);
            if (user && user.telegram_id) {
                bot.sendMessage(user.telegram_id, text).catch(e => console.error(e));
            }
        } catch(e) {}
    };
};
