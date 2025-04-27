const TelegramBot = require('node-telegram-bot-api');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const { MongoClient } = require('mongodb');
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
require('dotenv').config();

// Environment variables
const PORT = process.env.PORT || 3000;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID_FOR_QR_CODE = process.env.CHAT_ID_FOR_QR_CODE;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin8898@';
const TOKEN_EXPIRY_HOURS = parseInt(process.env.TOKEN_EXPIRY_HOURS || '24');

// MongoDB connection
const clientMongo = new MongoClient(MONGO_URI);

// Global MongoDB Collections
let usageCollection, usersCollection, apiKeysCollection, verificationCodesCollection, sessionsCollection, adminCollection;

// Initialize Telegram Bot
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });

// WhatsApp client and session storage
let client;

// Admin token management
const ADMIN_TOKENS = new Map(); // Store active tokens

// Create necessary directories
function createDirectories() {
    try {
        // Create .wwebjs_auth_local directory if it doesn't exist
        const authDir = path.join(__dirname, '.wwebjs_auth_local');
        if (!fs.existsSync(authDir)) {
            fs.mkdirSync(authDir, { recursive: true });
            console.log('Created auth directory:', authDir);
        }
        
        return true;
    } catch (err) {
        console.error('Error creating directories:', err);
        return false;
    }
}

// Connect to MongoDB
async function connectMongo() {
    try {
        await clientMongo.connect();
        const db = clientMongo.db('WSChecker');
        usageCollection = db.collection('usage');
        usersCollection = db.collection('users');
        apiKeysCollection = db.collection('apiKeys');
        verificationCodesCollection = db.collection('verificationCodes');
        adminCollection = db.collection('admin');
        console.log('Connected to MongoDB');
        
        // Initialize the admin user if it doesn't exist
        await initializeAdmin();
        
        // Create directories for WhatsApp session
        createDirectories();
        
        // Initialize WhatsApp client directly with LocalAuth
        initializeWhatsApp();
    } catch (err) {
        console.error('MongoDB connection error:', err);
    }
}
connectMongo();

// Initialize admin user
async function initializeAdmin() {
    try {
        const adminUser = await adminCollection.findOne({});
        
        if (!adminUser) {
            console.log('No admin user found, creating default admin...');
            
            // Hash the password
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            await adminCollection.insertOne({
                username: ADMIN_USERNAME,
                password: hashedPassword,
                createdAt: new Date()
            });
            console.log('Default admin user created');
        } else {
            // Update admin with new credentials
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            await adminCollection.updateOne(
                { _id: adminUser._id },
                { 
                    $set: { 
                        username: ADMIN_USERNAME,
                        password: hashedPassword 
                    } 
                }
            );
            console.log('Admin user credentials updated');
        }
    } catch (err) {
        console.error('Error initializing admin user:', err);
    }
}

// Initialize WhatsApp
async function initializeWhatsApp() {
    try {
        console.log('Initializing WhatsApp client...');
        
        // Create required directories
        if (!createDirectories()) {
            console.error('Failed to create necessary directories');
            return;
        }
        
        // Initialize client with local auth
        const { Client, LocalAuth } = require('whatsapp-web.js');
        
        client = new Client({
            authStrategy: new LocalAuth({
                dataPath: path.join(__dirname, '.wwebjs_auth_local')
            }),
            puppeteer: {
                headless: true,
                args: [
                    '--no-sandbox', 
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu'
                ]
            }
        });
        
        // Set up event handlers
        setupWhatsAppEventHandlers();
        
        // Initialize the client
        await client.initialize().catch(err => {
            console.error('Error initializing WhatsApp client:', err);
            
            // If there's an error, try to reinitialize after some time
            setTimeout(() => {
                console.log('Retrying WhatsApp initialization in 30 seconds...');
                initializeWhatsApp();
            }, 30000);
        });
    } catch (error) {
        console.error('Critical error in initializeWhatsApp:', error);
        
        // Clear any existing client
        if (client) {
            client.destroy().catch(err => console.log('Error destroying client:', err.message));
            client = null;
        }
        
        // Try again after a delay
        setTimeout(() => {
            console.log('Retrying WhatsApp initialization after error...');
            initializeWhatsApp();
        }, 30000);
    }
}

// Set up WhatsApp event handlers
function setupWhatsAppEventHandlers() {
    // Prevent adding duplicate event listeners
    client.removeAllListeners();
    
    // QR code handling
client.on('qr', (qr) => {
    console.log('Scan this QR code with your WhatsApp app:');
    qrcode.generate(qr, { small: true });
        // Store the QR code for admin dashboard
        global.latestQR = qr;
    bot.sendMessage(CHAT_ID_FOR_QR_CODE, `Scan this QR code to log in to WhatsApp:\n${qr}`);
});

client.on('ready', () => {
    console.log('WhatsApp client is ready!');
        // Clear QR code when ready
        global.latestQR = null;
        bot.sendMessage(CHAT_ID_FOR_QR_CODE, 'WhatsApp client is ready and connected!');
    });
    
    client.on('authenticated', (session) => {
        console.log('WhatsApp session authenticated');
    });
    
    client.on('auth_failure', (error) => {
        console.error('Authentication failed:', error);
        bot.sendMessage(CHAT_ID_FOR_QR_CODE, 'WhatsApp authentication failed. Please restart the session.');
        
        // Try to recover by reinitializing, with a flag to prevent multiple reinits
        if (!client.isReinitializing) {
            client.isReinitializing = true;
            setTimeout(() => {
                console.log('Attempting to reinitialize WhatsApp client...');
                client.isReinitializing = false;
                initializeWhatsApp();
            }, 5000);
        }
    });
    
    client.on('disconnected', (reason) => {
        console.error('Disconnected from WhatsApp Web:', reason);
        bot.sendMessage(CHAT_ID_FOR_QR_CODE, 'Disconnected from WhatsApp. Attempting to reconnect...');
        
        // Try to recover by reinitializing, with a flag to prevent multiple reinits
        if (!client.isReinitializing) {
            client.isReinitializing = true;
            setTimeout(() => {
                console.log('Attempting to reinitialize WhatsApp client after disconnection...');
                client.isReinitializing = false;
                initializeWhatsApp();
            }, 5000);
        }
    });
    
    client.on('loading_screen', (percent, message) => {
        console.log(`WhatsApp loading: ${percent}% - ${message}`);
    });
    
    client.on('change_state', state => {
        console.log('WhatsApp connection state:', state);
    });
    
    // Error handling
    client.on('error', error => {
        console.error('WhatsApp client error:', error);
        
        // Check if error is related to session
        if (error.message && (
            error.message.includes('session') || 
            error.message.includes('auth') ||
            error.message.includes('ENOENT')
        )) {
            console.log('Session-related error detected, attempting to recover...');
            
            // Try to recover by reinitializing, with a flag to prevent multiple reinits
            if (!client.isReinitializing) {
                client.isReinitializing = true;
                setTimeout(() => {
                    console.log('Attempting to reinitialize WhatsApp client after error...');
                    client.isReinitializing = false;
                    initializeWhatsApp();
                }, 5000);
            }
        }
    });
}

// Handle Telegram Messages
bot.on('message', async (msg) => {
    const chatId = String(msg.chat.id);
    const userId = String(msg.from.id);
    const username = msg.from.username || 'N/A';
    const text = msg.text;
    const contact = msg.contact;

    // Update or insert user
    try {
        await usersCollection.updateOne(
            { chatId },
            { $set: { userId, username, lastActive: new Date().toISOString() } },
            { upsert: true }
        );
    } catch (err) {
        console.error('Error storing user:', err);
    }

    // /start or /help command
    if (text === '/start' || text === '/help') {
        const helpMessage = `*Welcome to WhatsApp Checker Bot!*\n\n`+
            `*Available Commands:*\n` +
            `- /getapi - Get an API key for WhatsApp Checker\n` +
            `- /stats - View your usage statistics\n` +
            `- /verify CODE - Verify your phone with a code\n` +
            `- /apidocs - Get API documentation URL\n` +
            `- /help - Show this help message\n\n` +
            `*How to check numbers:*\n` +
            `Simply send any phone number(s) to check if they're registered on WhatsApp. You can send multiple numbers, one per line.`;
        
        bot.sendMessage(chatId, helpMessage, { parse_mode: 'Markdown' });
        return;
    }

    // /apidocs command to get API documentation URL
    if (text === '/apidocs') {
        const apiDocsMessage = `*WhatsApp Checker API Documentation*\n\n` +
            `Access our API docs at:\n` +
            `http://192.168.102.35:3000/api-docs\n\n` +
            `The documentation includes details on:\n` +
            `- How to get an API key\n` +
            `- Available endpoints\n` +
            `- Request and response formats\n` +
            `- Code examples in various languages`;
        
        bot.sendMessage(chatId, apiDocsMessage, { parse_mode: 'Markdown' });
        return;
    }

    // /stats command
    if (text === '/stats') {
        try {
            const total = await usageCollection.countDocuments({ userId });
            const registered = await usageCollection.countDocuments({ userId, result: /✅/ });
            const rate = total ? (registered / total * 100).toFixed(2) : 0;
            bot.sendMessage(chatId, `Your Stats:\nTotal Checks: ${total}\nRegistered: ${registered} (${rate}%)`);
        } catch (err) {
            console.error('Error fetching stats:', err);
            bot.sendMessage(chatId, 'Error fetching your stats.');
        }
        return;
    }

    // /getapi command to register for API access
    if (text === '/getapi') {
        const shareContactKeyboard = {
            reply_markup: {
                keyboard: [[{
                    text: 'Share Contact',
                    request_contact: true
                }]],
                resize_keyboard: true,
                one_time_keyboard: true
            }
        };
        
        bot.sendMessage(
            chatId, 
            'To get an API key, please share your contact by pressing the button below or use the command /phone followed by your phone number.',
            shareContactKeyboard
        );
        return;
    }

    // Verify phone code via Telegram - simplified to accept just the code
    if (text && /^\d{6}$/.test(text.trim())) {
        const code = text.trim();
        try {
            // Find verification code by telegram ID
            const verificationRecord = await verificationCodesCollection.findOne({ 
                telegramId: userId,
                code
            });
            
            if (!verificationRecord) {
                // Not a verification code, treat as regular message
                await processPhoneNumber(chatId, userId, username, text);
                return;
            }
            
            if (new Date() > new Date(verificationRecord.expiresAt)) {
                bot.sendMessage(chatId, 'Verification code has expired. Please request a new one with /getapi');
                return;
            }
            
            // Generate API key
            const apiKey = generateApiKey();
            const phoneNumber = verificationRecord.phoneNumber;
            
            // Store API key
            await apiKeysCollection.updateOne(
                { phoneNumber },
                { 
                    $set: { 
                        key: apiKey,
                        telegramId: userId,
                        chatId,
                        verified: true,
                        createdAt: new Date(),
                        lastUsed: new Date(),
                        usageCount: 0,
                        disabled: false
                    }
                },
                { upsert: true }
            );
            
            // Delete verification code
            await verificationCodesCollection.deleteOne({ telegramId: userId, code });
            
            bot.sendMessage(chatId, `✅ Phone verified successfully!\n\nYour API key is:\n\n\`${apiKey}\`\n\nKeep this key secure. You can use it to access our WhatsApp Checker API.`, { parse_mode: 'Markdown' });
        } catch (err) {
            console.error('Error during verification:', err);
            bot.sendMessage(chatId, 'An error occurred. Please try again later.');
        }
        return;
    }

    // Verify phone code via Telegram with /verify command
    if (text && text.startsWith('/verify ')) {
        const code = text.split(' ')[1].trim();
        try {
            // Find verification code by telegram ID
            const verificationRecord = await verificationCodesCollection.findOne({ 
                telegramId: userId,
                code
            });
            
            if (!verificationRecord) {
                bot.sendMessage(chatId, 'Invalid verification code. Please try again.');
                return;
            }
            
            if (new Date() > new Date(verificationRecord.expiresAt)) {
                bot.sendMessage(chatId, 'Verification code has expired. Please request a new one with /getapi');
                return;
            }
            
            // Generate API key
            const apiKey = generateApiKey();
            const phoneNumber = verificationRecord.phoneNumber;
            
            // Store API key
            await apiKeysCollection.updateOne(
                { phoneNumber },
                { 
                    $set: { 
                        key: apiKey,
                        telegramId: userId,
                        chatId,
                        verified: true,
                        createdAt: new Date(),
                        lastUsed: new Date(),
                        usageCount: 0,
                        disabled: false
                    }
                },
                { upsert: true }
            );
            
            // Delete verification code
            await verificationCodesCollection.deleteOne({ telegramId: userId, code });
            
            bot.sendMessage(chatId, `✅ Phone verified successfully!\n\nYour API key is:\n\n\`${apiKey}\`\n\nKeep this key secure. You can use it to access our WhatsApp Checker API.`, { parse_mode: 'Markdown' });
        } catch (err) {
            console.error('Error during verification:', err);
            bot.sendMessage(chatId, 'An error occurred. Please try again later.');
        }
        return;
    }

    // Handle shared contact for API key registration
    if (contact) {
        const phoneNumber = contact.phone_number;
        let normalizedPhone;
        
        // Process phone number
        if (phoneNumber.startsWith('+')) {
            normalizedPhone = normalizePhoneNumber(phoneNumber);
        } else {
            normalizedPhone = normalizePhoneNumber('+' + phoneNumber);
        }
        
        if (!normalizedPhone) {
            bot.sendMessage(chatId, 'Invalid phone number format. Please provide a valid phone number with country code.');
            return;
        }

        try {
            // Check if phone is already registered
            const existingUser = await apiKeysCollection.findOne({ phoneNumber: normalizedPhone });
            if (existingUser && existingUser.verified) {
                bot.sendMessage(chatId, `This phone number is already registered. Your API key is: ${existingUser.key}`);
                return;
            }

            // Generate verification code
            const code = generateVerificationCode();
            
            await verificationCodesCollection.updateOne(
                { phoneNumber: normalizedPhone },
                { 
                    $set: { 
                        code,
                        telegramId: userId,
                        chatId,
                        expiresAt: new Date(Date.now() + 3600000) // Expires in 1 hour
                    }
                },
                { upsert: true }
            );
            
            // Reset keyboard to normal
            const resetKeyboard = {
                reply_markup: {
                    remove_keyboard: true
                }
            };
            
            // Send verification code directly in Telegram
            bot.sendMessage(
                chatId,
                `✅ Your verification code is: *${code}*\n\nPlease reply with the code to verify your phone and get an API key.\n\nThis code will expire in 1 hour.`,
                {
                    ...resetKeyboard,
                    parse_mode: 'Markdown'
                }
            );
        } catch (err) {
            console.error('Error during phone registration:', err);
            bot.sendMessage(chatId, 'An error occurred. Please try again later.');
        }
        return;
    }

    // Phone registration via Telegram - fallback for those who can't use contact sharing
    if (text && text.startsWith('/phone ')) {
        const phoneNumber = text.split(' ')[1].trim();
        const normalizedPhone = normalizePhoneNumber(phoneNumber);
        
        if (!normalizedPhone) {
            bot.sendMessage(chatId, 'Invalid phone number format. Please provide a valid phone number with country code.');
            return;
        }

        try {
            // Check if phone is already registered
            const existingUser = await apiKeysCollection.findOne({ phoneNumber: normalizedPhone });
            if (existingUser && existingUser.verified) {
                bot.sendMessage(chatId, `This phone number is already registered. Your API key is: ${existingUser.key}`);
                return;
            }

            // Generate verification code
            const code = generateVerificationCode();
            
            await verificationCodesCollection.updateOne(
                { phoneNumber: normalizedPhone },
                { 
                    $set: { 
                        code,
                        telegramId: userId,
                        chatId,
                        expiresAt: new Date(Date.now() + 3600000) // Expires in 1 hour
                    }
                },
                { upsert: true }
            );
            
            // Send verification code directly in Telegram
            bot.sendMessage(
                chatId,
                `✅ Your verification code is: *${code}*\n\nPlease reply with the code to verify your phone and get an API key.\n\nThis code will expire in 1 hour.`,
                { parse_mode: 'Markdown' }
            );
        } catch (err) {
            console.error('Error during phone registration:', err);
            bot.sendMessage(chatId, 'An error occurred. Please try again later.');
        }
        return;
    }

    // If it's not a command or contact, assume it's phone numbers to check
    if (text) {
        await processPhoneNumber(chatId, userId, username, text);
    }
});

// Process phone numbers for checking
async function processPhoneNumber(chatId, userId, username, text) {
    const rawNumbers = text.split(/[\n\s]+/).filter(Boolean);
    const validNumbers = rawNumbers.map(normalizePhoneNumber).filter(Boolean);

    if (validNumbers.length === 0) {
        bot.sendMessage(chatId, 'Please send valid phone numbers with country code.\nSingle or multiple numbers separated by newlines.');
        return;
    }

    bot.sendMessage(chatId, `Checking ${validNumbers.length} numbers...`);

    console.log('Normalized Numbers:', validNumbers);

    const results = await checkNumbersOnWhatsApp(validNumbers);

    const timestamp = new Date().toISOString();
    const records = validNumbers.map((number, i) => ({
        userId,
        username,
        timestamp,
        number,
        result: results[i]
    }));

    try {
        await usageCollection.insertMany(records);
    } catch (err) {
        console.error('Error logging usage:', err);
    }

    bot.sendMessage(chatId, results.join('\n'));
}

// Normalize Phone Numbers (international format)
function normalizePhoneNumber(number) {
    try {
        let cleaned = number.replace(/[^0-9+]/g, '');
        
        // Handle US/Canada numbers (starting with +1)
        if (cleaned.startsWith('+1')) {
            cleaned = '+1' + cleaned.slice(2).replace(/^0+/, '');
            if (cleaned.length !== 12) {
                console.warn(`Invalid US/Canada number format: ${number}`);
                return null;
            }
            return cleaned;
        }
        
        // Handle numbers without + prefix
        if (!cleaned.startsWith('+')) {
            // US/Canada 10-digit number
            if (cleaned.length === 10) {
                cleaned = '+1' + cleaned;
                return cleaned;
            }
            
            // Add + for other international numbers
            cleaned = '+' + cleaned;
        }
        
        // Ensure number has country code
        if (cleaned.length < 8) {
            console.warn(`Number too short, missing country code: ${number}`);
            return null;
        }
        
        // For now, we're focusing primarily on US/Canada numbers,
        // but we can validate and store other international numbers too
        return cleaned;
    } catch (error) {
        console.error(`Error normalizing number: ${number}`, error);
        return null;
    }
}

// Check Numbers on WhatsApp
async function checkNumbersOnWhatsApp(numbers) {
    const results = [];
    if (!client.info) {
        await new Promise(resolve => client.on('ready', resolve));
    }
    for (const number of numbers) {
        try {
            const phoneNumber = number.replace('+', '');
            const whatsappId = `${phoneNumber}@c.us`;
            console.log('Checking WID:', whatsappId);
            const isRegistered = await client.isRegisteredUser(whatsappId);
            if (isRegistered) {
                results.push(`✅ ${number} is registered on WhatsApp.`);
            } else {
                results.push(`❌ ${number} is NOT registered on WhatsApp.`);
            }
        } catch (error) {
            console.error(`Error checking ${number}:`, error.message);
            results.push(`⚠️ Error checking ${number}: ${error.message}`);
        }
    }
    return results;
}

// Express Web Server
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Generate a random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Validate admin token
function validateAdminToken(token) {
    return ADMIN_TOKENS.has(token);
}

// Add token auth middleware
function tokenAuth(req, res, next) {
    const token = req.query.token || req.body.token;
    
    if (!token || !validateAdminToken(token)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    next();
}

// Add this route before the /admin route
app.post('/admin-login', bodyParser.json(), async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Check against hardcoded credentials first for simplicity
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            const token = generateToken();
            ADMIN_TOKENS.set(token, { createdAt: Date.now() });
            
            // Return success with token
            return res.json({ success: true, token });
        }
        
        // Check credentials against MongoDB stored admin user
        const adminUser = await adminCollection.findOne({ username });
        
        if (adminUser && await bcrypt.compare(password, adminUser.password)) {
            const token = generateToken();
            ADMIN_TOKENS.set(token, { createdAt: Date.now() });
            
            // Return success with token
            return res.json({ success: true, token });
        } else {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Update admin route to serve the static HTML file
app.get('/admin', async (req, res) => {
    const token = req.query.token;
    
    if (!token || !validateAdminToken(token)) {
        return res.redirect('/admin-login.html');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Admin logout (clears token)
app.get('/admin-logout', (req, res) => {
    const token = req.query.token;
    
    if (token) {
        ADMIN_TOKENS.delete(token);
    }
    
    res.redirect('/admin-login.html');
});

// Cleanup expired tokens - run every hour
setInterval(() => {
    const now = Date.now();
    const tokenExpiry = TOKEN_EXPIRY_HOURS * 60 * 60 * 1000; // Convert hours to milliseconds
    
    for (const [token, data] of ADMIN_TOKENS.entries()) {
        if (now - data.createdAt > tokenExpiry) {
            ADMIN_TOKENS.delete(token);
        }
    }
}, 60 * 60 * 1000); // Run every hour

// Express Web Server
app.listen(PORT, () => console.log(`Web server running on port ${PORT}`));

// Catch Uncaught Errors
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

// Generate random verification code
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generate API key
function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Middleware to validate API key
async function validateApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({ error: 'API key is required' });
    }
    
    try {
        const apiKeyDoc = await apiKeysCollection.findOne({ key: apiKey });
        
        if (!apiKeyDoc) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        if (apiKeyDoc.disabled) {
            return res.status(403).json({ error: 'API key is disabled' });
        }
        
        // Update usage count
        await apiKeysCollection.updateOne(
            { key: apiKey },
            { 
                $inc: { usageCount: 1 },
                $set: { lastUsed: new Date() }
            }
        );
        
        req.apiKey = apiKeyDoc;
        next();
    } catch (err) {
        console.error('Error validating API key:', err);
        res.status(500).json({ error: 'Server error' });
    }
}

// API - Register and get verification code
app.post('/api/register', async (req, res) => {
    const { phoneNumber, telegramId } = req.body;
    
    if (!phoneNumber) {
        return res.status(400).json({ error: 'Phone number is required' });
    }
    
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    if (!normalizedPhone) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }
    
    try {
        // Check if phone is already registered
        const existingUser = await apiKeysCollection.findOne({ phoneNumber: normalizedPhone });
        if (existingUser && existingUser.verified) {
            return res.status(400).json({ error: 'Phone number already registered', apiKey: existingUser.key });
        }
        
        // Generate verification code
        const code = generateVerificationCode();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1); // Code expires in 1 hour
        
        // Save the verification code
        await verificationCodesCollection.updateOne(
            { phoneNumber: normalizedPhone },
            { 
                $set: { 
                    code,
                    telegramId,
                    expiresAt
                }
            },
            { upsert: true }
        );
        
        // If Telegram ID is provided, try to send the code via Telegram
        if (telegramId) {
            try {
                const user = await usersCollection.findOne({ userId: telegramId });
                if (user && user.chatId) {
                    bot.sendMessage(
                        user.chatId,
                        `✅ Your API verification code is: *${code}*\n\nThis code will expire in 1 hour.`,
                        { parse_mode: 'Markdown' }
                    );
                }
            } catch (telegramErr) {
                console.error('Error sending verification via Telegram:', telegramErr);
                // Continue with the API response even if Telegram message fails
            }
        }
        
        res.json({ 
            message: 'Verification code generated',
            code: code, // Include code in response since we're not using WhatsApp
            expires: expiresAt
        });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// API - Verify phone and issue API key
app.post('/api/verify', async (req, res) => {
    const { phoneNumber, code } = req.body;
    
    if (!phoneNumber || !code) {
        return res.status(400).json({ error: 'Phone number and verification code are required' });
    }
    
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    if (!normalizedPhone) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }
    
    try {
        // Find verification code
        const verificationRecord = await verificationCodesCollection.findOne({ 
            phoneNumber: normalizedPhone, 
            code 
        });
        
        if (!verificationRecord) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        if (new Date() > new Date(verificationRecord.expiresAt)) {
            return res.status(400).json({ error: 'Verification code has expired' });
        }
        
        // Generate API key
        const apiKey = generateApiKey();
        
        // Store API key
        await apiKeysCollection.updateOne(
            { phoneNumber: normalizedPhone },
            { 
                $set: { 
                    key: apiKey,
                    telegramId: verificationRecord.telegramId,
                    verified: true,
                    createdAt: new Date(),
                    lastUsed: new Date(),
                    usageCount: 0,
                    disabled: false
                }
            },
            { upsert: true }
        );
        
        // Delete verification code
        await verificationCodesCollection.deleteOne({ phoneNumber: normalizedPhone });
        
        res.json({ 
            message: 'Phone verified successfully',
            apiKey
        });
    } catch (err) {
        console.error('Error during verification:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// API - Check phone number with API key
app.post('/api/check', validateApiKey, async (req, res) => {
    const { numbers } = req.body;
    
    if (!numbers || !Array.isArray(numbers) || numbers.length === 0) {
        return res.status(400).json({ error: 'Please provide an array of phone numbers' });
    }
    
    if (numbers.length > 10) {
        return res.status(400).json({ error: 'Maximum 10 numbers per request' });
    }
    
    try {
        // Normalize phone numbers
        const validNumbers = numbers.map(normalizePhoneNumber).filter(Boolean);
        
        if (validNumbers.length === 0) {
            return res.status(400).json({ error: 'No valid US/Canada phone numbers provided' });
        }
        
        // Check numbers on WhatsApp
        const results = await checkNumbersOnWhatsApp(validNumbers);
        
        // Log usage
        const timestamp = new Date().toISOString();
        const records = validNumbers.map((number, i) => ({
            userId: req.apiKey.telegramId || 'api',
            username: req.apiKey.phoneNumber,
            timestamp,
            number,
            result: results[i],
            apiKey: req.apiKey.key
        }));
        
        await usageCollection.insertMany(records);
        
        // Format response
        const response = validNumbers.map((number, i) => {
            const isRegistered = results[i].includes('✅');
            return {
                number,
                registered: isRegistered,
                status: isRegistered ? 'registered' : 'not_registered'
            };
        });
        
        res.json({
            success: true,
            results: response
        });
    } catch (err) {
        console.error('Error checking numbers:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// API - Get API key usage stats
app.get('/api/stats', validateApiKey, async (req, res) => {
    try {
        const apiKey = req.apiKey.key;
        
        // Get usage stats
        const totalChecks = await usageCollection.countDocuments({ apiKey });
        const registeredCount = await usageCollection.countDocuments({ 
            apiKey, 
            result: /✅/ 
        });
        
        // Get last 10 checks
        const recentChecks = await usageCollection.find({ apiKey })
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();
        
        // Format recent checks
        const recent = recentChecks.map(check => ({
            number: check.number,
            result: check.result.includes('✅') ? 'registered' : 'not_registered',
            timestamp: check.timestamp
        }));
        
        res.json({
            success: true,
            stats: {
                totalChecks,
                registeredCount,
                notRegisteredCount: totalChecks - registeredCount,
                registeredPercentage: totalChecks ? ((registeredCount / totalChecks) * 100).toFixed(2) : 0,
                recentChecks: recent
            }
        });
    } catch (err) {
        console.error('Error fetching API key stats:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - List all API keys
app.get('/admin/api-keys', tokenAuth, async (req, res) => {
    try {
        const apiKeys = await apiKeysCollection.find().toArray();
        
        // Format API keys for display
        const formattedKeys = apiKeys.map(key => ({
            phoneNumber: key.phoneNumber,
            key: key.key,
            telegramId: key.telegramId,
            createdAt: key.createdAt,
            lastUsed: key.lastUsed,
            usageCount: key.usageCount,
            disabled: key.disabled
        }));
        
        res.json(formattedKeys);
    } catch (err) {
        console.error('Error fetching API keys:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Enable/disable API key
app.post('/admin/toggle-api-key', tokenAuth, async (req, res) => {
    const { key, disabled } = req.body;
    
    if (!key) {
        return res.status(400).json({ error: 'API key is required' });
    }
    
    try {
        const result = await apiKeysCollection.updateOne(
            { key },
            { $set: { disabled: !!disabled } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'API key not found' });
        }
        
        res.json({ 
            success: true, 
            message: `API key ${disabled ? 'disabled' : 'enabled'} successfully` 
        });
    } catch (err) {
        console.error('Error toggling API key:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Dashboard statistics
app.get('/admin/stats', tokenAuth, async (req, res) => {
    try {
        // Get today's date at midnight
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Total users count
        const totalUsers = await usersCollection.countDocuments();
        
        // Total checks count
        const totalChecks = await usageCollection.countDocuments();
        
        // Today's active users
        const todayActiveUsers = await usersCollection.countDocuments({
            lastActive: { $gte: today.toISOString() }
        });
        
        // Today's checks count
        const todayChecks = await usageCollection.countDocuments({
            timestamp: { $gte: today.toISOString() }
        });
        
        // API key users count
        const apikeyUsers = await apiKeysCollection.countDocuments();
        
        // API key usage count
        const apiKeys = await apiKeysCollection.find().toArray();
        const apikeyUsage = apiKeys.reduce((total, key) => total + (key.usageCount || 0), 0);
        
        res.json({
            totalUsers,
            totalChecks,
            todayActiveUsers,
            todayChecks,
            apikeyUsers,
            apikeyUsage
        });
    } catch (err) {
        console.error('Error fetching dashboard stats:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Recent checks
app.get('/admin/recent-checks', tokenAuth, async (req, res) => {
    try {
        const recentChecks = await usageCollection.find()
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();
            
        res.json(recentChecks);
    } catch (err) {
        console.error('Error fetching recent checks:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Check history with pagination
app.get('/admin/check-history', tokenAuth, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    try {
        const total = await usageCollection.countDocuments();
        
        const checks = await usageCollection.find()
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
            
        res.json({
            checks,
            total,
            page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error('Error fetching check history:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - WhatsApp status
app.get('/admin/whatsapp-status', tokenAuth, async (req, res) => {
    try {
        // Simple binary status: either connected or not
        const isConnected = client && client.info;
        
        // Return simple status
        res.json({ 
            state: isConnected ? 'CONNECTED' : 'DISCONNECTED',
            message: isConnected ? 'WhatsApp connected' : 'WhatsApp disconnected',
            qr: global.latestQR // Include QR code if available
        });
    } catch (err) {
        console.error('Error checking WhatsApp status:', err);
        res.status(200).json({ 
            state: 'DISCONNECTED',
            message: 'WhatsApp disconnected'
        });
    }
});

// Token validation endpoint for admin login page
app.get('/admin/validate-token', (req, res) => {
    const token = req.query.token;
    
    if (!token || !validateAdminToken(token)) {
        return res.status(401).send('Invalid token');
    }
    
    res.status(200).send('Valid token');
});

// Admin - Get admin account info
app.get('/admin/account-info', tokenAuth, async (req, res) => {
    try {
        const adminUser = await adminCollection.findOne({});
        
        if (!adminUser) {
            return res.status(404).json({ error: 'Admin user not found' });
        }
        
        res.json({
            username: adminUser.username
        });
    } catch (err) {
        console.error('Error fetching admin info:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Update admin credentials
app.post('/admin/update-credentials', tokenAuth, async (req, res) => {
    const { currentPassword, newUsername, newPassword } = req.body;
    
    if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required' });
    }
    
    if (!newUsername) {
        return res.status(400).json({ error: 'Username cannot be empty' });
    }
    
    try {
        const adminUser = await adminCollection.findOne({});
        
        if (!adminUser) {
            return res.status(404).json({ error: 'Admin user not found' });
        }
        
        const passwordMatch = await bcrypt.compare(currentPassword, adminUser.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        const updateData = { username: newUsername };
        
        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            updateData.password = hashedPassword;
        }
        
        await adminCollection.updateOne({}, { $set: updateData });
        
        res.json({ 
            success: true, 
            message: 'Admin credentials updated successfully' 
        });
    } catch (err) {
        console.error('Error updating admin credentials:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// API endpoint for sending broadcast messages
app.post('/broadcast', tokenAuth, async (req, res) => {
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message is required' });
    }
    
    try {
        // Get all active users
        const users = await usersCollection.find({}).toArray();
        let sentCount = 0;
        
        // Send message to each user
        for (const user of users) {
            if (user.chatId) {
                try {
                    await bot.sendMessage(user.chatId, message);
                    sentCount++;
                } catch (err) {
                    console.error(`Failed to send message to ${user.chatId}:`, err);
                }
            }
        }
        
        res.send(`Broadcast sent to ${sentCount} users.`);
    } catch (err) {
        console.error('Error sending broadcast:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 404 Error Handling - This must be after all other routes
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});