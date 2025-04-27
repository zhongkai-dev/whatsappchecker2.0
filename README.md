# WhatsApp Checker 2.0

WhatsApp Checker is a service that allows users to verify if phone numbers are registered on WhatsApp before contacting them. It's perfect for businesses, marketing, and personal use.

🌐 **Live Demo:** [https://whatsappchecker2.up.railway.app/](https://whatsappchecker2.up.railway.app/)

## Features

- **Telegram Bot Integration**: Check phone numbers directly through Telegram by messaging [@wschecker2bot](https://t.me/wschecker2bot)
- **Accurate Results**: Uses WhatsApp's API to provide the most up-to-date information
- **Developer API**: Integrate WhatsApp number verification into your own applications
- **User-Friendly Interface**: Simple web interface for interacting with the service

## Getting Started

### Prerequisites

- Node.js (14.x or higher)
- MongoDB database
- Telegram Bot token (from BotFather)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/zhongkai-dev/whatsappchecker2.0.git
   cd whatsappchecker2.0
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   # Server configuration
   PORT=3000

   # Telegram Bot configuration
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   CHAT_ID_FOR_QR_CODE=your_chat_id

   # MongoDB configuration
   MONGO_URI=your_mongodb_connection_string

   # Admin credentials
   ADMIN_USERNAME=your_admin_username
   ADMIN_PASSWORD=your_admin_password

   # Session configuration
   SESSION_SECRET=your_session_secret
   TOKEN_EXPIRY_HOURS=24
   ```

4. Start the application:
   ```
   node app.js
   ```

The application will be available at `http://localhost:3000`

## Usage

### Telegram Bot

1. Start a chat with [@wschecker2bot](https://t.me/wschecker2bot) on Telegram
2. Send one or more phone numbers with country code (e.g., +12345678901)
3. Receive instant verification results

### API Usage

1. Obtain an API key by messaging the Telegram bot with the command `/getapi`
2. Make API requests as follows:

```javascript
const response = await fetch('https://whatsappchecker2.up.railway.app/api/check', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'x-api-key': 'YOUR_API_KEY'
    },
    body: JSON.stringify({
        numbers: ['+1234567890', '+9876543210']
    })
});

const result = await response.json();
console.log(result);
```

## Admin Dashboard

Access the admin dashboard at `/admin-login.html` using the credentials set in your `.env` file. The dashboard provides:

- Usage statistics
- User management
- WhatsApp connection status
- API key management

## Deployment

This application can be deployed to platforms like Railway, Heroku, or any other Node.js hosting service.

For Railway deployment, simply connect this GitHub repository to Railway and set the required environment variables.

## Contact

Developer: [ZhongKai](https://t.me/ZhongKai_KL)

## License

This project is licensed under the MIT License - see the LICENSE file for details. 