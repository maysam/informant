# Telegram Login Website

A Flask web application that implements Telegram Login Widget with user notifications.

## Features

- Telegram Login Widget integration
- Admin notifications for user logins and logouts
- Secure authentication verification
- User session management
- Beautiful and responsive UI

## Prerequisites

- Python 3.7+
- A Telegram Bot (for login widget and notifications)
- ngrok or telebit (for local development)

## Setup

1. **Create a Telegram Bot**:
   - Talk to [@BotFather](https://t.me/botfather) on Telegram
   - Use the `/newbot` command to create a new bot
   - Save the bot token and username
   - Enable the bot's domain using `/setdomain` command with your website URL

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables**:
   Create a `.env` file in the project root with the following variables:
   ```bash
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   TELEGRAM_BOT_USERNAME=your_bot_username_without_@
   WEBSITE_URL=your_public_url
   ADMIN_USERNAME=your_telegram_username
   ADMIN_CHAT_ID=your_telegram_chat_id
   ```

4. **Get Your Chat ID**:
   - Send a message to your bot
   - Access `https://api.telegram.org/bot<YourBOTToken>/getUpdates`
   - Look for the `"id"` field in the response
   - Add this ID to your `.env` file as `ADMIN_CHAT_ID`

## Running Locally

1. **Set Up a Public URL**:
   
   Using telebit:
   ```bash
   # Install telebit
   curl https://get.telebit.io/ | bash

   # Start telebit
   export XDG_RUNTIME_DIR=/run/user/$UID
   systemctl --user restart telebit

   # Forward port 5000
   telebit http 5000
   ```

   OR using ngrok:
   ```bash
   # Install ngrok
   # Start ngrok
   ngrok http 5000
   ```

2. **Update Bot Domain**:
   - Copy your public URL (from telebit or ngrok)
   - Update the `WEBSITE_URL` in your `.env` file
   - Tell @BotFather to set this domain for your bot using `/setdomain`

3. **Start the Application**:
   ```bash
   python app.py
   ```

## Testing

Run the test suite:
```bash
python -m pytest
```

The tests cover:
- Basic page loading
- Login functionality
- Logout functionality
- Telegram data verification
- Error handling
- Environment variable configuration

## Security

- All Telegram login data is verified using HMAC-SHA256
- Environment variables are used for sensitive data
- Session management is implemented securely
- Bot token and admin chat ID are protected

## Troubleshooting

1. **Login Widget Not Showing**:
   - Ensure `TELEGRAM_BOT_USERNAME` is set correctly (without @)
   - Verify the domain is set in BotFather
   - Check browser console for errors

2. **Notifications Not Working**:
   - Verify `ADMIN_CHAT_ID` is set correctly
   - Ensure the bot token is valid
   - Check if you've sent at least one message to the bot

3. **Tests Failing**:
   - Make sure all dependencies are installed
   - Verify environment variables are set
   - Check if pytest is installed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
