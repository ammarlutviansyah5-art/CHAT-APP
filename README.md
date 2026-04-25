# ChatApp Fullstack Demo

Frontend is based on the uploaded `index_revised_fixed_v5.html` file. Backend is a lightweight Python server using SQLite.

## Run

```bash
cd backend
python3 server.py
```

Open `http://localhost:8000/`

## Included
- Email/password auth with OTP sign up, sign in, and reset password
- SQLite database
- Real-time SSE updates for chat/presence/status/notifications
- Profile persistence
- Block user support
- Media uploads saved to `backend/uploads`

## Notes
- If SMTP is not configured, OTP codes are written to `backend/data/dev_otp_log.txt`.
- The backend seeds demo accounts for quick testing.
- Calls are scaffolded through backend endpoints; WebRTC media relay is not fully implemented in this package.
