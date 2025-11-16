import { createServer } from "http";
import { Server } from "socket.io";
import { v4 as uuidv4 } from 'uuid';
import express from 'express';
import cors from 'cors';
import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import 'dotenv/config'; // Loads the .env file

// --- Constants ---
const PORT = process.env.PORT || 3000;
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;

if (!GOOGLE_WEB_CLIENT_ID || !JWT_SECRET) {
    console.error("Missing GOOGLE_WEB_CLIENT_ID or JWT_SECRET in .env file");
    process.exit(1);
}

// --- In-Memory "Database" (for demonstration) ---
// In a real app, you would use a proper database (like PostgreSQL or MongoDB)
const users = new Map(); // Stores user profile by email
const refreshTokens = new Map(); // Stores active refresh tokens
const devices = new Map(); // Stores device info

// --- Google Auth Client ---
const googleClient = new OAuth2Client(GOOGLE_WEB_CLIENT_ID);

// --- Initialize Express & HTTP Server ---
const app = express();
app.use(cors()); // Enable CORS for API requests
app.use(express.json()); // Enable parsing JSON bodies for POST requests

// This httpServer will now handle BOTH Express API routes and Socket.IO
const httpServer = createServer(app);

// ---------------------------------
// --- THIS IS THE NEW CODE YOU ASKED FOR ---
// ---------------------------------
/**
 * GET /
 * Health check route for Render to confirm the server is running.
 */
app.get('/', (req, res) => {
    res.status(200).json({ message: "Zync Server is running!" });
});
// ---------------------------------
// --- END OF NEW CODE ---
// ---------------------------------


// --- API Endpoints (for your Android App) ---

/**
 * POST /auth/verify
 * Handles the Google ID Token from the Android app.
 * Verifies the token, finds or creates a user, and returns
 * your app's own auth tokens.
 */
app.post('/auth/verify', async (req, res) => {
    try {
        const { id_token } = req.body;

        if (!id_token) {
            return res.status(400).json({ error: "Missing id_token" });
        }

        // 1. Verify the Google ID Token
        const ticket = await googleClient.verifyIdToken({
            idToken: id_token,
            audience: GOOGLE_WEB_CLIENT_ID, // Ensures the token is for your app
        });

        const payload = ticket.getPayload();
        const { email, name, picture, sub: googleId } = payload;

        // 2. Find or create the user in your database
        let user = users.get(email);
        if (!user) {
            user = {
                id: uuidv4(),
                googleId,
                email,
                name,
                picture
            };
            users.set(email, user);
            console.log(`[Auth] New user created: ${email}`);
        } else {
            console.log(`[Auth] User logged in: ${email}`);
        }

        // 3. Generate your app's own tokens
        const deviceId = uuidv4();
        const accessToken = jwt.sign({ userId: user.id, deviceId }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: user.id, deviceId }, JWT_SECRET, { expiresIn: '7d' });

        // Store the refresh token (in a real DB, you'd hash this)
        refreshTokens.set(refreshToken, { userId: user.id, deviceId });
        devices.set(deviceId, { userId: user.id, type: "android" });

        // 4. Send the response your Android app expects
        res.json({
            access_token: accessToken,
            refresh_token: refreshToken,
            device_id: deviceId,
            user_email: user.email,
            user_name: user.name,
            user_photo_url: user.picture
        });

    } catch (error) {
        console.error("[Auth Error] /auth/verify failed:", error.message);
        res.status(401).json({ error: "Invalid or expired token" });
    }
});

/**
 * POST /token/refresh
 * This endpoint validates the refresh_token and issues a new access_token.
 */
app.post('/token/refresh', (req, res) => {
    const { refresh_token } = req.body;

    if (!refresh_token || !refreshTokens.has(refresh_token)) {
        return res.status(401).json({ error: "Invalid refresh token" });
    }
    
    const tokenData = refreshTokens.get(refresh_token);
    
    // Issue a new access token
    const accessToken = jwt.sign({ userId: tokenData.userId, deviceId: tokenData.deviceId }, JWT_SECRET, { expiresIn: '15m' });
    
    console.log(`[Auth] Refreshed token for user: ${tokenData.userId}`);
    res.json({
        access_token: accessToken
    });
});

/**
 * POST /devices/unlink
 * This endpoint removes a device's refresh token.
 */
app.post('/devices/unlink', (req, res) => {
    const { device_id } = req.body;
    
    if (device_id) {
        devices.delete(device_id);
        // You would also find and delete any refresh tokens associated with this deviceId
        console.log(`[Auth] Unlinked device: ${device_id}`);
    }
    res.status(200).json({ message: "Device unlinked" });
});


// --- Socket.IO Server (Your existing logic) ---
const io = new Server(httpServer, {
    cors: {
        origin: "*", // Allow connections from any origin
    }
});

const pendingPairs = new Map();

io.on('connection', (socket) => {
    console.log(`[Connect] Client connected: ${socket.id}`);
    const pairingToken = uuidv4();
    pendingPairs.set(pairingToken, socket.id);
    socket.emit('pairing-token', pairingToken);
    console.log(`[Token] Sent token ${pairingToken} to ${socket.id}`);

    socket.on('pair-device', (token) => {
        console.log(`[Pairing] Received request with token: ${token}`);
        if (pendingPairs.has(token)) {
            const desktopSocketId = pendingPairs.get(token);
            const desktopSocket = io.sockets.sockets.get(desktopSocketId);
            if (desktopSocket) {
                const roomName = `room-${token}`;
                desktopSocket.join(roomName);
                socket.join(roomName);
                io.to(roomName).emit('pairing-successful');
                console.log(`[Success] Paired ${socket.id} and ${desktopSocketId} in room: ${roomName}`);
                pendingPairs.delete(token);
            }
        }
    });

    socket.on('new_notification', (data) => {
        const room = Array.from(socket.rooms)[1];
        if (room) {
            socket.to(room).emit('receive_notification', data);
            console.log(`[Notification] Relayed notification to room: ${room}`);
        }
    });

    socket.on('disconnect', () => {
        console.log(`[Disconnect] Client disconnected: ${socket.id}`);
    });
});


// --- Start the Server ---
httpServer.listen(PORT, () => {
    console.log(`🚀 Server is listening on port ${PORT}`);
    console.log(`Server link: http://localhost:${PORT}`);
});
