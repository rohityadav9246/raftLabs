"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const mongoose_1 = __importDefault(require("mongoose"));
const bcrypt = __importStar(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
const joi_1 = __importDefault(require("joi"));
const node_cache_1 = __importDefault(require("node-cache"));
const server_1 = require("@apollo/server");
const express4_1 = require("@apollo/server/express4");
const http_1 = __importDefault(require("http"));
const path_1 = __importDefault(require("path"));
const socket_io_1 = require("socket.io");
dotenv_1.default.config();
async function startServer() {
    const app = (0, express_1.default)();
    const httpServer = http_1.default.createServer(app);
    const cache = new node_cache_1.default();
    const io = new socket_io_1.Server(httpServer);
    io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth.token;
            await jsonwebtoken_1.default.verify(token, `${process.env.SECRET_KEY}`);
            next();
        }
        catch (error) {
            next(new Error("Invalid token provided"));
        }
    });
    io.on('connection', (socket) => {
        socket.join("raftlabs updates");
        io.to("raftlabs updates").emit("raftlabs updates", `${socket.id} joined raftlabs updates`);
        socket.on('user-message', (message) => {
            io.emit("message", message);
        });
    });
    const server = new server_1.ApolloServer({
        typeDefs: `
      type GeneralResponse {
        message: String
      }

      type LoginResponse {
        token: String 
      }

      type Query {
        home(token: String!): GeneralResponse
      }
      type Mutation{
        createUser(name: String!, email: String!, password: String! ): GeneralResponse
        login(email: String!, password: String!): LoginResponse
      }
    `,
        resolvers: {
            Query: {
                home: async (_, { token }) => {
                    try {
                        // @ts-ignore
                        const user = await jsonwebtoken_1.default.verify(token, `${process.env.SECRET_KEY}`);
                        return { "message": messageForHome() };
                    }
                    catch (error) {
                        console.error(error);
                        throw new Error('Invalid token');
                    }
                }
            },
            Mutation: {
                createUser: async (_, { name, email, password }) => {
                    try {
                        const existingUser = await User.findOne({ email });
                        if (existingUser) {
                            throw new Error('User with this email already exists');
                        }
                        // @ts-ignore
                        const hashedPassword = await bcrypt.hash(password, 10);
                        const newUser = new User({
                            name,
                            email,
                            password: hashedPassword,
                        });
                        await newUser.save();
                        return { message: 'User created successfully' };
                    }
                    catch (error) {
                        console.error('Error creating user:', error);
                        if (error.message === 'User with this email already exists') {
                            throw new Error(error.message);
                        }
                        throw new Error('An error occurred while creating the user');
                    }
                },
                login: async (_, { email, password }) => {
                    try {
                        if (cache.has(email)) {
                            const cachedPassword = cache.get(email);
                            // @ts-ignore
                            const isPasswordValid = await bcrypt.compare(password, cachedPassword);
                            if (!isPasswordValid) {
                                throw new Error('Invalid email or password');
                            }
                            cache.set(email, cachedPassword, 2 * 24 * 60 * 60);
                            const token = jsonwebtoken_1.default.sign({ email: email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
                            return { token };
                        }
                        const user = await User.findOne({ email });
                        if (!user) {
                            throw new Error('Invalid email or password');
                        }
                        const isPasswordValid = await bcrypt.compare(password, user.password);
                        if (!isPasswordValid) {
                            throw new Error('Invalid email or password');
                        }
                        cache.set(email, user.password, 2 * 24 * 60 * 60);
                        const token = jsonwebtoken_1.default.sign({ email: user.email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
                        return { token };
                    }
                    catch (error) {
                        console.error('Error authenticating user:', error);
                        if (error.message === 'Invalid email or password')
                            throw new Error(error.message);
                        throw new Error('An error occurred during authentication');
                    }
                }
            }
        },
    });
    app.use(express_1.default.json());
    app.use((0, cors_1.default)());
    await server.start();
    app.use("/graphql", (0, express4_1.expressMiddleware)(server));
    mongoose_1.default.connect('mongodb://localhost/raft_labs')
        .then(() => console.log('Connected to MongoDB...'))
        .catch(error => console.error('Could not connect to MongoDB ... ', error));
    const userSchema = new mongoose_1.default.Schema({
        name: {
            type: String,
            required: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },
    });
    const User = mongoose_1.default.model('User', userSchema);
    const createUserSchema = joi_1.default.object({
        name: joi_1.default.string().min(2).required(),
        email: joi_1.default.string().email().required(),
        password: joi_1.default.string().min(6).required(),
    });
    app.post('/create-user', async (req, res) => {
        try {
            const { error, value } = createUserSchema.validate(req.body);
            if (error) {
                return res.status(400).json({ error: error.message });
            }
            const { name, email, password } = req.body;
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: 'User with this email already exists' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({
                name,
                email,
                password: hashedPassword,
            });
            await newUser.save();
            return res.status(201).json({ message: 'User created successfully' });
        }
        catch (error) {
            console.error('Error creating user:', error);
            return res.status(500).json({ error: 'An error occurred while creating the user' });
        }
    });
    const loginUserSchema = joi_1.default.object({
        email: joi_1.default.string().email().required(),
        password: joi_1.default.string().min(6).required(),
    });
    app.post('/login', async (req, res) => {
        try {
            const { error, value } = loginUserSchema.validate(req.body);
            if (error) {
                return res.status(400).json({ error: error.message });
            }
            const { email, password } = req.body;
            if (cache.has(email)) {
                const cachedPassword = cache.get(email);
                // @ts-ignore
                const isPasswordValid = await bcrypt.compare(password, cachedPassword);
                if (!isPasswordValid) {
                    return res.status(401).json({ error: 'Invalid email or password' });
                }
                cache.set(email, cachedPassword, 2 * 24 * 60 * 60);
                const token = jsonwebtoken_1.default.sign({ email: email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
                return res.status(200).json({ token });
            }
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            cache.set(email, user.password, 2 * 24 * 60 * 60);
            const token = jsonwebtoken_1.default.sign({ email: user.email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
            return res.status(200).json({ token });
        }
        catch (error) {
            console.error('Error authenticating user:', error);
            return res.status(500).json({ error: 'An error occurred during authentication' });
        }
    });
    function verifyToken(req, res, next) {
        const token = req.headers.authorization.substring(7);
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }
        jsonwebtoken_1.default.verify(token, `${process.env.SECRET_KEY}`, (err, decoded) => {
            if (err) {
                return res.status(401).json({ error: 'Unauthorized: Invalid token' });
            }
            req.user = decoded;
            next();
        });
    }
    ;
    function messageForHome() {
        return 'Hello, Raft Labs!';
    }
    app.get('/', verifyToken, (req, res) => {
        return res.json({ message: messageForHome() });
    });
    app.use(express_1.default.static(path_1.default.resolve("./public")));
    app.get('/chatting-app', (req, res) => {
        return res.sendFile(path_1.default.resolve('./public/index.html'));
    });
    const PORT = process.env.PORT || 3000;
    httpServer.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}
startServer();
