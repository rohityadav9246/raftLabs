/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT 
 *   schemas:
 *     GetMessageResponse:
 *       type: object
 *       properties:
 *         message:
 *           type: string
 * 
 *     CreateUserRequest:
 *       type: object
 *       properties:
 *         name:
 *           type: string
 *         email:
 *           type: string
 *         password:
 *           type: string
 *       required:
 *         - name
 *         - email
 *         - password
 *     CreateUserResponse:
 *       type: object
 *       properties:
 *         message:
 *           type: string
 *           description: confirms creation of new user 
 *     LoginRequest:
 *       type: object
 *       properties:
 *         email:
 *           type: string
 *         password:
 *           type: string
 *       required:
 *         - email
 *         - password
 *     LoginResponse:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *           description: access token user can use to access authorised apis
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         error:
 *           type: string
 *           description: provides more detail about error 
 * /:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Message from server
 *     description: Get a message from server.
 *     responses:
 *       '200':
 *         description: Successful response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GetMessageResponse'
 *             example: { message: "Hello, Raft Labs here!" }
 *       '401':
 *         description: Unauthorised - due to invalid token provided or due to no token provided
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example: { error: "Unauthorized: Invalid token" }  
 * /create-user:
 *   post:
 *     summary: Create a new user
 *     description: Create a new user with the provided information.
 *     requestBody:
 *       description: User data to create a new user.
 *       required: true
 *       content:
 *         application/json:
 *           example: { "name": "Jon Doe", "email": "jondoe@abcmail.com", "password": "JonDoe"}
 *           schema:
 *             $ref: '#/components/schemas/CreateUserRequest'
 *     responses:
 *       '201':
 *         description: User created successfully
 *         content:
 *           application/json:
 *             example: { "message": "User created successfully" }
 *             schema:
 *               $ref: '#/components/schemas/CreateUserResponse'
 *       '400':
 *         description: Bad request, invalid data provided
 *         content:
 *           application/json:
 *             example: { "error": "\"email\" must be a valid email" }
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example: { "error": "An error occurred while creating the user" }
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 * /login:
 *   post:
 *     summary: User login
 *     description: Authenticate a user and generate an access token.
 *     requestBody:
 *       description: User login data.
 *       required: true
 *       content:
 *         application/json:
 *           example: {"email": "jondoe@abcmail.com", "password": "JonDoe"}
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       '200':
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             example: {"token": "some JWT token"}
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       '401':
 *         description: Unauthorized, invalid email or password
 *         content:
 *           application/json:
 *             example: { "error": "Invalid email or password" }
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       '400':
 *         description: Bad request, invalid data provided
 *         content:
 *           application/json:
 *             example: {"error": "\"password\" length must be at least 6 characters long"}
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             example: { "error": "An error occurred during authentication"}
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 * 
 * /chatting-app:
 *   get:
 *     summary: get real time chat page
 *     description: Returns a HTML file which enables user to chat suing socket.io.
 *     responses:
 *       '200':
 *         description: HTML content
 *         content:
 *           text/html:
 *             example: <HTML> Some Code Inside </HTML>
 *             schema:
 *               type: string
 * 
 */


import express, { Express, Request, Response } from 'express';
import mongoose from 'mongoose';
import * as bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import Joi from 'joi';
import NodeCache from 'node-cache';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import http from 'http';
import path from 'path';
import {Server, Socket} from 'socket.io';
import swaggerjsdoc from 'swagger-jsdoc';
import swaggerui from 'swagger-ui-express';

dotenv.config();

async function startServer() {
  
  const app: Express = express();
  const httpServer = http.createServer(app);
  const cache = new NodeCache();
  const io = new Server(httpServer);
  
  const spacs = swaggerjsdoc({
    definition: {
      openapi: "3.0.0",
      info: {
        title: "RaftLabs Assignment Docs",
        version: "1.0",
        description: "This is a simple server made as an assignment for RaftLabs with Express and MongoDB.",
        contact: {
          name: "Rohit Yadav",
          email: "rohit.yadav9246@gmail.com",
        },
      },
      servers: [
        {
          url: "http://localhost:3000/",
        },
      ],
    },
    apis: ["./dist/*.js"],
  });

  app.use("/api-docs", swaggerui.serve, swaggerui.setup(spacs) );

  io.use(async (socket, next)=>{
    try{
      const token = socket.handshake.auth.token;
      await jwt.verify(token, `${process.env.SECRET_KEY}`);  
      next();
    }catch(error){
      next(new Error("Invalid token provided"));
    }
  });

  io.on('connection', (socket)=>{
    socket.join("raftlabs updates");
    io.to("raftlabs updates").emit("raftlabs updates", `${socket.id} joined raftlabs updates`);
    socket.on('user-message', (message)=>{
      io.emit("message", message);
    });
  });
  

  const server = new ApolloServer({
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
        home: async (_, {token}) => {
          try{
            // @ts-ignore
            const user = await jwt.verify(token, `${process.env.SECRET_KEY}`);
            return {"message": messageForHome()};
          }catch(error){
            console.error(error);
            throw new Error('Invalid token');
          }
        }
      },
      Mutation: {
        createUser: async(_, {name, email, password}) => {
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
          } catch (error: any) {
            console.error('Error creating user:', error);
            if(error.message === 'User with this email already exists'){
              throw new Error(error.message);
            }
            throw new Error('An error occurred while creating the user' );
          }
        },
        login: async(_, {email, password}) => {
          try {
            if (cache.has(email)) {
              const cachedPassword = cache.get(email);
              // @ts-ignore
              const isPasswordValid = await bcrypt.compare(password, cachedPassword);
              if (!isPasswordValid) {
                throw new Error('Invalid email or password');
              }
      
              cache.set(email, cachedPassword, 2 * 24 * 60 * 60);
              const token = jwt.sign({ email: email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
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
            const token = jwt.sign({ email: user.email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
            return { token };
          } catch (error: any) {
            console.error('Error authenticating user:', error);
            if(error.message === 'Invalid email or password')
              throw new Error(error.message);

            throw new Error('An error occurred during authentication');
          }
        }
      }
    },
  });

  app.use(express.json());
  app.use(cors());

  await server.start();

  app.use("/graphql", expressMiddleware(server));


  mongoose.connect('mongodb://localhost/raft_labs')
    .then(() => console.log('Connected to MongoDB...'))
    .catch(error => console.error('Could not connect to MongoDB ... ', error));

  const userSchema = new mongoose.Schema({
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

  const User = mongoose.model('User', userSchema);

  interface CreateUserRequest extends Request {
    body: CreateUserRequestBody;
  }

  interface CreateUserRequestBody {
    name: string;
    email: string;
    password: string;
  }

  interface CreateUserResponse extends Response {
    status: (code: number) => any;
    json: (data:
      {
        error: string;
      } |
      {
        message: string;
      }
    ) => any;
  }

  const createUserSchema = Joi.object<CreateUserRequestBody>({
    name: Joi.string().min(2).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
  });

  app.post('/create-user', async (req: CreateUserRequest, res: CreateUserResponse): Promise<CreateUserResponse> => {
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
    } catch (error) {
      console.error('Error creating user:', error);
      return res.status(500).json({ error: 'An error occurred while creating the user' });
    }
  });



  interface LoginRequest extends Request {
    body: LoginUserRequestBody;
  }

  interface LoginUserRequestBody extends Request {
    email: string;
    password: string;
  }

  interface LoginResponse extends Response {
    status: (code: number) => any;
    json: (data:
      {
        error: string;
      } |
      {
        token: string
      }
    ) => any;
  }

  const loginUserSchema = Joi.object<LoginUserRequestBody>({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
  });

  app.post('/login', async (req: LoginRequest, res: LoginResponse): Promise<LoginResponse> => {
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
        const token = jwt.sign({ email: email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
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
      const token = jwt.sign({ email: user.email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
      return res.status(200).json({ token });
    } catch (error) {
      console.error('Error authenticating user:', error);
      return res.status(500).json({ error: 'An error occurred during authentication' });
    }
  });


  function verifyToken(req: any, res: any, next: any) {
    let token = req.headers.authorization
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    token = token.substring(7);

    jwt.verify(token, `${process.env.SECRET_KEY}`, (err: any, decoded: any) => {
      if (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
      }
      req.user = decoded;
      next();
    });
  };


  function messageForHome(){
    return 'Hello, Raft Labs here!';
  }

  app.get('/', verifyToken, (req: Request, res: Response) => {
    return res.json({message: messageForHome()});
  });

  app.use(express.static(path.resolve("./public")));
  app.get('/chatting-app', (req, res)=>{
    return res.sendFile(path.resolve('./public/index.html'));
  });

  const PORT = process.env.PORT || 3000;
  httpServer.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });

}

startServer();