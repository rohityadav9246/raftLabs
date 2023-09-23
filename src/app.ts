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
dotenv.config();

async function startServer() {
  
  const app: Express = express();
  const cache = new NodeCache();
  
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

  function createUser(name: String, email: String, password: String): void{

  }

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
    const token = req.headers.authorization.substring(7);

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, `${process.env.SECRET_KEY}`, (err: any, decoded: any) => {
      if (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
      }
      req.user = decoded;
      next();
    });
  };


  function messageForHome(){
    return 'Hello, Raft Labs!';
  }

  app.get('/', verifyToken, (req: Request, res: Response) => {
    return res.json({message: messageForHome()});
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });

}

startServer();