import dotenv from 'dotenv';
import app, { corsOptions } from './app';
dotenv.config();
import { ApolloServer } from 'apollo-server-express';
import { ApolloServerPluginDrainHttpServer } from 'apollo-server-core';
import config from 'config';
import http from 'http';
import typeDefs from './schemas/index';
import connectDB from './utils/connectDB';
import { Mutation, Query } from './resolvers/index';
import DateTime from './resolvers/datetime';
import getAuthUser from './middleware/authUser';

async function startNodeServer() {
  const httpServer = http.createServer(app);

  const resolvers = {
    DateTime,
    Query,
    Mutation,
  };

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    csrfPrevention: true,
    plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
    context: ({ req, res }) => ({ req, res, getAuthUser }),
  });

  // Start the server
  await server.start();

  // Apply middleware
  server.applyMiddleware({ app, cors: corsOptions });

  // Listen on port
  const port = config.get<number>('PORT') || 4000;
  await new Promise<void>((resolve) => httpServer.listen({ port }, resolve));
  console.log(
    `🚀 Server ready at http://localhost:${port}${server.graphqlPath}`
  );

  // CONNECT MONGODB
  connectDB();

  process.on('unhandledRejection', (err: any) => {
    console.log('UNHANDLED REJECTION 🔥🔥 Shutting down...');
    console.log(err);
    console.error('Error🔥', err.message);

    httpServer.close(async () => {
      process.exit(1);
    });
  });
}

startNodeServer();
