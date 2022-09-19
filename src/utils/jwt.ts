import config from "config";
import jwt from "jsonwebtoken";
import errorHandler from "../controllers/error.controller";

export const signJwt = (payload: any, Key: any, options: any) => {
  const privateKey = Buffer.from(config.get<string>(Key), "base64").toString(
    "ascii"
  );
  return jwt.sign(payload, privateKey, {
    ...(options && options),
    algorithm: "RS256",
  });
};

export const verifyJwt = (token: any, Key: string) => {
  try {
    const publicKey = Buffer.from(config.get<string>(Key), "base64").toString(
      "ascii"
    );
    const decoded = jwt.verify(token, publicKey);
    return decoded;
  } catch (error) {
    errorHandler(error);
  }
};
