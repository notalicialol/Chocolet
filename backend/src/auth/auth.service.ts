import { BadRequestException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { MongoClient } from "mongodb";
import * as bcrypt from "bcrypt";
import * as crypto from "crypto";

import { IpAddress, User } from "../../../types/src/index";

const uri = "mongodb://127.0.0.1:27017/chocolet?authSource=chocolet";
const client = new MongoClient(uri);

@Injectable()
export class AuthService {
    constructor(private readonly jwtService: JwtService) {}

    async connectToDatabase() {
        await client.connect();
        return client.db("chocolet");
    }

    async register(username: string, password: string, ip: string) : Promise<string | null> {
        const db = await this.connectToDatabase();

        if (await db.collection("users").findOne({ username: { "$regex": `^${username}$`, "$options": "i" } })) {
            throw new BadRequestException("A user with that username already exists. Please try again with a different username.");
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            
            const newUser = new User({
                username,
                password: hashedPassword
            });

            await db.collection("users").insertOne(newUser);

            return null;
        }
    }

    public hashIp(ip : string) {
        const hash = crypto.createHash("sha256");
        hash.update(ip);
        return hash.digest("hex");
    }
}
