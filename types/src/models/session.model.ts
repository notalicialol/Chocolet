import mongoose, { Schema, Document } from "mongoose";
import { randomUUID } from "crypto";

interface ISession extends Document {
    id: string;
    userId: mongoose.Types.ObjectId;
    createdAt: Date;
}

const SessionSchema: Schema = new Schema({
    id: { type: String, required: true, default: () => randomUUID(), unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    createdAt: { type: Date, required: true, default: Date.now }
});

const Session = mongoose.model<ISession>("Session", SessionSchema);

export default Session;
