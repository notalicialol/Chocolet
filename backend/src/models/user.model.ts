import mongoose, { Document, Schema } from "mongoose";

interface UserInterface extends Document {
    username: string;
    password: string;
    role?: string;
    avatar?: string;
    banner?: string;
    color?: string;
    tokens?: number;
    gems?: number;
    packs?: number;
    messages?: number;
    created?: Date;
    modified?: Date;
    ip?: string | null;
    mute?: string | null;
    ban?: string | null;
}

const userSchema: Schema<UserInterface> = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "Common" },
    avatar: { type: String, default: "/content/blooks/Default.webp" },
    banner: { type: String, default: "/content/banners/Default.webp" },
    color: { type: String, default: "#FFFFFF" },
    tokens: { type: Number, default: 0 },
    gems: { type: Number, default: 0 },
    packs: { type: Number, default: 0 },
    messages: { type: Number, default: 0 },
    created: { type: Date, default: Date.now },
    modified: { type: Date, default: Date.now },
    ip: { type: String, default: null },
    mute: { type: String, default: null },
    ban: { type: String, default: null }
});

const User = mongoose.model<UserInterface>("User", userSchema);

export default User;