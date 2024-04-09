"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose_1 = require("mongoose");
const userSchema = new mongoose_1.default.Schema({
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
const User = mongoose_1.default.model("User", userSchema);
exports.default = User;
//# sourceMappingURL=user.model.js.map