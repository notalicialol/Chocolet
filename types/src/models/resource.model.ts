import mongoose, { Schema, Document } from "mongoose";

interface IResource extends Document {
    path: string;
    userAvatar?: mongoose.Types.ObjectId[];
    customAvatar?: mongoose.Types.ObjectId[];
    userBanner?: mongoose.Types.ObjectId[];
    customBanner?: mongoose.Types.ObjectId[];
    blookImage?: mongoose.Types.ObjectId[];
    blookBackgroundImage?: mongoose.Types.ObjectId[];
    packImage?: mongoose.Types.ObjectId[];
    itemImage?: mongoose.Types.ObjectId[];
    bannerImage?: mongoose.Types.ObjectId[];
    fontResource?: mongoose.Types.ObjectId[];
    emojiImage?: mongoose.Types.ObjectId[];
}

const ResourceSchema: Schema = new Schema({
    path: { type: String, required: true },
    userAvatar: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    customAvatar: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    userBanner: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    customBanner: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    blookImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Blook" }],
    blookBackgroundImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Blook" }],
    packImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Pack" }],
    itemImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Item" }],
    bannerImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Banner" }],
    fontResource: [{ type: mongoose.Schema.Types.ObjectId, ref: "Font" }],
    emojiImage: [{ type: mongoose.Schema.Types.ObjectId, ref: "Emoji" }]
}, {
    timestamps: true
});

const Resource = mongoose.model<IResource>("Resource", ResourceSchema);

export default Resource;
