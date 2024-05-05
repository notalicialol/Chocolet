import mongoose, { Schema, Document } from "mongoose";

interface IMessage extends Document {
    authorId: mongoose.Types.ObjectId;
    roomId: mongoose.Types.ObjectId;
    content: string;
    mentions: mongoose.Types.ObjectId[];
    replyingToId?: mongoose.Types.ObjectId;
    edited: boolean;
    deleted: boolean;
    replies?: IMessage[];
}

const MessageSchema: Schema = new Schema({
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    roomId: { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true },
    content: { type: String, required: true },
    mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
    replyingToId: { type: mongoose.Schema.Types.ObjectId, ref: "Message" },
    edited: { type: Boolean, default: false },
    deleted: { type: Boolean, default: false },
    replies: [{ type: mongoose.Schema.Types.ObjectId, ref: "Message" }]
}, {
    timestamps: true
});

const Message = mongoose.model<IMessage>("Message", MessageSchema);

export default Message;
