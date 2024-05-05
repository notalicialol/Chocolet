import mongoose, { Schema, Document } from "mongoose";

interface IEmoji extends Document {
    name: string;
    imageId: mongoose.Types.ObjectId;
    priority: number;
}

const emojiSchema: Schema = new Schema({
    name: { type: String, unique: true, required: true },
    imageId: { type: mongoose.Types.ObjectId, required: true },
    priority: { type: Number, required: true, default: 0 },
});

const Emoji = mongoose.model<IEmoji>("Emoji", emojiSchema);

export default Emoji;
