import mongoose, { Schema, Document } from "mongoose";

interface IBlook extends Document {
    name: string;
    chance: number;
    price: number;
    rarityId: mongoose.Types.ObjectId;
    imageId: mongoose.Types.ObjectId;
    backgroundId: mongoose.Types.ObjectId;
    packId?: mongoose.Types.ObjectId;
    priority: number;
}

const blookSchema: Schema = new Schema({
    name: { type: String, unique: true, required: true },
    chance: { type: Number, required: true, default: 0 },
    price: { type: Number, required: true, default: 0 },
    rarityId: { type: mongoose.Types.ObjectId, required: true },
    imageId: { type: mongoose.Types.ObjectId, required: true },
    backgroundId: { type: mongoose.Types.ObjectId, required: true },
    packId: { type: mongoose.Types.ObjectId },
    priority: { type: Number, required: true, default: 0 },
});

const Blook = mongoose.model<IBlook>("Blook", blookSchema);

export default Blook;
