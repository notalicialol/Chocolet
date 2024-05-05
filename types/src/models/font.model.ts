import mongoose, { Schema, Document } from "mongoose";

interface IFont extends Document {
    name: string;
    resourceId: mongoose.Types.ObjectId;
}

const fontSchema: Schema = new Schema({
    name: { type: String, unique: true, required: true },
    resourceId: { type: mongoose.Types.ObjectId, required: true },
});

const Font = mongoose.model<IFont>("Font", fontSchema);

export default Font;
