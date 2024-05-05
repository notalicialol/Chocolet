import mongoose, { Schema, Document } from "mongoose";

interface IFile extends Document {
    filename: string;
    contentType: string;
    size: number;
    path: string;
    uploaderId: mongoose.Types.ObjectId;
    roomId: mongoose.Types.ObjectId;
    createdAt: Date;
}

const FileSchema: Schema = new Schema({
    filename: { type: String, required: true },
    contentType: { type: String, required: true },
    size: { type: Number, required: true },
    path: { type: String, required: true },
    uploaderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    roomId: { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true },
    createdAt: { type: Date, default: Date.now }
});

const File = mongoose.model<IFile>("File", FileSchema);

export default File;
