import mongoose, { Schema, Document } from "mongoose";

interface ITitle extends Document {
    name: string;
    priority: number;
}

const TitleSchema: Schema = new Schema({
    name: { type: String, required: true, unique: true },
    priority: { type: Number, default: 0 }
});

const Title = mongoose.model<ITitle>("Title", TitleSchema);

export default Title;
