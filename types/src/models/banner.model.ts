import mongoose, { Schema, Document } from "mongoose";

interface IBanner extends Document {
    name: string;
    imageId: mongoose.Types.ObjectId;
    priority: number;
}

const bannerSchema: Schema = new Schema({
    name: { type: String, unique: true, required: true },
    imageId: { type: mongoose.Types.ObjectId, required: true },
    priority: { type: Number, required: true, default: 0 },
});

const Banner = mongoose.model<IBanner>("Banner", bannerSchema);

export default Banner;
