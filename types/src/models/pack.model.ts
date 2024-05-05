import mongoose, { Schema, Document } from "mongoose";

interface IPack extends Document {
    name: string;
    price: number;
    enabled: boolean;
    imageId: mongoose.Types.ObjectId;
    innerColor: string;
    outerColor: string;
    priority: number;
    blooks?: mongoose.Types.ObjectId[];
}

const packSchema: Schema = new Schema({
    name: { type: String, unique: true, required: true },
    price: { type: Number, required: true, default: 0 },
    enabled: { type: Boolean, required: true, default: true },
    imageId: { type: mongoose.Types.ObjectId, required: true },
    innerColor: { type: String, required: true, validate: { validator: (v: string) => /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$|^rainbow$/.test(v) } },
    outerColor: { type: String, required: true, validate: { validator: (v: string) => /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$|^rainbow$/.test(v) } },
    priority: { type: Number, required: true, default: 0 },
    blooks: [{ type: mongoose.Types.ObjectId, ref: "Blook" }]
});

const Pack = mongoose.model<IPack>("Pack", packSchema);

export default Pack;
