import mongoose, { Schema, Document } from "mongoose";

enum AnimationType {
    UNCOMMON = 1,
    RARE = 2,
    EPIC = 3,
    LEGENDARY = 4,
    CHROMA = 5
}

interface IRarity extends Document {
    name: string;
    color: string;
    animationType: AnimationType;
    experience: number;
    blooks?: mongoose.Types.ObjectId[];
}

const RaritySchema: Schema = new Schema({
    name: { type: String, required: true, unique: true },
    color: { 
        type: String, 
        required: true,
        validate: {
            validator: function(v: string) {
                return /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$|^rainbow$/.test(v);
            },
            message: props => `${props.value} is not a valid color code or "rainbow"!`
        }
    },
    animationType: { 
        type: Number, 
        required: true,
        enum: Object.values(AnimationType),
        message: `animationType must be one of these values: ${Object.keys(AnimationType).join(", ")}`
    },
    experience: { type: Number, required: true },
    blooks: [{ type: mongoose.Schema.Types.ObjectId, ref: "Blook" }]
}, {
    timestamps: true
});

const Rarity = mongoose.model<IRarity>("Rarity", RaritySchema);

export default Rarity;
