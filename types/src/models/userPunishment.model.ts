import mongoose, { Schema, Document } from "mongoose";

enum PunishmentType {
    WARN = 1,
    MUTE = 2,
    BAN = 3,
    BLACKLIST = 4
}

interface IUserPunishment extends Document {
    userId: mongoose.Types.ObjectId;
    type: PunishmentType;
    reason: string;
    expiresAt: Date;
    staffId: mongoose.Types.ObjectId;
    createdAt: Date;
}

const UserPunishmentSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { 
        type: Number, 
        required: true,
        enum: Object.values(PunishmentType),
        validate: {
            validator: function(value: number) {
                return Object.values(PunishmentType).includes(value);
            },
            message: props => `Type must be one of these values: ${Object.keys(PunishmentType).join(", ")}`
        }
    },
    reason: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    createdAt: { type: Date, default: Date.now }
});

const UserPunishment = mongoose.model<IUserPunishment>("UserPunishment", UserPunishmentSchema);

export default UserPunishment;
