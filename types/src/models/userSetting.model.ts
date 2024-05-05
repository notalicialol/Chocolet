import mongoose, { Schema, Document } from "mongoose";

enum FriendRequestSetting {
    ON = 1,
    OFF = 2,
    MUTUAL = 3
}

interface IUserSetting extends Document {
    userId: mongoose.Types.ObjectId;
    openPacksInstantly: boolean;
    friendRequests: FriendRequestSetting;
    categoriesClosed: string[];
}

const UserSettingSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    openPacksInstantly: { type: Boolean, default: false },
    friendRequests: { 
        type: Number, 
        required: true, 
        enum: Object.values(FriendRequestSetting),
        default: FriendRequestSetting.ON,
        validate: {
            validator: function(value: number) {
                return Object.values(FriendRequestSetting).includes(value);
            },
            message: props => `Friend requests setting must be one of these values: ${Object.keys(FriendRequestSetting).join(", ")}`
        }
    },
    categoriesClosed: { type: [String], default: [] }
});

const UserSetting = mongoose.model<IUserSetting>("UserSetting", UserSettingSchema);

export default UserSetting;
