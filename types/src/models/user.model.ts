import mongoose, { Schema, Document } from "mongoose";

interface IResource extends Document {
    path: string;
}

interface IUser extends Document {
    id: string;
    username: string;
    password?: string;
    avatarId: mongoose.Types.ObjectId;
    customAvatarId?: mongoose.Types.ObjectId;
    bannerId: mongoose.Types.ObjectId;
    customBannerId?: mongoose.Types.ObjectId;
    titleId: mongoose.Types.ObjectId;
    fontId: mongoose.Types.ObjectId;
    color: string;
    tokens: number;
    gems: number;
    experience: number;
    permissions: number;
    lastClaimed?: Date;
    ipAddress?: string;
    avatar?: IResource;
    customAvatar?: IResource;
    banner?: IResource;
    customBanner?: IResource;
}

const UserSchema: Schema = new Schema({
    id: { type: String, required: true, default: () => (Math.floor(Date.now() / 1000)).toString() + Math.floor(1000000 + Math.random() * 9000000).toString() },
    username: { type: String, required: true, unique: true },
    password: { type: String },
    avatarId: { type: mongoose.Schema.Types.ObjectId, ref: "Resource" },
    customAvatarId: { type: mongoose.Schema.Types.ObjectId, ref: "Resource" },
    bannerId: { type: mongoose.Schema.Types.ObjectId, ref: "Resource" },
    customBannerId: { type: mongoose.Schema.Types.ObjectId, ref: "Resource" },
    titleId: { type: mongoose.Schema.Types.ObjectId, ref: "Title" },
    fontId: { type: mongoose.Schema.Types.ObjectId, ref: "Font" },
    color: { type: String, required: true, default: "#ffffff", validate: /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$|^rainbow$/ },
    tokens: { type: Number, default: 0 },
    gems: { type: Number, default: 0 },
    experience: { type: Number, default: 0 },
    permissions: { type: Number, default: 0 },
    lastClaimed: { type: Date },
    ipAddress: { type: String }
}, {
    timestamps: false
});

UserSchema.virtual("avatarPath").get(function (this: IUser) {
    return this.avatar?.path;
});
UserSchema.virtual("customAvatarPath").get(function (this: IUser) {
    return this.customAvatar?.path;
});
UserSchema.virtual("bannerPath").get(function (this: IUser) {
    return this.banner?.path;
});
UserSchema.virtual("customBannerPath").get(function (this: IUser) {
    return this.customBanner?.path;
});

const User = mongoose.model<IUser>("User", UserSchema);

export default User;
