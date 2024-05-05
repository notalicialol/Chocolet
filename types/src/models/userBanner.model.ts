import mongoose, { Schema, Document } from "mongoose";

interface IUserBanner extends Document {
    userId: mongoose.Types.ObjectId;
    bannerId: mongoose.Types.ObjectId;
}

const UserBannerSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    bannerId: { type: mongoose.Schema.Types.ObjectId, ref: "Banner", required: true }
});

const UserBanner = mongoose.model<IUserBanner>("UserBanner", UserBannerSchema);

export default UserBanner;
