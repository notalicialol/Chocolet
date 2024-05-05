import mongoose, { Schema, Document } from "mongoose";

interface IUserTitle extends Document {
    userId: mongoose.Types.ObjectId;
    titleId: mongoose.Types.ObjectId;
}

const UserTitleSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    titleId: { type: mongoose.Schema.Types.ObjectId, ref: "Title", required: true }
});

const UserTitle = mongoose.model<IUserTitle>("UserTitle", UserTitleSchema);

export default UserTitle;
