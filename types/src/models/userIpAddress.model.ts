import mongoose, { Schema, Document } from "mongoose";

interface IUserIpAddress extends Document {
    userId: mongoose.Types.ObjectId;
    ipAddressId: mongoose.Types.ObjectId;
    uses: number;
}

const UserIpAddressSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    ipAddressId: { type: mongoose.Schema.Types.ObjectId, ref: "IpAddress", required: true },
    uses: { type: Number, required: true, default: 0 }
});

const UserIpAddress = mongoose.model<IUserIpAddress>("UserIpAddress", UserIpAddressSchema);

export default UserIpAddress;
