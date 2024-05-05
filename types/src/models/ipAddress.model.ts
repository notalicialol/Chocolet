import mongoose, { Schema, Document } from "mongoose";

interface IIpAddress extends Document {
    ipAddress: string;
    users?: mongoose.Types.ObjectId[];
}

const IpAddressSchema: Schema = new Schema({
    ipAddress: { type: String, required: true, unique: true },
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: "UserIpAddress" }]
});

const IpAddress = mongoose.model<IIpAddress>("IpAddress", IpAddressSchema);

export default IpAddress;
