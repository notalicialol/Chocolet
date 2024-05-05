import mongoose, { Schema, Document } from "mongoose";

interface IRoomUser extends Document {
    roomId: mongoose.Types.ObjectId;
    userId: mongoose.Types.ObjectId;
}

const RoomUserSchema: Schema = new Schema({
    roomId: { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
}, {
    timestamps: true
});

const RoomUser = mongoose.model<IRoomUser>("RoomUser", RoomUserSchema);

export default RoomUser;
