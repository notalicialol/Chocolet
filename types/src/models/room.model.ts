import mongoose, { Schema, Document } from "mongoose";

interface IRoom extends Document {
    name: string;
    public: boolean;
    users?: mongoose.Types.ObjectId[];
    messages?: mongoose.Types.ObjectId[];
}

const RoomSchema: Schema = new Schema({
    name: { type: String, required: true },
    public: { type: Boolean, required: true, default: true },
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: "RoomUser" }],
    messages: [{ type: mongoose.Schema.Types.ObjectId, ref: "Message" }]
}, {
    timestamps: true
});

const Room = mongoose.model<IRoom>("Room", RoomSchema);

export default Room;
