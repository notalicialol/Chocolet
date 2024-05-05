import mongoose, { Schema, Document } from "mongoose";

interface IUserStatistic extends Document {
    userId: mongoose.Types.ObjectId;
    packsOpened: number;
    messagesSent: number;
}

const UserStatisticSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    packsOpened: { type: Number, default: 0 },
    messagesSent: { type: Number, default: 0 }
});

const UserStatistic = mongoose.model<IUserStatistic>("UserStatistic", UserStatisticSchema);

export default UserStatistic;
