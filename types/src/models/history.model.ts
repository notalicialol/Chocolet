import mongoose, { Schema, Document } from "mongoose";

enum HistoryType {
    UNKNOWN = 1,
    TRADE = 2,
    BAZAAR = 3
}

interface IHistory extends Document {
    previousOwnerId: mongoose.Types.ObjectId;
    newOwnerId: mongoose.Types.ObjectId;
    type: HistoryType;
}

const HistorySchema: Schema = new Schema({
    previousOwnerId: { type: mongoose.Types.ObjectId, ref: "User", required: true },
    newOwnerId: { type: mongoose.Types.ObjectId, ref: "User", required: true },
    type: { 
        type: Number, 
        required: true, 
        default: HistoryType.UNKNOWN, 
        validate: {
            validator: function(value: number) {
                return [1, 2, 3].includes(value);
            },
            message: props => `type must be one of these values: ${Object.keys(HistoryType).join(", ")}`
        }
    }
});

const History = mongoose.model<IHistory>("History", HistorySchema);

export default History;
