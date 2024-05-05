import mongoose, { Schema, Document } from "mongoose";

interface IPurchase extends Document {
    userId: mongoose.Types.ObjectId;
    timestamp: Date;
    ip: string;
    purchaseId: string;
    amount: number;
    item: string;
    currency: string;
    status: string;
    additionalInfo: any;
}

const PurchaseSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    timestamp: { type: Date, default: Date.now },
    ip: { type: String, required: true },
    purchaseId: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    item: { type: String, required: true },
    currency: { type: String, required: true },
    status: { type: String, required: true },
    additionalInfo: { type: Schema.Types.Mixed }
}, {
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" }
});

const Purchase = mongoose.model<IPurchase>("Purchase", PurchaseSchema);

export default Purchase;
