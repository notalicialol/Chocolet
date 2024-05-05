import mongoose, { Schema, Document } from "mongoose";

enum FormStatus {
    PENDING = 1,
    ACCEPTED = 2,
    DENIED = 3
};

interface IForm extends Document {
    id: string;
    username: string;
    password: string;
    ipAddress: string;
    reasonToPlay: string;
    status: FormStatus;
    deniedReason?: string;
    accepterId?: mongoose.Types.ObjectId;
}

const FormSchema: Schema = new Schema({
    id: { type: String, required: true, default: () => require("crypto").randomUUID() },
    username: { type: String, required: true },
    password: { type: String, required: true },
    ipAddress: { type: String, required: true },
    reasonToPlay: { type: String, required: true },
    status: { type: Number, required: true, default: FormStatus.PENDING },
    deniedReason: { type: String, default: null },
    accepterId: { type: Schema.Types.ObjectId, ref: "User" }
});

const Form = mongoose.model<IForm>("Form", FormSchema);

export default Form;
