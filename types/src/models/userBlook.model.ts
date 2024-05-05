import mongoose, { Schema, Document } from "mongoose";

enum BlookObtainMethod {
    UNKNOWN = 1,
    PACK_OPEN = 2,
    STAFF = 3
}

interface IUserBlook extends Document {
    userId: mongoose.Types.ObjectId;
    blookId: mongoose.Types.ObjectId;
    sold: boolean;
    initalObtainerId: mongoose.Types.ObjectId;
    obtainedBy: BlookObtainMethod;
}

const UserBlookSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    blookId: { type: mongoose.Schema.Types.ObjectId, ref: "Blook", required: true },
    sold: { type: Boolean, default: false },
    initalObtainerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    obtainedBy: { 
        type: Number, 
        required: true, 
        default: BlookObtainMethod.UNKNOWN,
        validate: {
            validator: function(value: number) {
                return Object.values(BlookObtainMethod).includes(value);
            },
            message: props => `obtainedBy must be one of these values: ${Object.keys(BlookObtainMethod).join(", ")}`
        }
    }
});

const UserBlook = mongoose.model<IUserBlook>("UserBlook", UserBlookSchema);

export default UserBlook;
