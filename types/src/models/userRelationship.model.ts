import mongoose, { Schema, Document } from "mongoose";

enum RelationType {
    ADD = 1,
    BLOCK = 2
}

interface IUserRelationship extends Document {
    userId: mongoose.Types.ObjectId;
    targetId: mongoose.Types.ObjectId;
    friendNickname?: string;
    type: RelationType;
}

const UserRelationshipSchema: Schema = new Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    targetId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    friendNickname: { type: String },
    type: { 
        type: Number, 
        required: true,
        enum: Object.values(RelationType),
        validate: {
            validator: function(value: number) {
                return Object.values(RelationType).includes(value);
            },
            message: props => `Relationship type must be one of these values: ${Object.keys(RelationType).join(", ")}`
        }
    }
});

const UserRelationship = mongoose.model<IUserRelationship>("UserRelationship", UserRelationshipSchema);

export default UserRelationship;
