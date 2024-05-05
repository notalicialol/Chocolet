import mongoose, { Schema, Document } from "mongoose";

enum ItemType {
    NONE = 1,
    BOOSTER = 2
}

interface IResource extends Document {
    path: string;
}

interface IItem extends Document {
    name: string;
    description: string;
    rarityId: mongoose.Types.ObjectId;
    imageId: mongoose.Types.ObjectId;
    type: ItemType;
    canUse: boolean;
    canTrade: boolean;
    boosterDuration: number;
}

interface IItemPopulated extends IItem {
    image: IResource;
}

const ItemSchema: Schema = new Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    rarityId: { type: mongoose.Schema.Types.ObjectId, ref: "Rarity", required: true },
    imageId: { type: mongoose.Schema.Types.ObjectId, ref: "Resource", required: true },
    type: { 
        type: Number, 
        required: true, 
        default: ItemType.NONE,
        validate: {
            validator: function(value: number) {
                return Object.values(ItemType).includes(value);
            },
            message: props => `itemType must be one of: ${Object.values(ItemType).join(", ")}`
        }
    },
    canUse: { type: Boolean, required: true, default: false },
    canTrade: { type: Boolean, required: true, default: false },
    boosterDuration: { type: Number, default: 0 }
});

ItemSchema.virtual("imagePath").get(function(this: IItemPopulated) {
    return this.image.path;
});

const Item = mongoose.model<IItem>("Item", ItemSchema);

export default Item;
