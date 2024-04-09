/// <reference types="mongoose/types/aggregate" />
/// <reference types="mongoose/types/callback" />
/// <reference types="mongoose/types/collection" />
/// <reference types="mongoose/types/connection" />
/// <reference types="mongoose/types/cursor" />
/// <reference types="mongoose/types/document" />
/// <reference types="mongoose/types/error" />
/// <reference types="mongoose/types/expressions" />
/// <reference types="mongoose/types/helpers" />
/// <reference types="mongoose/types/middlewares" />
/// <reference types="mongoose/types/indexes" />
/// <reference types="mongoose/types/models" />
/// <reference types="mongoose/types/mongooseoptions" />
/// <reference types="mongoose/types/pipelinestage" />
/// <reference types="mongoose/types/populate" />
/// <reference types="mongoose/types/query" />
/// <reference types="mongoose/types/schemaoptions" />
/// <reference types="mongoose/types/schematypes" />
/// <reference types="mongoose/types/session" />
/// <reference types="mongoose/types/types" />
/// <reference types="mongoose/types/utility" />
/// <reference types="mongoose/types/validation" />
/// <reference types="mongoose/types/virtuals" />
/// <reference types="mongoose/types/inferschematype" />
import mongoose, { Document } from "mongoose";
interface UserInterface extends Document {
    username: string;
    password: string;
    role?: string;
    avatar?: string;
    banner?: string;
    color?: string;
    tokens?: number;
    gems?: number;
    packs?: number;
    messages?: number;
    created?: Date;
    modified?: Date;
    ip?: string | null;
    mute?: string | null;
    ban?: string | null;
}
declare const User: mongoose.Model<UserInterface, {}, {}, {}, mongoose.Document<unknown, {}, UserInterface> & UserInterface & {
    _id: mongoose.Types.ObjectId;
}, any>;
export default User;
