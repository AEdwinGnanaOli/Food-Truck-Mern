import mongoose from 'mongoose';

const likeSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: "Users", required: true }, // Reference to the Users collection
    product: { type: mongoose.Schema.Types.ObjectId, ref: "products", required: true }, // Reference to the products collection
    like: { type: String, enum: ['like', 'unLike'], default: 'unLike' }, // Enum to specify like/unlike
}, {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
});

const likeModel = mongoose.model('Likes', likeSchema);

export default likeModel;
