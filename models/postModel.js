const mongoose = require('mongoose');

const postSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Post must have a title'],
    },
    description: {
      type: String,
      required: [true, 'Post must have a description'],
    },
    rating: {
      type: Number,
      default: 0,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Post must belong to a user'],
    },
  },
  {
    // NOTE each time the data is outputted as JSON, we want virtuals to be true
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
    id: false,
  }
);

// NOTE virtual populate
postSchema.virtual('comments', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'post',
});

postSchema.virtual('commentCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'post',
  count: true,
});

postSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'user',
    select: 'username photo',
  });

  next();
});

const Post = mongoose.model('Post', postSchema);

module.exports = Post;
