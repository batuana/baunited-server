const Post = require('../models/postModel');
const factory = require('./handlerFactory');
const catchAsync = require('../utils/catchAsync');

// exports.createPost = factory.createOne(Post);
exports.createPost = catchAsync(async (req, res, next) => {
  req.body.user = req.user._id;
  const doc = await Post.create(req.body);

  res.status(201).json({
    status: 'success',
    data: {
      data: doc,
    },
  });
});
exports.getAllPosts = factory.getAll(Post, { path: 'commentCount' });
/* exports.getAllPostsWithCommentCounts = catchAsync(async (req, res, next) => {
  // Assuming you have already imported your Post and Comment models
  const postsWithCommentCount = await Post.aggregate([
    {
      $lookup: {
        from: 'comments', // NOTE The name of the comments collection in MongoDB
        localField: '_id', // Field in the posts collection
        foreignField: 'post', // Field in the comments collection
        as: 'comment_count', // Alias for the resulting array of comments
      },
    },
    {
      $addFields: {
        comment_count: { $size: '$comment_count' }, // Calculate the comment count OVERWRITES
      },
    },
  ]);

  res.status(200).json({
    status: 'success',
    requestedAt: req.requestTime,
    data: {
      data: postsWithCommentCount,
    },
  });
}); */
exports.getPost = factory.getOne(Post, { path: 'comments', select: '-__v' });
exports.updatePost = factory.updateOne(Post);
exports.votePost = catchAsync(async (req, res, next) => {
  const doc = await Post.findByIdAndUpdate(
    req.params.id,
    { $inc: { rating: req.body.value } },
    {
      new: true,
      runValidators: true,
    }
  );

  if (!doc) {
    return next(new AppError('No document found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      data: doc,
    },
  });
});
exports.deletePost = factory.deleteOne(Post);
