const Comment = require("../models/commentModel");
const factory = require("./handlerFactory");
const catchAsync = require("../utils/catchAsync");

// exports.createComment = factory.createOne(Comment);
exports.createComment = catchAsync(async (req, res, next) => {
  req.body.user = req.user._id;
  const doc = await Comment.create(req.body);

  res.status(201).json({
    status: "success",
    data: {
      data: doc,
    },
  });
});
exports.updateComment = factory.updateOne(Comment);
exports.voteComment = catchAsync(async (req, res, next) => {
  const doc = await Comment.findByIdAndUpdate(
    req.params.id,
    { $inc: { rating: req.body.value } },
    {
      new: true,
      runValidators: true,
    }
  );

  if (!doc) {
    return next(new AppError("No document found with that ID", 404));
  }

  res.status(200).json({
    status: "success",
    data: {
      data: doc,
    },
  });
});
exports.deleteComment = factory.deleteOne(Comment);

exports.getAllComments = catchAsync(async (req, res, next) => {
  const comments = await Comment.find({ user: req.user._id });

  res.status(200).json({
    status: "success",
    data: {
      comments,
    },
  });
});
