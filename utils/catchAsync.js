// NOTE consuming promise rejection causes error (throws error).
module.exports = fn => (req, res, next) => {
  fn(req, res, next).catch(next);
};
