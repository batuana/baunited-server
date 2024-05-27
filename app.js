const express = require("express");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");

const AppError = require("./utils/appError");
const globalErrorHandler = require("./controllers/errorController");
const userRouter = require("./routes/userRoutes");
const postRouter = require("./routes/postRoutes");
const commentRouter = require("./routes/commentRoutes");

const app = express();

// Set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === "development") app.use(morgan("dev"));

// Limit requests from same IP
const limiter = rateLimit({
  // allow 1000 requests from the same IP in 1 hour
  // NOTE resetting of the app will reset the remaining requests
  max: 1000,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour!",
});
app.use("/api", limiter);

// Body parser, reading data from body into req.body
// when we have a body larger than 10kilobyte, it will not be accepted
app.use(express.json({ limit: "10kb" }));

// Data sanitization against NoSQL query injection
// checks req.body, req.query, req.params -> filter out all of the dollar signs and dots
app.use(mongoSanitize());

// Data sanitization against XSS (cross-site scripting attacks)
// cleans any user input from malicious HTML code
app.use(xss());

// TODO prevent parameter pollution
// clears up the query string from duplicated fields instead of creating an array -> sort=duration&sort=price (uses the last one)
app.use(
  hpp({
    whitelist: [],
  })
);

// Attaching date to incoming request
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

// mounting the router
app.use("/api/v1/users", userRouter);
app.use("/api/v1/posts", postRouter);
app.use("/api/v1/comments", commentRouter);

app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
