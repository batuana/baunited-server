const cors = require("cors");

const corsOptions = {
  origin: "http://127.0.0.1:5500",
};

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

const app = express();

app.use(cors(corsOptions));

// Set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// Limit requests from same IP
const limiter = rateLimit({
  // allow 100 requests from the same IP in 1 hour (REST?)
  // resetting of the app will reset the remaining requests
  max: 1000,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour!",
});
app.use("/api", limiter);

// Body parser, reading data from body into req.body
// when we have a body larger than 10kilobyte, it will not be accepted
app.use(express.json({ limit: "10kb" }));

// Data sanitization against NoSQL query injection
// check req.body, req.query, req.params -> filter out all of the dollar signs and dots
app.use(mongoSanitize());

// Data sanitization against XSS (cross-site scripting attacks), clean any user input from malicious HTML code
app.use(xss());

// TODO Prevent parameter pollution, clears up the query string
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

app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
