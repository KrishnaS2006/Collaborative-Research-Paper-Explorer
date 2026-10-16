
export const errorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  const statusCode = err.statusCode || 500;

  if (statusCode >= 500) {
    console.error("Server error:", err.message);
  }

  return res.status(statusCode).json({
    error:
      statusCode >= 500
        ? "Internal server error."
        : err.message,
  });
};

export default errorHandler;
