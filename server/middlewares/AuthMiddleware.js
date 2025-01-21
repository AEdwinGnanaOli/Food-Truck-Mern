import jwt from "jsonwebtoken";
import { verifyToken } from "../utils/secretToken.js";

const authenticate = (req, res, next) => {

    const cookieHeader = req.headers.cookie; // Extract the Cookie header

    // Check if the Cookie header exists
    if (!cookieHeader) {
      return res.status(401).json({
        status: false,
        message: "Authentication token is missing",
      });
    }// Parse the token from the Cookie header
    const cookies = cookieHeader.split(";").reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split("=");
      acc[key] = value;
      return acc;
    }, {});
    const token = cookies.token; // Replace 'token' with the key of your cookie

  // Verify the token
  const decode = verifyToken(token);

  // Attach user information to the request object
  req.user = { id: decode.id, role: decode.role };

  // Proceed to the next middleware or route handler
  next();

};

const roleAuthentication = (roles = []) => async (req, res, next) => {

  const { user } = req;
  // console.log(user)
  if (roles.includes(user.role)) {

    next();
  } else {
    return res.status(403).json({ message: 'Unauthorized' });
  }
};
export { authenticate, roleAuthentication };
