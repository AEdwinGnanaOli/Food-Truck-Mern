import axios from "axios";

const BASE_URL = "http://localhost:8800";
// Global Axios configuration
axios.defaults.withCredentials = true;
axios.defaults.baseURL = BASE_URL; // Optionally set globally

const makeRequest = async (
  endPoint = "/",
  method = "GET",
  data = null,
  config = {}
) => {
  axios.defaults.withCredentials = true;
  try {
    const response = await axios({
      url: endPoint,
      method,
      baseURL: BASE_URL,
      data,
      timeout: 60000 * 2, // Timeout in milliseconds (10 seconds)
      ...config, // Allows custom configurations like headers
      withCredentials: true
    });
    
    return response.data;
  } catch (error) {
    // Normalize and log error message
    const errorMessage =
      error.response?.data || error.message || "Unknown error occurred";
    console.error("API Error:", errorMessage);
    throw new Error(errorMessage); // Throw normalized error
  }
};

export { makeRequest };
